# -*- coding: utf-8 -*-
"""配置加载。

优先级：CLI 参数 > 环境变量 > <repo>/.ai-audit.yaml > 内置默认值。
定义依据：设计文档 04 第 2.3 节 + 06 第 5.4 节（Agentic 预算）。
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml


# ---------------------------------------------------------------- 默认值

# ★ 排除模式必须带 `**/` 前缀。实测踩坑：最初写 "tests/**"，而 glob_match_posix
# 对 `tests/**` 只匹配**顶层** `tests/` 目录，`app/bbs/tests/foo.py` 匹配不上——
# 于是 Django 自带的测试桩（`app/*/tests.py`，断言 `1+1==2`）混进了审计范围。
DEFAULT_EXCLUDE = [
    "**/tests/**", "**/test/**", "**/migrations/**",
    "**/tests.py", "**/test_*.py", "**/*_test.py", "**/conftest.py",
    "**/.venv/**", "**/venv/**", "**/node_modules/**",
    "**/__pycache__/**", "**/.git/**", "**/site-packages/**",
]

DEFAULT_VENDORED_PATHS = [
    "lib/**", "vendor/**", "third_party/**", "extern/**", "external/**",
    "**/contrib/**", "**/dist-packages/**",
]

DEFAULT_VENDORED_HEADERS = [
    "Copyright (c)", "Software Foundation", "vendored from",
    "This is a copy of", "Licensed under the Apache License",
    "Permission is hereby granted, free of charge",
    "GNU General Public License", "All rights reserved",
]

# 敏感路径硬编码对齐——治理方案 12.6.2（见设计 01 §4.6）
DEFAULT_SENSITIVE_PATHS = [
    "src/control/", "src/auth/", "src/crypto/", "src/data/sensitive/",
    "**/config/prod/**", "**/*.pem", "**/settings_production.py",
]

DEFAULT_SENSITIVE_CONTENT = [
    r"(?i)(orbit|telemetry|站控|遥控|遥测|轨道|测控指令)",
    r"(?i)(BEGIN (RSA |EC )?PRIVATE KEY)",
]


# ---------------------------------------------------------------- 子配置

@dataclass
class ScanConfig:
    exclude: list[str] = field(default_factory=lambda: list(DEFAULT_EXCLUDE))
    include_extensions: list[str] = field(default_factory=lambda: [".py"])
    python_versions: list[str] = field(default_factory=lambda: ["2.7", "3"])
    exclude_vendored: bool = True
    min_severity: str = "low"
    baseline_file: str | None = None


@dataclass
class VendoredConfig:
    path_patterns: list[str] = field(default_factory=lambda: list(DEFAULT_VENDORED_PATHS))
    header_markers: list[str] = field(default_factory=lambda: list(DEFAULT_VENDORED_HEADERS))
    require_confirm: bool = True
    on_unconfirmed: str = "suspected_vendored"
    handling: str = "skip"                 # skip | report_as_dependency


@dataclass
class EngineConfig:
    semgrep_enabled: bool = True
    semgrep_rulesets: list[str] = field(default_factory=lambda: ["p/python", "p/secrets"])
    semgrep_timeout: int = 600
    bandit_enabled: bool = True
    bandit_min_severity: str = "medium"
    deps_enabled: bool = True
    secret_enabled: bool = True
    secret_entropy_threshold: float = 4.0
    ai_code_enabled: bool = True
    max_candidates: int = 300


@dataclass
class LLMConfig:
    provider: str = "auto"                 # auto | deepseek | anthropic | local | mock
    model: str = ""
    base_url: str = ""
    api_key: str = ""
    temperature: float = 0.0
    fallback_to_engines_only: bool = True
    # ★ 4096 → 8192（2026-09-19）。4096 是缺陷 #31 的根因：模型一轮会发
    # 10–24 个带证据文本的调用（受控探针实测 12 个 ≈ 1,900 输出 token，
    # 而真实 `record_finding` 的 input 含约 250 词证据、单块就是探针的几倍），
    # 4096 装不下，于是每轮从尾巴上被砍断，留下参数为空的残骸块。
    # 8192 已在该端点实测可用（`out/_probe_truncation.py` 用例 B/C/D 都以
    # max_tokens=8000 跑通，`stop_reason='tool_use'`，无截断）。
    # ★ 这个值会写进产物快照（`report._build_meta`）——不记的话，两次运行
    # 的"可比性"就缺了一项真正会改变结果的配置。
    max_output_tokens: int = 8192
    request_timeout: int = 180


@dataclass
class AgentConfig:
    """★ 06 §5.4 双预算 + 循环控制。"""
    enabled: bool = True
    max_turns: int = 40
    max_tokens: int = 200_000
    max_seconds: int = 0
    nudge_at_ratio: float = 0.5            # 首次提示（06 §5.6）
    converge_at_ratio: float = 0.7
    final_at_ratio: float = 0.9
    tool_result_max_chars: int = 6000      # 单次工具结果截断（06 §5.5 L1）
    context_window_tokens: int = 120_000   # 模型的上下文窗口
    # ★ 压缩按**上下文填充率**触发（context_window × 本比例）。
    # 注意它与 max_tokens（跨轮次的总预算）是两个不同的量：总预算决定
    # 「还能跑多久」，上下文窗口决定「一次能塞多少」。混用会造成每轮压缩。
    compact_at_ratio: float = 0.6
    max_truncation_retries: int = 2        # 截断续写上限（06 §5.1）
    require_adversarial_for: list[str] = field(
        default_factory=lambda: ["CRITICAL", "HIGH"]
    )

    # ★ 收敛对账（06 §5.8）。默认开启——它是验收报告 §4 里唯一能兜住
    # "看见了、说出来了、没落账"这类漏报的机制，关掉等于放弃那 2/3 的召回。
    recall_enabled: bool = True
    # 预算用掉多少之后开始对账。对账是**收敛阶段**的活动：太早做，模型
    # 还在读文件，每个刚读过的文件都会被当成"读过却没结论"；它另有
    # 一个更强的触发点——`conclude` 被调用时无条件做一次，所以即使模型
    # 在预算很浅时就收敛，也不会漏掉这一步。
    recall_after_ratio: float = 0.5
    recall_max_mention: int = 4            # A 类（提及对账）每轮最多提几条
    recall_max_file: int = 2               # B 类（文件回访）每轮最多提几条
    recall_max_total: int = 6              # **每次**对账最多提几条
    # ★ 上面三个都是"每次"的上限，管不住整场运行的总产量。
    # 实测 real-recall：每轮 2–4 条、从第 20 轮提到第 39 轮，累计 **46 条**，
    # 而 B 类去重失效让 6 个文件被反复提名（admin/views.py 18 次）。
    # 模型在轨迹里说得清清楚楚："I can dispose all 44 with position-specific
    # reasons"——它知道每一条是什么，也打算处置，**它做不完**：
    # 最后一轮要挤 58 次 dispose。对账于是从"防漏报"变成"制造做不完的清单"。
    # 全局配额才是真正管用的那个旋钮：线索总量必须落在预算**能处置完**的范围内。
    recall_max_mention_total: int = 6      # A 类整场运行的总上限
    recall_max_file_total: int = 6         # B 类整场运行的总上限


@dataclass
class ReportConfig:
    language: str = "zh"
    include_snippets: bool = True
    mask_sensitive_in_report: bool = False
    formats: list[str] = field(default_factory=lambda: ["md", "json"])


@dataclass
class GateConfig:
    fail_on: str = "high"
    security_critical_paths: list[str] = field(default_factory=list)
    enabled: bool = False


@dataclass
class Config:
    repo: Path
    out_dir: Path = field(default_factory=lambda: Path("./ai-audit-out"))
    mode: str = "full"                     # full | diff
    base_sha: str | None = None
    head_sha: str | None = None
    scan: ScanConfig = field(default_factory=ScanConfig)
    vendored: VendoredConfig = field(default_factory=VendoredConfig)
    engines: EngineConfig = field(default_factory=EngineConfig)
    llm: LLMConfig = field(default_factory=LLMConfig)
    agent: AgentConfig = field(default_factory=AgentConfig)
    report: ReportConfig = field(default_factory=ReportConfig)
    gate: GateConfig = field(default_factory=GateConfig)
    sensitive_paths: list[str] = field(default_factory=lambda: list(DEFAULT_SENSITIVE_PATHS))
    sensitive_content_patterns: list[str] = field(
        default_factory=lambda: list(DEFAULT_SENSITIVE_CONTENT)
    )
    raw: dict = field(default_factory=dict)   # 原始 yaml，供扩展字段

    # ---------------------------------------------------------- 加载

    @classmethod
    def load(cls, repo: Path | str, config_path: Path | str | None = None,
             overrides: dict | None = None) -> "Config":
        repo = Path(repo).resolve()
        cfg = cls(repo=repo)

        path = Path(config_path) if config_path else repo / ".ai-audit.yaml"
        if path.exists():
            try:
                data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            except Exception:
                data = {}
            cfg.raw = data
            _apply(cfg, data)

        _apply_env(cfg)
        if overrides:
            _apply(cfg, overrides, from_overrides=True)
        return cfg

    def resolved_out_dir(self) -> Path:
        out = self.out_dir
        if not out.is_absolute():
            out = (Path.cwd() / out).resolve()
        out.mkdir(parents=True, exist_ok=True)
        return out


def _set(obj, name: str, value):
    if hasattr(obj, name) and value is not None:
        setattr(obj, name, value)


def _apply(cfg: Config, data: dict, from_overrides: bool = False) -> None:
    """把 yaml 字典铺到 Config 上。未知字段静默忽略（向前兼容）。"""
    if not isinstance(data, dict):
        return

    v = data.get("version")
    if v and v != 1:
        pass  # 预留版本迁移钩子

    s = data.get("scan") or {}
    for k in ("exclude", "include_extensions", "python_versions", "baseline_file"):
        _set(cfg.scan, k, s.get(k))
    _set(cfg.scan, "exclude_vendored", s.get("exclude_vendored"))
    _set(cfg.scan, "min_severity", s.get("min_severity"))

    vd = data.get("vendored") or {}
    for k in ("path_patterns", "header_markers", "require_confirm",
              "on_unconfirmed", "handling"):
        _set(cfg.vendored, k, vd.get(k))

    en = data.get("engines") or {}
    sm = en.get("semgrep") or {}
    _set(cfg.engines, "semgrep_enabled", sm.get("enabled"))
    _set(cfg.engines, "semgrep_rulesets", sm.get("rulesets"))
    _set(cfg.engines, "semgrep_timeout", sm.get("timeout"))
    bd = en.get("bandit") or {}
    _set(cfg.engines, "bandit_enabled", bd.get("enabled"))
    _set(cfg.engines, "bandit_min_severity", bd.get("min_severity"))
    dp = en.get("deps") or {}
    _set(cfg.engines, "deps_enabled", dp.get("enabled"))
    sc = en.get("secret") or {}
    _set(cfg.engines, "secret_enabled", sc.get("enabled"))
    _set(cfg.engines, "secret_entropy_threshold", sc.get("entropy_threshold"))
    ac = en.get("ai_code") or {}
    _set(cfg.engines, "ai_code_enabled", ac.get("enabled"))
    _set(cfg.engines, "max_candidates", (data.get("llm") or {}).get("max_candidates"))

    ll = data.get("llm") or {}
    for k in ("provider", "model", "base_url", "api_key", "temperature",
              "request_timeout"):
        _set(cfg.llm, k, ll.get(k))
    _set(cfg.llm, "fallback_to_engines_only", ll.get("fallback_to_engines_only"))
    _set(cfg.llm, "max_output_tokens", ll.get("max_output_tokens"))

    ag = data.get("agent") or {}
    for k in ("enabled", "max_turns", "max_tokens", "max_seconds",
              "nudge_at_ratio", "converge_at_ratio", "final_at_ratio",
              "tool_result_max_chars", "compact_at_ratio",
              "max_truncation_retries", "require_adversarial_for"):
        _set(cfg.agent, k, ag.get(k))

    rp = data.get("report") or {}
    for k in ("language", "include_snippets", "mask_sensitive_in_report", "formats"):
        _set(cfg.report, k, rp.get(k))

    gt = data.get("gate") or {}
    _set(cfg.gate, "fail_on", gt.get("fail_on"))
    _set(cfg.gate, "security_critical_paths", gt.get("security_critical_paths"))
    _set(cfg.gate, "enabled", gt.get("enabled"))

    if from_overrides:
        _set(cfg, "mode", data.get("mode"))
        _set(cfg, "base_sha", data.get("base_sha"))
        _set(cfg, "head_sha", data.get("head_sha"))
        if data.get("out_dir"):
            cfg.out_dir = Path(data["out_dir"])


def _apply_env(cfg: Config) -> None:
    """环境变量覆盖。密钥只从环境读，**绝不落盘到配置文件**。"""
    env_map = {
        "AI_AUDIT_PROVIDER": ("llm", "provider"),
        "AI_AUDIT_MODEL": ("llm", "model"),
        "AI_AUDIT_BASE_URL": ("llm", "base_url"),
        "AI_AUDIT_API_KEY": ("llm", "api_key"),
        "AI_AUDIT_MAX_TURNS": ("agent", "max_turns"),
        "AI_AUDIT_MAX_TOKENS": ("agent", "max_tokens"),
    }
    for env_key, (section, attr) in env_map.items():
        val = os.environ.get(env_key)
        if not val:
            continue
        target = getattr(cfg, section)
        cur = getattr(target, attr, None)
        if isinstance(cur, int):
            try:
                val = int(val)
            except ValueError:
                continue
        setattr(target, attr, val)

    # 兜底：从 Anthropic 兼容环境变量推断 provider
    if not cfg.llm.base_url:
        cfg.llm.base_url = os.environ.get("ANTHROPIC_BASE_URL", "")
    if not cfg.llm.api_key:
        cfg.llm.api_key = (
            os.environ.get("ANTHROPIC_AUTH_TOKEN", "")
            or os.environ.get("ANTHROPIC_API_KEY", "")
        )
    if not cfg.llm.model:
        cfg.llm.model = os.environ.get("ANTHROPIC_MODEL", "")
