# -*- coding: utf-8 -*-
"""ai-audit 公共数据模型。

全流程的公共货币：所有引擎、Agent 工具、对抗验证的输出最终归一化为 Finding。
定义依据：设计文档 05 第 1 节（含 Agentic 架构新增字段）。
"""
from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


# ---------------------------------------------------------------- 枚举

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    def __lt__(self, other: "Severity") -> bool:  # 便于 max()/sorted()
        return self.rank < other.rank


_SEVERITY_RANK = {
    Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2,
    Severity.HIGH: 3, Severity.CRITICAL: 4,
}


class Verdict(str, Enum):
    UNVERIFIED = "UNVERIFIED"          # 未经对抗验证
    CONFIRMED = "CONFIRMED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    NEEDS_HUMAN = "NEEDS_HUMAN"
    PARTIAL = "PARTIAL"                # 成立但影响被削弱


class Exploitability(str, Enum):
    """★ 06 §6：与 severity 解耦。not_exploitable 不参与门禁判定。"""
    EXPLOITABLE = "exploitable"
    CONDITIONAL = "conditional"
    NOT_EXPLOITABLE = "not_exploitable"
    UNKNOWN = "unknown"


class CoverageClass(str, Enum):
    """★ 06 §4.1：覆盖度契约的七类风险。"""
    C1_INJECTION = "C1_注入"
    C2_DESERIALIZATION = "C2_反序列化"
    C3_AUTHZ = "C3_认证授权"
    C4_CREDENTIALS = "C4_凭据配置"
    C5_FILE_PATH = "C5_文件路径"
    C6_SUPPLY_CHAIN = "C6_依赖供应链"
    C7_AI_CODE = "C7_AI代码特有"

    @classmethod
    def all_ids(cls) -> list[str]:
        return [c.value for c in cls]


class CoverageStatus(str, Enum):
    """★ 06 §2.3：每个 C 类必须落到四态之一。"""
    COVERED = "covered"                # 已审且发现问题
    NO_ISSUE = "no_issue"              # 已审无问题（须有审查证据）
    SKIPPED = "skipped"                # 主动放弃（须给理由）
    OUT_OF_SCOPE = "out_of_scope"      # 经论证不适用（须给论证）
    UNVERIFIED = "unverified"          # 声明 no_issue 但无证据（被强制降级）


class AuditLayer(str, Enum):
    """★ 06 §4.2：结论到达的推理层。报告须声明，避免读者高估 L1 结论。"""
    L1_SYNTACTIC = "L1"
    L2_SEMANTIC = "L2"
    L3_CONTEXTUAL = "L3"


class Attribution(str, Enum):
    """★ 06 §5.3：归因。vendored/dependency 不计入项目漏洞。"""
    PROJECT = "project"
    VENDORED = "vendored"
    DEPENDENCY = "dependency"
    UNKNOWN = "unknown"


class FindingSource(str, Enum):
    SEMGREP = "semgrep"
    BANDIT = "bandit"
    DEPS = "deps"
    SECRET = "secret"
    AI_CODE = "ai-code"
    LLM_APP = "llm-app"
    LLM = "llm"
    AGENT = "agent"


# ---------------------------------------------------------------- 子结构

@dataclass
class Evidence:
    """证据契约（06 §2.4）。Agent 记录时缺任一必填项将被拒绝。"""

    # 基础
    snippet: str = ""                       # 命中的代码原文
    attack_path: list[str] = field(default_factory=list)
    dataflow: list[str] = field(default_factory=list)
    mitigations_found: list[str] = field(default_factory=list)
    attestation: dict = field(default_factory=dict)   # 机械校验结果

    # ★ 证据契约必需字段
    sink: str = ""                          # 危险操作所在行 + 代码片段
    source: str = ""                        # 污点来源 + 不可控性判定
    reachability: str = ""                  # 入口到 sink 的可达路径
    sanitizer_check: str = ""               # 路径上的净化措施枚举 + 为何无效（D3 对策）

    # 必填项清单——contracts.py 用
    REQUIRED = ("sink", "source", "reachability", "sanitizer_check")

    def missing_fields(self) -> list[str]:
        return [f for f in self.REQUIRED if not str(getattr(self, f, "")).strip()]


@dataclass
class Verification:
    stage: str = "none"                     # none | adversarial | human
    verdict: Verdict = Verdict.UNVERIFIED
    rebuttal: str | None = None
    reasoning: str | None = None
    severity_adjusted: bool = False
    # ★ 06 §7：对抗验证的独立性证明
    verifier_context_hash: str = ""
    sanitizers_checked: list[str] = field(default_factory=list)


@dataclass
class Remediation:
    summary: str = ""
    patch_hint: str | None = None
    references: list[str] = field(default_factory=list)


# ---------------------------------------------------------------- Finding

@dataclass
class Finding:
    id: str
    title: str
    severity: Severity
    confidence: float
    location: dict                          # {file, line, end_line, function}
    category: str = "unknown"

    cwe: str | None = None
    owasp: str | None = None
    evidence: Evidence = field(default_factory=Evidence)
    verification: Verification = field(default_factory=Verification)
    remediation: Remediation = field(default_factory=Remediation)

    sources: list[FindingSource] = field(default_factory=list)
    dedup_key: str = ""
    baselined: bool = False
    in_critical_path: bool = False

    # ★ Agentic 架构新增（05 §1）
    exploitability: Exploitability = Exploitability.UNKNOWN
    coverage_class: CoverageClass | None = None
    audit_layer: AuditLayer = AuditLayer.L1_SYNTACTIC
    recorded_at_turn: int = 0
    attribution: Attribution = Attribution.PROJECT

    # ---------------------------------------------------------- 派生

    @staticmethod
    def make_dedup_key(file: str, line: int, category: str) -> str:
        raw = f"{file}:{line}:{category}".replace("\\", "/")
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    @property
    def is_active(self) -> bool:
        """是否参与门禁判定（06 §6.2 / 04 §4.2）。"""
        return (
            self.verification.verdict != Verdict.FALSE_POSITIVE
            and not self.baselined
            and self.exploitability != Exploitability.NOT_EXPLOITABLE
            and self.attribution == Attribution.PROJECT
        )

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        for key in ("severity", "exploitability", "coverage_class", "audit_layer", "attribution"):
            v = d.get(key)
            if v is not None:
                d[key] = v
        d["sources"] = [s.value if hasattr(s, "value") else s for s in self.sources]
        d["verification"]["verdict"] = self.verification.verdict.value
        return d


# ---------------------------------------------------------------- 覆盖度

@dataclass
class CoverageEntry:
    """单个 C 类的覆盖状态（06 §2.3）。"""
    coverage_class: str
    status: CoverageStatus = CoverageStatus.UNVERIFIED
    note: str = ""
    evidence_turns: list[int] = field(default_factory=list)   # 支撑证据所在轮次
    evidence_refs: list[str] = field(default_factory=list)    # 支撑证据描述
    findings: list[str] = field(default_factory=list)         # 关联的 finding id

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        return d


@dataclass
class Budget:
    """双预算（06 §5.4）。"""
    max_turns: int = 40
    max_tokens: int = 200_000
    max_seconds: int = 0                    # 0 = 不限
    turns_used: int = 0
    tokens_used: int = 0
    seconds_used: float = 0.0

    @property
    def turns_left(self) -> int:
        return max(0, self.max_turns - self.turns_used)

    @property
    def tokens_left(self) -> int:
        return max(0, self.max_tokens - self.tokens_used)

    @property
    def exhausted(self) -> bool:
        if self.turns_left <= 0 or self.tokens_left <= 0:
            return True
        return bool(self.max_seconds and self.seconds_used >= self.max_seconds)

    @property
    def ratio_used(self) -> float:
        """已用比例，取轮次与 token 的较大者——驱动 nudge 触发（06 §5.6）。"""
        t = self.turns_used / self.max_turns if self.max_turns else 0.0
        k = self.tokens_used / self.max_tokens if self.max_tokens else 0.0
        return max(t, k)
