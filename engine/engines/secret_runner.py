# -*- coding: utf-8 -*-
"""凭据扫描引擎。

## 与其他引擎最重要的区别

semgrep 和 bandit 报的是「这里有个危险的写法」——可以原样进报告。
本引擎报的是「这里有个**真的密钥**」。原样进报告的后果是：密钥被抄送给
每一个能看报告的人，以及每一个读到账本摘要的模型（账本摘要每轮都注入）。

所以本引擎与 `redact.py` 是**绑定**的：命中值在离开本循环之前就被送进
`SecretVault`，`EngineHit` 携带的只有 `Redaction`——类型、长度、指纹、
前 3 位预览。**这个类里没有任何一条路径会把原值写进返回值。**

## 指纹带来的一个真实好处

同一个凭据散落在多个文件里，是配置管理失控的典型征兆（改了一处漏了另一处）。
指纹让我们能把它们**合并成一条命中并列出全部位置**，而无需保留明文。
「这个 key 在 3 个文件里都有」这个结论，不需要知道 key 是什么。

## 误报控制

凭据扫描最容易变成噪声源。三类值会被主动排除：占位符（`your_key_here`）、
环境变量引用（`os.environ[...]`）、结构性常量（全同字符、纯数字）。
判据写得很直白——宁可漏掉一个可疑值，也不要让报告被 40 条 `password = 'test'`
淹掉，那会掩盖掉真正的那个。
"""
from __future__ import annotations

import re

from ..redact import Redaction, SecretVault, fingerprint, scrub
from ..util import read_text
from .base import EngineHit, EngineResult, EngineRunner

# (kind, severity, pattern, 取值组, 说明)
# 顺序即优先级：一行只报最先命中的那条，否则 SECRET_KEY 会被报两次。
_RULES: list[tuple[str, str, re.Pattern, int, str]] = [
    ("private_key", "CRITICAL",
     re.compile(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"),
     0, "私钥内容直接内联在源码中——拿到仓库即拿到私钥"),

    ("django_secret_key", "HIGH",
     re.compile(r"(?i)\bSECRET_KEY\b\s*[:=]\s*(['\"])([^'\"\n]{16,})\1"),
     2, "SECRET_KEY 硬编码——可用于伪造 session cookie 与密码重置令牌"),

    ("aws_akid", "HIGH", re.compile(r"\b(?:AKIA|ASIA)([0-9A-Z]{16})\b"),
     0, "AWS Access Key ID 硬编码"),

    ("anthropic_key", "HIGH", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b"),
     0, "Anthropic API Key 硬编码"),
    ("openai_key", "HIGH", re.compile(r"\bsk-(?!ant-)[A-Za-z0-9_\-]{24,}\b"),
     0, "OpenAI 风格 API Key 硬编码"),
    ("github_token", "HIGH", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
     0, "GitHub Token 硬编码"),
    ("slack_token", "HIGH", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b"),
     0, "Slack Token 硬编码"),

    ("connection_string", "MEDIUM",
     re.compile(r"\b(?:mysql|postgres|postgresql|mongodb|redis|amqp)://"
                r"[^\s:@/]+:([^\s:@/]{3,})@[^\s/'\"]+"),
     0, "数据库/中间件连接串内嵌明文口令"),

    ("jwt", "LOW",
     re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"),
     0, "JWT 字面量（确认是否为长期有效的固定令牌）"),

    ("hardcoded_credential", "MEDIUM",
     re.compile(r"(?i)\b(password|passwd|pwd|secret|api_key|apikey|access_key|"
                r"auth_token|private_token|db_pass)\b\s*[:=]\s*"
                r"(['\"])([^'\"\n]{6,})\2"),
     3, "口令/令牌字面量赋值"),
]

# 不像凭据的值——排除它们，否则报告会被示例配置淹没
_PLACEHOLDER = re.compile(
    r"(?i)^(?:your|my|test|demo|sample|example|placeholder|dummy|foo|bar|baz|"
    r"xxx+|changeme|change_me|todo|none|null|nil|empty|secret|password|"
    r"\*+|\.+|-+|_+|\s*)$")
_ENV_REF = re.compile(
    r"(?i)(os\.environ|os\.getenv|getenv|environ\[|config\(|settings\.|"
    r"self\.\w+|\w+\.\w+|%\w|\{\w+\}|input\(|\$\{)")


def _plausible(value: str, kind: str) -> bool:
    """这个值像不像一个真凭据。

    **宁可漏掉一个可疑值，也不要让报告被 40 条 `password = 'test'` 淹掉**——
    噪声的代价不只是难看，它会掩盖掉真正的那一条。
    """
    v = value.strip().strip("'\"")
    if not v or len(v) < 6:
        return False
    if _PLACEHOLDER.match(v):
        return False
    if len(set(v)) <= 3:              # aaaaaaaa / 12345678
        return False
    if _ENV_REF.search(v):            # 不是字面量，是引用
        return False
    if kind != "private_key" and v.isdigit():
        return False
    return True


class SecretRunner(EngineRunner):
    """内置凭据扫描。不依赖外部工具——`available()` 恒为真。"""

    name = "secret"

    def __init__(self, cfg, scope=None) -> None:
        super().__init__(cfg)
        self.scope = scope
        # ★ 原值的唯一存放处。它不会被写进 EngineResult，也不会出现在
        #   候选、账本或报告里。
        self.vault = SecretVault()

    def available(self) -> bool:
        return True

    # -------------------------------------------------- 扫描

    def _targets(self) -> list[str]:
        if self.scope is None:
            return []
        seen: set[str] = set()
        out: list[str] = []
        for fi in self.scope.files.values():
            rel = getattr(fi, "rel", "")
            # 凭据扫描不跳过 vendored：第三方代码里的真密钥同样是真密钥，
            # 而且"库文件里躺着一个生产密钥"恰恰是更严重的情形。
            if rel and rel not in seen:
                seen.add(rel)
                out.append(rel)
        return out

    def _run(self, targets: list[str] | None) -> EngineResult:
        res = EngineResult(self.name)
        rels = targets or self._targets()
        if not rels:
            res.ok = False
            res.error = "无可扫描的文件（未传入 scope）"
            return res

        # fingerprint -> 聚合记录。同值多处出现合并成一条。
        found: dict[str, dict] = {}

        for rel in rels:
            try:
                text = read_text(self.repo / rel)
            except Exception:
                continue
            if not text:
                continue
            res.analyzed_files += 1

            for lineno, line in enumerate(text.splitlines(), 1):
                if len(line) > 4000:      # 压缩过的一行文件，没有可读性
                    continue
                for kind, sev, pat, gi, note in _RULES:
                    m = pat.search(line)
                    if not m:
                        continue
                    raw = m.group(gi) if gi else m.group(0)
                    if not _plausible(raw, kind):
                        continue
                    r = self.vault.add(raw, kind, rel, lineno)
                    rec = found.setdefault(r.fingerprint, {
                        "kind": kind, "sev": sev, "note": note,
                        "redaction": r, "locs": []})
                    rec["locs"].append((rel, lineno))
                    break             # 一行只报一条，避免同值重复计数

        res.raw_counts = {"secrets": len(found),
                          "occurrences": sum(len(v["locs"]) for v in found.values())}

        for fp, rec in found.items():
            r: Redaction = rec["redaction"]
            locs: list[tuple[str, int]] = rec["locs"]
            f0, l0 = locs[0]

            msg = rec["note"]
            if len(locs) > 1:
                # ★ 这是指纹设计的兑现点：能说出"同一个值散落在 N 处"，
                #   却说不出这个值是什么。
                msg += (f"。**同一凭据出现在 {len(locs)} 处**（改一处漏一处）："
                        + "、".join(f"{f}:{l}" for f, l in locs[:6])
                        + ("…" if len(locs) > 6 else ""))
            if rec["kind"] == "django_secret_key" and r.preview.startswith("dja"):
                msg += "。值以 `django-insecure-` 开头，是 Django 脚手架生成的开发值"

            hits_extra = {
                "fingerprint": fp,
                "redaction": r.to_dict(),
                "occurrences": [{"file": f, "line": l} for f, l in locs],
                "already_sanitized": True,
            }
            res.hits.append(EngineHit(
                source=self.name, rule=f"secret/{rec['kind']}",
                file=f0, line=l0, end_line=l0, severity=rec["sev"],
                message=msg[:600],
                # 片段也过 scrub——即便这里已经知道值被换掉了，
                # 同一行上还可能有第二个凭据（正则只报了优先级最高的那个）。
                snippet=scrub(f"{l0}: " + _line_at(self.repo / f0, l0))[:600],
                cwe=["CWE-798"], owasp=["A02:2021"],
                confidence="HIGH", extra=hits_extra))

        # 同一文件多值：按文件行号排序，让报告读起来有次序
        res.hits.sort(key=lambda h: (h.file, h.line))
        return res

    def secret_report(self) -> list[dict]:
        """供报告使用的凭据清单（已脱敏，可安全写盘）。"""
        return [r.to_dict() for r in self.vault.all_redactions()]


def _line_at(path, lineno: int) -> str:
    try:
        lines = read_text(path).splitlines()
        return lines[lineno - 1] if 0 < lineno <= len(lines) else ""
    except Exception:
        return ""


# ------------------------------------------------------------------ 自检

if __name__ == "__main__":
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

    from engine.config import Config
    from engine.collect import collect
    from engine.util import force_utf8
    force_utf8()

    repo = Path(sys.argv[1] if len(sys.argv) > 1 else "审计对象/ylinux_old-master")
    cfg = Config.load(repo, None, {})
    scope, _ = collect(cfg)
    r = SecretRunner(cfg, scope=scope).run()
    print(r.summary())
    print()
    for h in r.hits:
        print(f"  [{h.severity:8s}] {h.file}:{h.line}  {h.rule}")
        print(f"             {h.message[:150]}")
        print(f"             片段 {h.snippet[:110]}")
    print()
    print("扫描器自己的账：", end=" ")
    for k, v in r.raw_counts.items():
        print(f"{k}={v}", end="  ")
    print()
