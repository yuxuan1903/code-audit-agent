# -*- coding: utf-8 -*-
"""凭据脱敏管道（03 §5「数据不出域」）。

**这个模块为什么必须存在**

凭据扫描器与「把代码发给 LLM」这两件事放在一起，会自然形成一条把密钥
送出去的通道：扫描器在 settings.py 找到 SECRET_KEY → 写进候选 → 候选进
账本 → 账本摘要每轮注入给模型 → **密钥就这样离开了本机**。整条链路上
没有任何一环是"故意"的，但结果是确定的。

所以规则是硬的：**凭据的值在离开扫描器之前就被替换掉**。下游（账本、
报告、LLM 上下文）能拿到的只有五样东西：

    kind         类型（django_secret_key）
    fingerprint  sha256 前 12 位——用来判断「两处是不是同一个凭据」
    length       长度——用来识别被截断的占位符
    preview      前 3 位 + `***`——用来让人确认类型（`AKIA` vs `sk-`）
    file:line    位置——这才是报告真正要说的东西

前 3 位是刻意留的：足以区分凭据种类，不足以复原。指纹也是刻意的：
它让「同一个 key 散落在 3 个文件里」这类结论成为可能，而无需保留明文。

**本模块不提供任何把原值序列化的方法**——没有 `to_dict()`，没有
`__repr__` 泄露，没有导出。要原值只能显式调用 `SecretVault.reveal()`，
而它记录调用者。这不是防攻击者，是防我们自己图省事。
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

__all__ = ["Redaction", "SecretVault", "scrub", "redact_snippet"]


# ------------------------------------------------------------------ 结构

@dataclass(frozen=True)
class Redaction:
    """一个凭据的**可外发替身**。它不含原值，构造不出来原值。"""

    kind: str
    fingerprint: str
    length: int
    preview: str
    file: str = ""
    line: int = 0

    def __str__(self) -> str:
        loc = f" @{self.file}:{self.line}" if self.file else ""
        return f"<{self.kind}:{self.preview} len={self.length} fp={self.fingerprint}>{loc}"

    def to_dict(self) -> dict:
        return {"kind": self.kind, "fingerprint": self.fingerprint,
                "length": self.length, "preview": self.preview,
                "file": self.file, "line": self.line}


def _preview(value: str) -> str:
    """前 3 位 + ***。短值全掩——3 位预览对 8 字符的口令就是半个口令。"""
    v = value.strip().strip("'\"")
    if len(v) < 10:
        return "***"
    return v[:3] + "***"


def fingerprint(value: str) -> str:
    return hashlib.sha256(value.strip().encode("utf-8", "replace")).hexdigest()[:12]


class SecretVault:
    """凭据原值的隔离容器。

    原值只在这里存在，且**不参与序列化**。账本、报告、外发请求拿到的是
    `Redaction`。同一个值出现多次时复用同一条 Redaction——指纹相同即可
    关联，不必让明文在系统里多留一份。
    """

    def __init__(self) -> None:
        self._values: dict[str, str] = {}       # fingerprint -> 原值
        self._redactions: dict[str, Redaction] = {}
        self.reveal_calls: list[str] = []       # 谁要过原值

    def add(self, value: str, kind: str, rel: str = "", line: int = 0) -> Redaction:
        v = value.strip()
        fp = fingerprint(v)
        self._values.setdefault(fp, v)
        if fp in self._redactions:
            return self._redactions[fp]
        r = Redaction(kind=kind, fingerprint=fp, length=len(v),
                      preview=_preview(v), file=rel, line=line)
        self._redactions[fp] = r
        return r

    def get(self, fp: str) -> Redaction | None:
        return self._redactions.get(fp)

    def reveal(self, fp: str, why: str = "") -> str | None:
        """取回原值。**记录调用者**——任何一次取用都应该有理由。

        正常流程里没有人会调它。它存在是为了让「我确实需要原值」这个
        决定变得显式、可审计，而不是顺手 print 一下。
        """
        self.reveal_calls.append(f"{fp}: {why or '未说明理由'}")
        return self._values.get(fp)

    def all_redactions(self) -> list[Redaction]:
        return list(self._redactions.values())

    def __len__(self) -> int:
        return len(self._redactions)

    def __repr__(self) -> str:
        return f"<SecretVault {len(self._redactions)} 个凭据（原值不外显）>"


# ------------------------------------------------------------------ 兜底脱敏

# 通用凭据形态。这里的目标不是"扫得全"（那是 secret_runner 的活），
# 而是**兜底**：任何即将外发的文本都过一遍，防止某个凭据从我们没预料到的
# 路径上溜出去（比如被审代码里的测试夹具、注释里的示例密钥）。
_SCRUB_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("private_key", re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]{0,4000}?"
        r"-----END [A-Z ]*PRIVATE KEY-----")),
    ("aws_akid", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("openai_key", re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}\b")),
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}")),
    ("connection_string", re.compile(
        r"\b(?:mysql|postgres|postgresql|mongodb|redis|amqp)://"
        r"[^\s:@/]+:[^\s:@/]{3,}@[^\s/]+")),
    ("assigned_secret", re.compile(
        r"(?i)\b(?:password|passwd|pwd|secret|secret_key|api_key|apikey|"
        r"access_key|auth_token|private_token)\b\s*[:=]\s*"
        r"(['\"])([^'\"\n]{8,})\1")),
]

_SCRUB_EXEMPT = re.compile(
    r"(?i)^\s*(?:your|my|test|demo|sample|example|placeholder|dummy|xxx|"
    r"change|refer|see|the|this|todo|none|null|empty|password|secret)")


def scrub(text: str) -> str:
    """把任意文本里的凭据替换成脱敏替身。

    **外发前的最后一道闸**：发给 LLM 的工具结果、写进报告的代码片段，
    都应该先过这里。它不保证扫全（没有任何正则能），但能把最常见的
    几类凭据挡住——而这些正是实际操作中最容易顺手贴出去的东西。
    """
    if not text:
        return text
    out = text
    for kind, pat in _SCRUB_PATTERNS:
        def _sub(m: re.Match, _kind: str = kind) -> str:
            v = m.group(0)
            # 赋值式还要看值本身像不像占位符——`password = 'your_pass'`
            # 是文档示例，标红它只会制造噪声
            if _kind == "assigned_secret":
                val = m.group(2)
                if _SCRUB_EXEMPT.match(val) or len(set(val)) <= 3:
                    return v
                v = val
            return f"<{_kind}:{_preview(v)} len={len(v.strip())} fp={fingerprint(v)}>"
        out = pat.sub(_sub, out)
    return out


def redact_snippet(snippet: str, line: int = 0) -> str:
    """对代码片段做脱敏，并保留行号结构（报告里要对得上）。"""
    if not snippet:
        return ""
    return "\n".join(
        f"{line + i if line else ''}: {scrub(ln)}".lstrip(": ")
        for i, ln in enumerate(snippet.splitlines())
    )


# ------------------------------------------------------------------ 自检

if __name__ == "__main__":
    v = SecretVault()
    s = "SECRET_KEY = 'django-insecure-abc123def456ghi789'"
    r = v.add("django-insecure-abc123def456ghi789", "django_secret_key",
              "settings.py", 79)
    print("Redaction:", r)
    print("序列化:", r.to_dict())
    print()
    for t in [
        s,
        "password = 'hunter2xyz'",
        "password = 'your_password_here'",
        "aws = 'AKIAIOSFODNN7EXAMPLE'",
        "conn = 'mysql://root:s3cr3t@10.0.0.1:3306/db'",
        "token = 'ghp_abcdefghijklmnopqrstuvwxyz0123456789'",
        "DEBUG = True",
    ]:
        print(f"  {t[:52]:54s} → {scrub(t)[:78]}")
