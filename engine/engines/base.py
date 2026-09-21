# -*- coding: utf-8 -*-
"""静态引擎接入的公共结构。

**铁律（与 parse.py 同源）**：引擎跳过的文件**必须显式报告**。

实测依据：Bandit 1.9.4 静默跳过全部 9 个 Python 2 文件——其中包含
`app/sessions/backends/base.py`（`pickle.loads` 反序列化点）。若不声明，
报告上会呈现为"Bandit 跑过了没问题"，而事实是**根本没跑**。
用户必须能区分"审过了没问题"和"没审"（06 §4.3）。
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path

from ..util import rel_posix, run_tool_json


@dataclass
class EngineHit:
    source: str
    rule: str
    file: str                      # 仓库相对 POSIX 路径
    line: int
    end_line: int = 0
    severity: str = "MEDIUM"
    message: str = ""
    snippet: str = ""
    cwe: list[str] = field(default_factory=list)
    owasp: list[str] = field(default_factory=list)
    confidence: str = ""
    extra: dict = field(default_factory=dict)

    @property
    def key(self) -> str:
        return f"{self.source}:{self.rule}:{self.file}:{self.line}"

    def to_candidate(self) -> dict:
        return {
            "source": self.source, "rule": self.rule, "file": self.file,
            "line": self.line, "severity": self.severity,
            "message": self.message[:400], "snippet": self.snippet[:1500],
            "attrs": {"end_line": self.end_line, "cwe": self.cwe,
                      "owasp": self.owasp, "confidence": self.confidence},
        }


@dataclass
class EngineResult:
    engine: str
    hits: list[EngineHit] = field(default_factory=list)
    ok: bool = True
    error: str = ""
    skipped_files: list[str] = field(default_factory=list)
    skipped_reason: str = ""
    analyzed_files: int = 0
    duration_s: float = 0.0
    raw_counts: dict = field(default_factory=dict)

    def summary(self) -> str:
        L = [f"{self.engine}: {len(self.hits)} 条命中"
             f"，分析 {self.analyzed_files} 个文件，{self.duration_s:.1f}s"]
        if self.skipped_files:
            L.append(f"  ⚠️ **跳过 {len(self.skipped_files)} 个文件**"
                     f"（{self.skipped_reason}）——这些文件的此类风险**未被本引擎覆盖**：")
            for f in self.skipped_files[:12]:
                L.append(f"    · {f}")
            if len(self.skipped_files) > 12:
                L.append(f"    · …另有 {len(self.skipped_files) - 12} 个")
        if not self.ok:
            L.append(f"  ❌ 引擎失败：{self.error[:300]}")
        return "\n".join(L)


class EngineRunner:
    """引擎基类。`_parse` 由子类实现，公共部分（计时/异常/跳过统计）在此统一。"""

    name = "engine"

    def __init__(self, cfg) -> None:
        self.cfg = cfg
        self.repo = Path(cfg.repo)

    def available(self) -> bool:
        from ..util import find_tool
        return find_tool(self.name) is not None

    def run(self, targets: list[str] | None = None) -> EngineResult:
        t0 = time.time()
        try:
            r = self._run(targets)
        except Exception as e:
            return EngineResult(self.name, ok=False,
                                error=f"{type(e).__name__}: {e}",
                                duration_s=time.time() - t0)
        r.duration_s = time.time() - t0
        return r

    def _run(self, targets: list[str] | None) -> EngineResult:
        raise NotImplementedError

    # -------------------------------------------------- 工具

    def _rel(self, p: str) -> str:
        """把引擎返回的绝对路径（Windows 反斜杠）归一为仓库相对 POSIX 路径。"""
        if not p:
            return ""
        return rel_posix(Path(p), self.repo)

    def _oneline(self, snippet: str, line: int) -> str:
        """从多行代码块里取出命中行，便于 Agent 快速判断。"""
        if not snippet:
            return ""
        return snippet[:1500]

    def _tool_json(self, args: list[str], timeout: int, cwd: Path | None = None):
        return run_tool_json(args, timeout=timeout, cwd=cwd or self.repo)
