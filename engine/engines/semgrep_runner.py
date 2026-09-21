# -*- coding: utf-8 -*-
"""Semgrep 接入。

实测（靶子）：`p/python` + `p/secrets` 全量扫描 105 文件可行，输出 11 条命中
（10 条 open-redirect 落在 `app/admin/views.py` 与各 urls 跳转，1 条 sha1）。

Semgrep 的价值在于**跨行数据流**（open-redirect 需要追踪 `request.GET` → `redirect()`），
这是 Bandit 的 AST 单点检查做不到的。两者互补：Bandit 覆盖 Python 特有的危险 API
（B605 `os.system`、B608 拼接 SQL），Semgrep 覆盖框架语义的污点流。
"""
from __future__ import annotations

import json
from pathlib import Path

from .base import EngineHit, EngineResult, EngineRunner


class SemgrepRunner(EngineRunner):
    name = "semgrep"

    def _run(self, targets: list[str] | None) -> EngineResult:
        cfg = self.cfg.engines
        rulesets = cfg.semgrep_rulesets or ["p/python"]
        tgt = [str(Path(self.repo) / t) if t else str(self.repo)
               for t in (targets or [""])]

        args = ["semgrep", "--json", "--quiet", "--timeout", "30"]
        for rs in rulesets:
            args += ["--config", rs]
        args += ["--max-target-bytes", "2000000", *tgt]

        data, err = self._tool_json(args, timeout=cfg.semgrep_timeout)
        if data is None:
            return EngineResult(self.name, ok=False,
                                error=f"semgrep 执行失败: {err[:400]}")

        hits: list[EngineHit] = []
        skipped: list[str] = []
        for r in data.get("results") or []:
            extra = r.get("extra") or {}
            md = extra.get("metadata") or {}
            # ★ 跳过项必须收集：semgrep 会因解析失败/文件过大而跳过，
            # 静默丢弃等于把"没扫到"伪装成"扫过没问题"
            path = r.get("path") or ""
            hits.append(EngineHit(
                source="semgrep",
                rule=r.get("check_id", ""),
                file=self._rel(path),
                line=(r.get("start") or {}).get("line", 0),
                end_line=(r.get("end") or {}).get("line", 0),
                severity=_sev(md.get("impact") or extra.get("severity") or "WARNING"),
                message=(extra.get("message") or "").strip(),
                snippet=(extra.get("lines") or "")[:1500],
                cwe=[str(c) for c in _aslist(md.get("cwe"))],
                owasp=[str(o) for o in _aslist(md.get("owasp"))],
                confidence=str(md.get("confidence", "")),
                extra={"fingerprint": extra.get("fingerprint", ""),
                       "references": _aslist(md.get("references"))[:4]},
            ))

        for e in data.get("errors") or []:
            t = str(e.get("path") or e.get("message") or "")
            if t:
                skipped.append(self._rel(t) or t[:120])

        # paths.skipped 是 semgrep 明确的跳过清单
        p = data.get("paths") or {}
        for t in (p.get("skipped") or []):
            s = self._rel(str(t)) or str(t)[:120]
            if s not in skipped:
                skipped.append(s)

        return EngineResult(
            self.name, hits=hits,
            skipped_files=skipped,
            skipped_reason="semgrep 报告解析失败/被跳过",
            analyzed_files=len(p.get("scanned") or []),
            raw_counts={"results": len(hits),
                        "errors": len(data.get("errors") or [])},
        )


def _aslist(v) -> list:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


_SEV_MAP = {
    "ERROR": "HIGH", "ERRORHIGH": "HIGH", "HIGH": "HIGH",
    "WARNING": "MEDIUM", "MEDIUM": "MEDIUM",
    "INFO": "LOW", "LOW": "LOW",
    "CRITICAL": "CRITICAL",
}


def _sev(v) -> str:
    return _SEV_MAP.get(str(v).strip().upper(), "MEDIUM")
