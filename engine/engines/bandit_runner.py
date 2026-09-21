# -*- coding: utf-8 -*-
"""Bandit 接入。

★ 本 runner 的**核心职责不是解析命中，而是精确统计跳过**。

## 实测确证（2026-09-19，对照实验）

| 样本 | metrics loc | 命中 |
|---|---|---|
| `print "x"`（Py2 语法） | **11** | **0 条** |
| `print("x")`（Py3，其余逐字相同） | 11 | **4 条** B403/B301/B605/B608 |

**Bandit 会读文件、数行数、记入 metrics，然后对 Py2 语法文件一条都不报。**
这是最危险的一类"覆盖率假象"——报告上看起来它扫过了，实际什么都没分析。

靶子上受影响的 9 个文件里包含 `app/sessions/backends/base.py`
（`pickle.loads` 反序列化点）与 `app/ydata/views.py`。

## 对账判据（可证明，不依赖 Bandit 自述）

**不要**用 metrics 里有没有这个文件来判断——实测它对被跳过的文件同样计数。
正确判据：**Bandit 用 Python 3.14 的内置 `ast`，凡是 Py3 `ast` 解析不了的文件，
它必然分析不了。** 这正是自研解析层 `detect_version()` 的判据，因此：

    version != "3"  ⟺  Bandit 未覆盖

这是等价关系而非统计推断，不会漏也不会误报。
"""
from __future__ import annotations

import json
from pathlib import Path

from .base import EngineHit, EngineResult, EngineRunner


class BanditRunner(EngineRunner):
    name = "bandit"

    def __init__(self, cfg, parsed: dict | None = None) -> None:
        super().__init__(cfg)
        # {rel: ParsedModule}，由 collect 传入——用于对账跳过项
        self.parsed = parsed or {}

    def _run(self, targets: list[str] | None) -> EngineResult:
        cfg = self.cfg.engines
        tgt = [str(Path(self.repo) / t) if t else str(self.repo)
               for t in (targets or [""])]

        # `-l` = 报 LOW 及以上。
        # ★ 不要写 `-ll`——那是**MEDIUM 及以上**的阈值，实测把 22 条砍成 4 条。
        # 过滤策略属于账本（可审计、可解释），不该在引擎层静默丢弃。
        args = ["bandit", "-r", "-f", "json", "-q", "--exit-zero", "-l", *tgt]

        data, err = self._tool_json(args, timeout=cfg.semgrep_timeout)
        if data is None:
            return EngineResult(self.name, ok=False,
                                error=f"bandit 执行失败: {err[:400]}")

        hits: list[EngineHit] = []
        seen_files: set[str] = set()
        for r in data.get("results") or []:
            rel = self._rel(r.get("filename", ""))
            if rel:
                seen_files.add(rel)
            md = r.get("issue_cwe") or {}
            hits.append(EngineHit(
                source="bandit",
                rule=r.get("test_id", ""),
                file=rel,
                line=int(r.get("line_number") or 0),
                end_line=int(r.get("line_range", [0])[-1] if r.get("line_range") else 0),
                severity=str(r.get("issue_severity", "MEDIUM")).upper(),
                message=str(r.get("issue_text", "")).strip(),
                # bandit 的 code 字段已带行号，直接可用
                snippet=str(r.get("code", ""))[:1500].rstrip(),
                cwe=[f"CWE-{md.get('id')}" if md.get("id") else ""],
                confidence=str(r.get("issue_confidence", "")),
                extra={"more_info": r.get("more_info", ""),
                       "test_name": r.get("test_name", "")},
            ))

        # ★ 跳过对账（等价判据，见模块 docstring）
        # `version != "3"` ⟺ Py3 ast 解析不了 ⟺ Bandit 必然分析不了。
        # **不要**改回「在 metrics 里出现过就算分析过」——实测被跳过的文件同样计入 metrics。
        if self.parsed:
            analyzable = [rel for rel, m in self.parsed.items()
                          if getattr(m, "version", "") == "3"]
            skipped = sorted(rel for rel, m in self.parsed.items()
                             if getattr(m, "version", "") != "3")
        else:
            # 未传入解析结果时只能退化为"有命中的文件"，会在覆盖率上偏乐观——
            # 调用方必须传 parsed（collect() 总是提供），此处仅为兜底不崩。
            analyzable, skipped = sorted(seen_files), []

        # 未解析的文件里，哪些属于审计范围？只有这些需要在报告里点名。
        return EngineResult(
            self.name, hits=hits,
            skipped_files=skipped,
            skipped_reason="Bandit 使用 Py3 ast，无法解析这些文件的语法"
                           "（实测：它会读文件、数行数、记入 metrics，然后一条都不报）",
            analyzed_files=len(analyzable),
            raw_counts={
                "results": len(hits),
                "py3_analyzable": len(analyzable),
                "not_analyzable": len(skipped),
            },
        )


def merge_duplicate_hits(hits: list[EngineHit]) -> list[EngineHit]:
    """同一位置被多引擎命中时保留信息量最大的那条，另一条记入 extra。

    实测需要：`app/admin/views.py` 的 open-redirect 同时被 semgrep 报（框架语义）
    和可能的其它规则命中。直接并排展示会让 Agent 以为是两个问题。
    """
    by_key: dict[str, EngineHit] = {}
    for h in hits:
        k = f"{h.file}:{h.line}:{h.rule}"
        if k in by_key:
            prev = by_key[k]
            prev.extra.setdefault("also_reported_by", []).append(h.source)
            continue
        by_key[k] = h
    return list(by_key.values())
