# -*- coding: utf-8 -*-
"""外部账本（06 §5.7）。

**存在的理由**：实测缺陷 D1 表明模型不会自觉维护记账——它会重复已查过的方向、
遗忘还没覆盖的 C 类、把同一个问题记两遍。把"记住什么"交给对话上下文是靠不住的。

因此：**账本在对话之外，是唯一真相来源。** 每一轮把账本的确定性摘要喂回给模型。
模型看到的不是"它记得什么"，而是"实际记下了什么"。这样即使模型漂移，
账本仍然完整，收敛检测仍然有效。

三类账目：
  · findings   已记录的问题（含证据契约校验）
  · coverage   七个 C 类的覆盖状态（终态强制）
  · candidates 引擎命中的待处置项（每项必须到终态，否则不得 conclude）
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from ..schema import (
    Attribution, CoverageClass, CoverageEntry, CoverageStatus, Evidence,
    Exploitability, Finding, FindingSource, Severity, Verdict,
)
from .recall import RecallScanner


# ---------------------------------------------------------------- 候选

@dataclass
class Candidate:
    """引擎命中，等待 Agent 处置。

    ★ 为什么候选要单独记账：静态引擎必然有误报（Bandit 在
    `app/account/backends.py` 上必报 B608，而正确答案是不报）。
    若只让模型"看着办"，它会挑几条确认、其余静默忽略——**静默忽略不可审计**。
    每个候选强制到终态（confirmed / dismissed / deferred），且带理由。
    """
    id: str
    source: str                      # semgrep | bandit | deps | secret
    rule: str
    file: str
    line: int
    severity: str = "MEDIUM"
    message: str = ""
    snippet: str = ""
    attrs: dict = field(default_factory=dict)

    status: str = "open"             # open | confirmed | dismissed | deferred
    reason: str = ""
    finding_id: str = ""
    at_turn: int = 0

    @property
    def is_open(self) -> bool:
        return self.status == "open"


# ---------------------------------------------------------------- 账本

class Ledger:
    def __init__(self, scope, cfg) -> None:
        self.scope = scope
        self.cfg = cfg

        self.findings: dict[str, Finding] = {}
        self.candidates: dict[str, Candidate] = {}
        self.coverage: dict[str, CoverageEntry] = {
            c.value: CoverageEntry(coverage_class=c.value)
            for c in CoverageClass
        }

        # 收口结论（由主循环在 conclude 通过时写入）
        self.conclusion: dict = {}

        # 文件审查轨迹：rel -> [(start, end), ...]。用于"重复读同一段"检测，
        # 以及覆盖度契约里"文件是否被真正看过"的客观依据。
        self.reviewed: dict[str, list[tuple[int, int]]] = {}
        self._dedup: dict[str, str] = {}          # dedup_key -> finding id
        self._cand_seq = 0
        self._find_seq = 0

        # 审计日志（03 §5：数据外发的可追溯证据）
        self.events: list[dict] = []

        # 收敛对账（06 §5.8）。扫描器跨轮存活——"提过"发生在过去，
        # 而处置发生在未来，它得同时看得见两头。
        self.recall = (RecallScanner(
            scope,
            max_mention=cfg.agent.recall_max_mention,
            max_file=cfg.agent.recall_max_file,
            max_total=cfg.agent.recall_max_total,
            max_mention_total=getattr(cfg.agent, "recall_max_mention_total", 6),
            max_file_total=getattr(cfg.agent, "recall_max_file_total", 6),
        ) if getattr(cfg.agent, "recall_enabled", True) else None)

    # -------------------------------------------------- 事件

    def log(self, kind: str, **kw) -> None:
        self.events.append({"kind": kind, **kw})

    # -------------------------------------------------- 候选

    def add_candidate(self, source: str, rule: str, file: str, line: int,
                      severity: str = "MEDIUM", message: str = "",
                      snippet: str = "", attrs: dict | None = None) -> Candidate:
        self._cand_seq += 1
        cid = f"C{self._cand_seq:04d}"
        c = Candidate(id=cid, source=source, rule=rule, file=file, line=line,
                      severity=severity, message=message, snippet=snippet,
                      attrs=attrs or {})
        self.candidates[cid] = c
        return c

    def add_candidates(self, cands: list[dict]) -> list[Candidate]:
        return [self.add_candidate(**c) for c in cands]

    @property
    def open_candidates(self) -> list[Candidate]:
        return [c for c in self.candidates.values() if c.is_open]

    # -------------------------------------------------- 收敛对账

    def recall_scan(self, turn: int) -> list[Candidate]:
        """★ 06 §5.8：把"推理里提过、账本里没有"的位置变成待处置候选。

        存在的理由（验收报告 §4）：两次真实运行的漏报**没有一条**是
        "读不懂代码"或"判错了类型"，全都是"看见了、说出来了、没落账"。
        证据在轨迹里，而报告只读账本——所以漏报不是"没发现"，
        是"发现了但没留下"。

        生成的是**候选**而不是结论：模型必须逐条处置（confirmed 要给
        finding_id、dismissed 要给理由）。于是"发现了但决定不报"从一个
        静默的省略，变成一条留在报告里的判断。
        """
        if self.recall is None:
            return []
        # ★ 先回收已经不再成立的线索，再提新的。
        self._reap_stale(turn)
        items = self.recall.scan(self, turn, self.coverage_of_file)
        out: list[Candidate] = []
        for it in items:
            c = self.add_candidate(
                source="recall", rule=it["kind"],
                file=it["file"], line=it["line"],
                severity="INFO", message=it["why"],
                snippet=it.get("seg", ""),
                attrs={"turn": it.get("turn", 0),
                       "hazard": it.get("hazard", ""),
                       "ratio": round(float(it.get("ratio") or 0), 3),
                       "entries": it.get("entries", 0)},
            )
            # ★ 这里**不能**用 `kind=` 作参数名：`log(kind, **kw)` 已经把
            # 第一个位置参数占成了 kind，再传一个 kind 就是 TypeError。
            # 这个撞名让对账机制在真实运行里一调用就抛异常，而 run() 的
            # 兜底 except 把它吞成了 loop_error——机制上线即失效且不报错。
            # 用 `rule=`（与 Candidate.rule 同名）记 mention/file 两类。
            self.log("recall_flagged", id=c.id, rule=it["kind"],
                     file=it["file"], line=it["line"], turn=turn)
            out.append(c)
        return out

    def _reap_stale(self, turn: int) -> list[str]:
        """回收**已经被后续 finding 覆盖**的开放线索。返回被回收的 id。

        ★ 线索的成立与否是**动态**的。提出它的时候那个文件确实没有结论，
        之后模型补上了 finding，这条线索就不再成立——但账本里的候选不会
        自己消失，模型得回头逐条驳回。实测 real-fix：12 条线索只处置了 1 条，
        而未处置的 11 条里绝大多数所在文件**都已经记了 finding**：
        `lib/ylinux_xmlrpc.py`→F-006、`settings.py`→F-009、
        `app/ydata/views.py`→F-007/F-008、`app/account/models.py`→F-005。

        要求模型驳回这些，是让它**为自己已经做对的事再付一次账**——
        几十次调用花在确认"我刚才记的那个文件，现在确实记过了"。
        这类核对是机械的，系统自己做更快也更可靠。

        注意边界：**只有"确有 finding"才回收**。模型判断为误报、故意不记的
        位置不会被自动关掉——那需要它自己给出理由，这正是对账要留的东西。
        回收理由写明覆盖它的 finding，报告里可独立核对。
        """
        from .recall import REAP_TOL, Accounted
        acc = Accounted(self)
        reaped: list[str] = []
        for c in list(self.open_candidates):
            if c.source != "recall":
                continue
            if c.rule == "mention":
                # ★ 回收用 REAP_TOL（3），不是 LOC_TOL（15）。
                # 同一个文件里另一个函数被记了 finding，**不构成**这条
                # 线索过时的理由——模型仍须自己表态。
                covered = acc.covers({"file": c.file, "line": c.line,
                                      "end_line": c.line}, tol=REAP_TOL)
                why = "该位置随后已被 finding 覆盖"
            else:
                covered = c.file in acc.files or c.file in acc.named
                why = "该文件随后已记录 finding 或已在证据里给出坐标"
            if not covered:
                continue
            # 去重保序：一条 finding 的本体坐标和证据坐标可能都落在这个文件上
            who = "、".join(list(dict.fromkeys(acc.by_file.get(c.file, [])))[:3])
            self.dispose_candidate(
                c.id, "dismissed",
                f"{why}（{who or '见账本'}）——系统自动回收："
                f"线索提出时该处尚无结论，现已有结论故不再追问。", turn=turn)
            reaped.append(c.id)
        if reaped:
            self.log("recall_reaped", ids=reaped, turn=turn)
        return reaped

    def dispose_candidate(self, cid: str, status: str, reason: str,
                          finding_id: str = "", turn: int = 0) -> tuple[bool, str]:
        """处置候选。**理由必填**——无理由的关闭等于静默忽略。"""
        c = self.candidates.get(cid)
        if c is None:
            return (False, f"候选 {cid} 不存在。可用候选：{self._candidate_ids()}")
        if status not in ("confirmed", "dismissed", "deferred"):
            return (False, f"status 必须是 confirmed/dismissed/deferred，收到 {status!r}")
        if not (reason or "").strip():
            return (False, f"处置候选 {cid} 必须给出 reason——"
                           "无理由关闭等同于静默忽略，不可审计")
        if status == "confirmed" and not finding_id:
            return (False, f"确认候选 {cid} 必须同时 record_finding，并给出其 id")
        c.status, c.reason, c.finding_id, c.at_turn = status, reason, finding_id, turn
        self.log("candidate_disposed", id=cid, status=status, reason=reason[:200],
                 turn=turn)
        return (True, f"{cid} → {status}")

    def _candidate_ids(self, limit: int = 12) -> str:
        ids = [c.id for c in self.open_candidates][:limit]
        return ", ".join(ids) if ids else "（无）"

    # -------------------------------------------------- 记录 finding

    def record_finding(self, raw: dict, turn: int = 0,
                       enforce_evidence: bool = True) -> tuple[bool, str]:
        """记录一条 finding。**证据契约在此强制**（06 §2.4）。

        校验失败时返回可操作的错误信息——模型据此补齐后重试，而不是被拒绝后放弃。
        """
        ok, err, f = self._build_finding(raw, turn, enforce_evidence)
        if not ok:
            return (False, err)

        if f.dedup_key in self._dedup:
            exist = self._dedup[f.dedup_key]
            return (True, f"已存在同位置同类的问题（{exist}），本条计入其为重复，"
                          f"未新建。如需补充证据请更新 {exist}。")

        self._dedup[f.dedup_key] = f.id
        self.findings[f.id] = f

        # 归因过滤：非项目代码不计入项目漏洞（06 §5.3）
        fi = self.scope.get(f.location.get("file", ""))
        if fi is not None:
            if fi.forked_from:
                f.attribution = Attribution.PROJECT
            elif fi.attribution == "vendored":
                f.attribution = Attribution.VENDORED
            elif fi.attribution == "suspected":
                f.attribution = Attribution.UNKNOWN
            f.in_critical_path = fi.in_critical_path

        # 自动关联覆盖类
        if f.coverage_class:
            e = self.coverage.get(f.coverage_class.value)
            if e is not None and f.id not in e.findings:
                e.findings.append(f.id)
                if e.status in (CoverageStatus.UNVERIFIED, CoverageStatus.NO_ISSUE):
                    e.status = CoverageStatus.COVERED

        self.log("finding_recorded", id=f.id, severity=f.severity.value,
                 file=f.location.get("file"), line=f.location.get("line"),
                 turn=turn)
        return (True, f"已记录 {f.id}（{f.severity.value}）：{f.title}")

    def _build_finding(self, raw: dict, turn: int,
                       enforce_evidence: bool) -> tuple[bool, str, Finding]:
        # --- 必填项
        for k in ("title", "severity", "file", "line"):
            if raw.get(k) in (None, ""):
                return (False, f"缺少必填字段 {k}", None)

        try:
            sev = Severity(str(raw["severity"]).upper())
        except ValueError:
            return (False, f"severity 必须是 {[s.value for s in Severity]} 之一，"
                           f"收到 {raw['severity']!r}", None)

        try:
            line = int(raw["line"])
        except (TypeError, ValueError):
            return (False, f"line 必须是整数，收到 {raw['line']!r}", None)

        file = str(raw["file"]).replace("\\", "/").lstrip("./")
        fi = self.scope.get(file)
        if fi is None:
            near = [f.rel for f in self.scope.in_scope
                    if file.split("/")[-1] in f.rel][:5]
            hint = f"；相近的可用路径：{near}" if near else ""
            return (False, f"路径 {file!r} 不在仓库中{hint}", None)
        file = fi.rel

        if line < 1 or line > max(fi.lines, 1):
            return (False, f"line {line} 超出 {file} 的行数范围 (1-{fi.lines})", None)

        # --- 证据契约
        ev_raw = raw.get("evidence") or {}
        ev = Evidence(
            snippet=str(ev_raw.get("snippet", ""))[:4000],
            attack_path=list(ev_raw.get("attack_path") or []),
            dataflow=list(ev_raw.get("dataflow") or []),
            mitigations_found=list(ev_raw.get("mitigations_found") or []),
            sink=str(ev_raw.get("sink", "")),
            source=str(ev_raw.get("source", "")),
            reachability=str(ev_raw.get("reachability", "")),
            sanitizer_check=str(ev_raw.get("sanitizer_check", "")),
        )
        if enforce_evidence:
            missing = ev.missing_fields()
            if missing:
                return (False,
                        f"证据不完整，缺少 {missing}。证据契约要求逐项给出："
                        "sink（危险操作所在行+代码）、source（污点来源及其是否可控）、"
                        "reachability（从哪个外部入口可达）、"
                        "sanitizer_check（路径上的净化措施枚举+为何无效）。"
                        "若某项确实不存在（例如无净化措施），说明该事实而不是留空。", None)

        # --- 枚举字段
        cc = None
        if raw.get("coverage_class"):
            try:
                cc = CoverageClass(raw["coverage_class"])
            except ValueError:
                pass
        if cc is None:
            cc = _guess_class(raw.get("category", ""))

        try:
            exp = Exploitability(str(raw.get("exploitability", "unknown")).lower())
        except ValueError:
            exp = Exploitability.UNKNOWN

        self._find_seq += 1
        fid = raw.get("id") or f"F-{self._find_seq:03d}"

        from ..schema import AuditLayer
        try:
            layer = AuditLayer(str(raw.get("audit_layer", "L2")).upper()[:2])
        except ValueError:
            layer = AuditLayer.L2_SEMANTIC

        f = Finding(
            id=fid,
            title=str(raw["title"])[:300],
            severity=sev,
            confidence=float(raw.get("confidence", 0.7) or 0.7),
            location={"file": file, "line": line,
                      "end_line": int(raw.get("end_line") or line),
                      "function": str(raw.get("function", ""))},
            category=str(raw.get("category", "unknown")),
            cwe=raw.get("cwe"), owasp=raw.get("owasp"),
            evidence=ev,
            sources=[FindingSource.AGENT],
            dedup_key=Finding.make_dedup_key(file, line, str(raw.get("category", "unknown"))),
            exploitability=exp,
            coverage_class=cc,
            audit_layer=layer,
            recorded_at_turn=turn,
            remediation=_remediation(raw.get("remediation")),
        )
        return (True, "", f)

    # -------------------------------------------------- 覆盖度

    def set_coverage(self, class_id: str, status: str, note: str,
                     evidence_refs: list[str] | None = None,
                     turn: int = 0) -> tuple[bool, str]:
        """设置 C 类覆盖状态。**终态强制**（06 §2.3）。"""
        e = self.coverage.get(class_id)
        if e is None:
            return (False, f"未知的覆盖类 {class_id!r}。"
                           f"可选：{list(self.coverage.keys())}")
        try:
            st = CoverageStatus(status)
        except ValueError:
            return (False, f"status 必须是 "
                           f"{[s.value for s in CoverageStatus]} 之一，收到 {status!r}")

        if not (note or "").strip():
            return (False, f"设置 {class_id} 必须给出 note")

        # ★ no_issue 必须有审查证据，否则强制降级为 unverified
        refs = list(evidence_refs or [])
        if st == CoverageStatus.NO_ISSUE and not refs:
            st = CoverageStatus.UNVERIFIED
            note = (note + "｜（未给出审查证据，按契约强制降级为 unverified："
                           "声明「审过没问题」必须能指出审了哪里）")
        if st == CoverageStatus.SKIPPED and not note.strip():
            return (False, "skipped 必须给出放弃理由")

        e.status = st
        e.note = note[:800]
        e.evidence_refs = refs[:20]
        if turn:
            e.evidence_turns.append(turn)
        self.log("coverage_set", cls=class_id, status=st.value, turn=turn)
        return (True, f"{class_id} → {st.value}")

    def pending_coverage(self) -> list[CoverageEntry]:
        """尚未落终态的 C 类。"""
        return [e for e in self.coverage.values()
                if e.status == CoverageStatus.UNVERIFIED]

    # -------------------------------------------------- 审查轨迹

    def note_reviewed(self, rel: str, start: int, end: int) -> bool:
        """记一次代码阅读。返回 True 表示这段之前没读过（新信息）。"""
        fi = self.scope.get(rel)
        if fi is not None:
            rel = fi.rel
        spans = self.reviewed.setdefault(rel, [])
        for (s, e) in spans:
            if start >= s and end <= e:
                return False           # 完全被已有区间覆盖 → 重复阅读
        spans.append((start, end))
        spans.sort()
        # 合并相邻区间，便于"该文件读过多少"的统计
        merged: list[tuple[int, int]] = []
        for (s, e) in spans:
            if merged and s <= merged[-1][1] + 3:
                merged[-1] = (merged[-1][0], max(merged[-1][1], e))
            else:
                merged.append((s, e))
        self.reviewed[rel] = merged
        return True

    def coverage_of_file(self, rel: str) -> float:
        """该文件被读过的行占比（0-1）。"""
        fi = self.scope.get(rel)
        if fi is None or fi.lines <= 0:
            return 0.0
        n = sum(e - s + 1 for (s, e) in self.reviewed.get(fi.rel, []))
        return min(1.0, n / fi.lines)

    # -------------------------------------------------- 摘要（喂回模型）

    def digest(self, max_findings: int = 12, max_cands: int = 10) -> str:
        """确定性状态摘要。**每轮注入**——这是防止模型漂移的锚点。"""
        L: list[str] = []
        L.append(f"### 账本（第 {len(self.events)} 次记账）")

        # 覆盖度
        done = [e for e in self.coverage.values()
                if e.status != CoverageStatus.UNVERIFIED]
        L.append(f"**覆盖度 {len(done)}/7**：")
        for e in self.coverage.values():
            mark = {"covered": "✅", "no_issue": "✅", "skipped": "⏭️",
                    "out_of_scope": "➖", "unverified": "⬜"}[e.status.value]
            n = len(e.findings)
            tail = f"（{n} 条）" if n else (f" — {e.note[:40]}" if e.note else "")
            L.append(f"  {mark} {e.coverage_class}  {e.status.value}{tail}")

        # 已读过的文件——压缩之后，这一节是防止重复阅读的唯一依据。
        # 账本一直在记（每次 read_code 都会调 note_reviewed），但摘要此前不输出，
        # 模型就只能靠"我好像读过"来判断，而这在长上下文里必然退化成重读。
        # 带上行占比而不只是行数：只给行数，模型无法判断读全了没有，
        # 为了保险会再读一遍——压缩省下的上下文又原样花回去了。
        if self.reviewed:
            parts = []
            for rel in sorted(self.reviewed):
                n = sum(e - s + 1 for (s, e) in self.reviewed[rel])
                cov = self.coverage_of_file(rel)
                parts.append(f"{rel}({n}行/{cov:.0%})" if cov else f"{rel}({n}行)")
            L.append(f"**已读过 {len(self.reviewed)} 个文件**"
                     f"（未列出的或占比不足的才需要读）：")
            L.append("  " + "、".join(parts[:50])
                     + (f"　…另有 {len(parts) - 50} 个" if len(parts) > 50 else ""))

        # findings
        active = [f for f in self.findings.values() if f.is_active]
        vend = [f for f in self.findings.values()
                if f.attribution != Attribution.PROJECT]
        L.append(f"**已记录问题 {len(self.findings)} 条**"
                 f"（有效 {len(active)}"
                 + (f"，非项目归因 {len(vend)}" if vend else "") + "）：")
        if not self.findings:
            L.append("  （无）")
        for f in list(self.findings.values())[-max_findings:]:
            tag = " ⚠️未验证" if f.verification.verdict == Verdict.UNVERIFIED \
                and f.severity.rank >= Severity.HIGH.rank else ""
            attr = "" if f.attribution == Attribution.PROJECT else f" [{f.attribution.value}]"
            L.append(f"  · {f.id} [{f.severity.value}/{f.exploitability.value}]"
                     f"{attr}{tag} {f.location['file']}:{f.location['line']} {f.title[:44]}")

        # 收敛对账线索——单独一节、放在引擎候选之前。它们条数少（默认至多 6 条）
        # 但每条都直指一处"你说过却没记"的位置，是最容易被忽略也最该被处置的。
        # 截图到 120 字而不是 52：这条消息本身就是要模型读的内容，
        # 裁短了它就得再去 list_candidates 捞一次，反而更贵。
        rec = [c for c in self.open_candidates if c.source == "recall"]
        if rec:
            L.append(f"**⏳ 收敛对账线索 {len(rec)} 条待处置**"
                     f"（你在推理里提过、账本里没记的位置）：")
            for c in rec:
                L.append(f"  · {c.id} {c.file}:{c.line} — {c.message[:120]}")
            if len(rec) >= 3:
                L.append("  ↳ 线索占着名额：处置掉一条（confirmed/dismissed/deferred "
                         "加理由，三者都算）就腾出一个给下一个位置。压着不动，"
                         "后面提到的位置就进不来。")

        # 候选
        op = [c for c in self.open_candidates if c.source != "recall"]
        eng = [c for c in self.candidates.values() if c.source != "recall"]
        if eng:
            L.append(f"**引擎候选 {len(op)}/{len(eng)} 待处置**：")
            for c in op[:max_cands]:
                L.append(f"  · {c.id} [{c.source}/{c.severity}] "
                         f"{c.file}:{c.line} {c.rule} — {c.message[:52]}")
            if len(op) > max_cands:
                L.append(f"  · …另有 {len(op) - max_cands} 条")
            # ★ 积压提示只在真的积压时出现。它要同时挡住两种相反的失败：
            #   · 把处置攒到收口——real-quota 实测：模型打算在最后一轮一次发
            #     45 个处置调用，输出撞上长度上限被截断，**一条都没发出去**，
            #     召回从 80% 掉到 40%；
            #   · 反过来，看到"34 条待处置"就抢在审代码之前全判掉。
            # 所以「成组做」和「审到那处再做」必须写在同一句里——少了后半句，
            # 这个提示会亲手制造一批没有依据的驳回，比积压更糟。
            if len(op) >= 5:
                L.append("  ↳ 数量多，**审到那处代码时**顺手用 dispose_candidates "
                         "成组处置（同一类判据的放一组，理由写一次）——别攒到最后："
                         "收口前几十条挤在一起发会撑爆输出，实测过一次，"
                         "45 个调用被截断，一条都没发出去。")

        return "\n".join(L)

    def blockers(self, min_severity_verify: float = 0.0) -> list[str]:
        """阻止收敛的硬性缺口（06 §5.6 nudge 的依据）。"""
        out: list[str] = []
        pend = self.pending_coverage()
        if pend:
            out.append("覆盖度未完成：" + "、".join(e.coverage_class for e in pend)
                       + " 仍是 unverified。每个 C 类都必须落到"
                         " covered / no_issue / skipped / out_of_scope 之一；"
                         "声明 no_issue 时必须给出证据引用（审了哪个文件哪几行）。")
        # 引擎候选与对账线索分开说。前者是静态引擎报的、模型从没表态过的命中；
        # 后者是**模型自己说过、账本里却没有**的位置。两件事的处置动作一样，
        # 但需要被提醒的**理由**完全不同——混在一条里，后者会被当成噪音跳过。
        op = [c for c in self.open_candidates if c.source != "recall"]
        if op:
            ids = "、".join(c.id for c in op[:8])
            out.append(f"{len(op)} 个引擎候选未处置（{ids}…）。"
                       "每个候选必须处置到 confirmed / dismissed / deferred 并给出理由"
                       "——无理由关闭等同静默忽略。数量多就用 dispose_candidates 成组做："
                       "同一类判据的候选放一组，理由写一次。")

        rec = [c for c in self.open_candidates if c.source == "recall"]
        if rec:
            ids = "、".join(c.id for c in rec)
            out.append(
                f"{len(rec)} 条收敛对账线索未处置（{ids}）。"
                "这些**不是引擎报的**，是你在推理里提过、而账本里没有记录的位置——"
                "要么当时忘了记，要么判断过不报但没留下理由。"
                "用 list_candidates(source=\"recall\", group_by=\"file\") 看详情，"
                "再用 dispose_candidates 成组处置："
                "确实成立 → 先 record_finding 再 dispose_candidate(confirmed, finding_id=…)；"
                "判断过不成立 → dismissed 并写明为什么；"
                "本次来不及看 → deferred。**不处置不能收口。**")

        # ★ 覆盖度自洽性：covered 的含义是「审了并发现问题」。
        # 若某类标为 covered 却没有任何关联 finding，就是自相矛盾——
        # 报告上会出现「C4 凭据配置：covered」但正文一条凭据问题都没有，
        # 读者只能怀疑整份报告。必须在收口前纠正（记问题，或改标 no_issue）。
        inconsistent = [e for e in self.coverage.values()
                        if e.status == CoverageStatus.COVERED and not e.findings]
        if inconsistent:
            out.append(
                f"{len(inconsistent)} 个覆盖类标为 covered 但没有关联任何 finding"
                f"（{'、'.join(e.coverage_class for e in inconsistent)}）。"
                f"covered 表示「审了且发现问题」——请用 record_finding 记录对应问题"
                f"（它会自动关联），或把该类的状态改为 no_issue。")

        need = {s for s in self.cfg.agent.require_adversarial_for}
        unver = [f for f in self.findings.values()
                 if f.severity.value in need
                 and f.attribution == Attribution.PROJECT
                 and f.verification.verdict == Verdict.UNVERIFIED]
        if unver:
            out.append(f"{len(unver)} 条 HIGH/CRITICAL 未经对抗验证"
                       f"（{'、'.join(f.id for f in unver[:6])}）。"
                       "对每条调用 adversarial_verify；验证者会主动尝试证伪。")
        return out

    @property
    def can_conclude(self) -> bool:
        return not self.blockers()

    # -------------------------------------------------- 序列化

    def to_dict(self) -> dict:
        return {
            "findings": [f.to_dict() for f in self.findings.values()],
            "coverage": [e.to_dict() for e in self.coverage.values()],
            # ★ `message` 与 `snippet` 必须落盘。它们是候选的**理由**——
            # 报告读者看到"`app/admin/views.py:1` 未处置"时，唯一能告诉他
            # 这条为什么被提出来的就是 message（"第 23 轮的推理里提到过这里
            # （「越权」），账本里没有对应记录"）。少了它，线索退化成一个
            # 没有上下文的位置，复核者得从零猜它想说什么。
            # 落盘缺口是实测发现的：`_check_reports.py` 读 `c['message']` 直接 KeyError。
            # 账本是"唯一的真相来源"（06 §5.7），真相里不能缺理由。
            "candidates": [
                {"id": c.id, "source": c.source, "rule": c.rule, "file": c.file,
                 "line": c.line, "severity": c.severity, "status": c.status,
                 "message": c.message, "snippet": c.snippet,
                 "reason": c.reason, "finding_id": c.finding_id}
                for c in self.candidates.values()
            ],
            "reviewed": {k: v for k, v in self.reviewed.items()},
            "conclusion": self.conclusion,
            "events": self.events,
        }

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), ensure_ascii=False, indent=2,
                                   default=str), encoding="utf-8")


# ---------------------------------------------------------------- 辅助

_CLASS_HINTS = [
    (("sql", "command", "injection", "xss", "ssti", "xxe", "ldap", "nosql",
      "code_injection", "os_command", "template"), CoverageClass.C1_INJECTION),
    (("pickle", "deserial", "yaml", "marshal", "unserialize", "xxe_entity"),
     CoverageClass.C2_DESERIALIZATION),
    (("auth", "authz", "permission", "access", "idor", "csrf", "session",
      "privilege", "missing_authorization"), CoverageClass.C3_AUTHZ),
    (("secret", "credential", "password", "api_key", "hardcoded", "debug",
      "config", "token", "key"), CoverageClass.C4_CREDENTIALS),
    (("path", "traversal", "file", "upload", "download", "zip", "symlink"),
     CoverageClass.C5_FILE_PATH),
    (("dependency", "supply", "cve", "outdated", "package", "requirement"),
     CoverageClass.C6_SUPPLY_CHAIN),
    (("ai", "llm", "prompt", "hallucinat", "copilot", "generated",
      "vibe", "agent"), CoverageClass.C7_AI_CODE),
]


def _guess_class(category: str) -> CoverageClass | None:
    c = (category or "").lower()
    if not c or c == "unknown":
        return None
    for keys, cls in _CLASS_HINTS:
        if any(k in c for k in keys):
            return cls
    return None


def _remediation(raw) -> "Remediation":
    from ..schema import Remediation
    if isinstance(raw, dict):
        return Remediation(
            summary=str(raw.get("summary", "")),
            patch_hint=raw.get("patch_hint"),
            references=list(raw.get("references") or []),
        )
    if isinstance(raw, str):
        return Remediation(summary=raw)
    return Remediation()
