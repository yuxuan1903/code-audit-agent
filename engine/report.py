# -*- coding: utf-8 -*-
"""报告生成（任务 1.17）。

**这份报告必须回答的问题不是"发现了什么"，而是"这份结论有多可信"。**

AI 生成的审计报告有一个特有的失败形态：它读起来无懈可击——结构完整、
措辞专业、每条都有证据——但读者无法判断**它没看什么**。
一份声称"未发现命令注入"的报告，如果不说清楚它其实有 9 个文件
静态引擎完全没解析，那就是在误导。

因此本报告把「覆盖度与局限性」放在正文靠前的位置，而不是塞进附录：
  · 七类风险各自的终态与依据
  · 哪些文件静态引擎完全没覆盖（以及为什么）
  · 哪些入口未逐条核验
  · 哪些结论需要人工确认才能定案
  · 哪些候选被驳回、驳回理由是什么

**没有"零问题"这种表述。** 只有"在如下范围内、用如下方法、未发现如下类别的问题"。
"""
from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path

from .schema import (Attribution, CoverageClass, CoverageStatus,
                     Exploitability, Severity, Verdict)
from .util import build_fingerprint

_SEV_ICON = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡",
             "LOW": "🔵", "INFO": "⚪"}
_STATUS_ICON = {"covered": "✅", "no_issue": "✅", "skipped": "⏭️",
                "out_of_scope": "➖", "unverified": "⬜"}
_VERDICT_TXT = {
    Verdict.CONFIRMED: "已对抗验证确认",
    Verdict.FALSE_POSITIVE: "**对抗验证判定为误报**",
    Verdict.PARTIAL: "成立但影响被削弱",
    Verdict.NEEDS_HUMAN: "**需人工确认**",
    Verdict.UNVERIFIED: "未经对抗验证",
}


# ---------------------------------------------------------------- Markdown

def render_markdown(scope, ledger, agent_result=None, engines=None,
                    cfg=None, meta: dict | None = None) -> str:
    meta = dict(meta or {})
    # ★ 构建指纹在这里兜底，而不是只在 write_reports 里设。
    # 曾经只写在 write_reports，于是任何**直接调用渲染器**的路径
    # （测试、二次加工、别的入口）产出的报告都缺 7.7 节——而且是**静默**缺，
    # 读者无从分辨"这次运行没有指纹"和"这一节被漏掉了"。
    # 指纹的全部意义就是"能核"，核不了就等于没写。
    if cfg is not None:
        meta.setdefault("build", _build_meta(cfg))
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    repo = Path(scope.repo).name

    L: list[str] = []
    A = L.append

    A(f"# 代码安全审计报告：{repo}")
    A("")
    A(f"- **生成时间**：{now}")
    A(f"- **审计对象**：`{scope.repo}`")
    A(f"- **审计方式**：静态分析（不执行被审代码）；"
      f"静态引擎 + LLM Agent 数据流推理 + 独立对抗验证")
    if agent_result is not None:
        A(f"- **Agent 运行**：{agent_result.turns} 轮 / "
          f"{agent_result.tokens:,} tokens / {agent_result.seconds:.0f}s"
          f"（状态：{agent_result.status}）")
    A("")

    _exec_summary(A, scope, ledger, agent_result)
    _coverage_and_limits(A, scope, ledger, engines, agent_result)
    _findings(A, ledger)
    _candidates(A, ledger)
    _entry_points(A, scope)
    _attribution(A, scope)
    _appendix(A, scope, ledger, engines, meta, agent_result)

    return "\n".join(L)


def _exec_summary(A, scope, ledger, agent_result) -> None:
    findings = list(ledger.findings.values())
    active = [f for f in findings if f.is_active]
    by_sev: dict[str, int] = {}
    for f in active:
        by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1

    A("## 一、执行摘要")
    A("")
    covered = [e for e in ledger.coverage.values()
               if e.status in (CoverageStatus.COVERED, CoverageStatus.NO_ISSUE)]
    A(f"在 {len(scope.in_scope)} 个在审文件中，**七类风险中的 "
      f"{len(covered)} 类完成了实质审查**，记录有效问题 "
      f"**{len(active)}** 条"
      + ("：" if by_sev else "。"))
    if by_sev:
        A("")
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            if sev in by_sev:
                A(f"- {_SEV_ICON[sev]} **{sev}**：{by_sev[sev]} 条")

    # 结论可信度声明——放在摘要里，不藏到附录
    unresolved = [e for e in ledger.coverage.values()
                  if e.status in (CoverageStatus.SKIPPED,
                                  CoverageStatus.UNVERIFIED)]
    noa = [f for f in active if f.verification.verdict == Verdict.NEEDS_HUMAN]
    fp = [f for f in findings if f.verification.verdict == Verdict.FALSE_POSITIVE]
    A("")
    notes = []
    if unresolved:
        notes.append(f"{len(unresolved)} 类风险未完成实质审查"
                     f"（{'、'.join(e.coverage_class for e in unresolved)}）")
    if noa:
        notes.append(f"{len(noa)} 条结论需要人工确认才能定案")
    if fp:
        notes.append(f"{len(fp)} 条 finding 被对抗验证判定为误报（保留在报告末，"
                     f"不计入门禁）")
    if notes:
        A("> **结论可信度**：" + "；".join(notes) + "。详见第二节。")
    A("")


def _coverage_and_limits(A, scope, ledger, engines, agent_result) -> None:
    A("## 二、覆盖度与局限性")
    A("")
    A("本节说明**这份报告没有覆盖什么**。审计结论的可信度直接取决于此——"
      "一份不声明边界的报告，其结论无法被正确使用。")
    A("")

    # --- 七类覆盖矩阵
    A("### 2.1 七类风险覆盖矩阵")
    A("")
    A("| 风险类 | 状态 | 发现 | 依据 |")
    A("|---|---|---|---|")
    for c in CoverageClass:
        e = ledger.coverage.get(c.value)
        if e is None:
            continue
        mark = _STATUS_ICON.get(e.status.value, "?")
        n = len(e.findings)
        basis = e.note.replace("|", "\\|").replace("\n", " ")[:200] or "—"
        A(f"| {mark} {c.value} | {e.status.value} | {n if n else '—'} | {basis} |")
    A("")

    pend = ledger.pending_coverage()
    if pend:
        A(f"> ⚠️ **仍有 {len(pend)} 类未落到终态**"
          f"（{'、'.join(e.coverage_class for e in pend)}）："
          f"本次审计在预算内未能完成这些类别的审查，**不得据此报告认为它们没有问题**。")
        A("")

    # --- 静态引擎覆盖
    A("### 2.2 静态引擎覆盖与实际盲区")
    A("")
    if engines:
        for name, res in engines.items():
            if res is None:
                continue
            A(f"**{name}**：分析 {res.analyzed_files} 个文件，"
              f"命中 {len(res.hits)} 条。")
            if res.skipped_files:
                A("")
                A(f"⚠️ **{len(res.skipped_files)} 个文件完全未被该引擎分析**"
                  f"（{res.skipped_reason}）：")
                A("")
                for f in res.skipped_files[:30]:
                    fi = scope.get(f)
                    tag = ""
                    if fi is not None:
                        tag = f" — {fi.attribution}" if fi.attribution != "project" else ""
                    A(f"- `{f}`{tag}")
                if len(res.skipped_files) > 30:
                    A(f"- …另有 {len(res.skipped_files) - 30} 个")
            A("")

        # ★ 凭据扫描的解释方式与其他引擎**根本不同**，需要单独说明。
        # semgrep/bandit 报的是「这种写法有风险」，处置是改代码；
        # 凭据扫描报的是「这里躺着一个真的密钥」，处置是**轮换密钥**。
        # 只改代码不轮换，等于没改——密钥已经进过版本历史、进过构建产物、
        # 进过每一个克隆过仓库的人手里。
        sec = engines.get("secret")
        if sec is not None and sec.hits:
            A("**凭据扫描的特别说明**：下面命中的是**真实存在的凭据**，"
              "不是有风险的写法。因此处置方式是**轮换凭据**而不是修改代码——"
              "密钥一旦进入过版本历史，改掉当前文件并不能使它失效。"
              "本报告不包含任何凭据明文，清单见附录的「凭据清单」一节。")
            A("")
            A(f"本轮命中 **{len(sec.hits)}** 条凭据候选"
              f"（覆盖 {sec.analyzed_files} 个文件）。")
            A("")

    # 解析失败
    unparse = [r for r, f in scope.files.items() if not f.parse_ok and not f.trivial]
    if unparse:
        A(f"**解析失败的文件**（{len(unparse)} 个）：")
        A("")
        for r in unparse[:20]:
            A(f"- `{r}` — {scope.files[r].parse_error[:100]}")
        A("")

    # 未进入审计范围的
    A(f"**未纳入审计范围的目录/文件**（{len(scope.excluded)} 项）："
      "测试桩、生成物、依赖目录等。")
    A("")

    if agent_result is not None:
        A("### 2.3 Agent 运行状态")
        A("")
        if agent_result.status == "concluded":
            # ★ 措辞是「已**提交**验证」而非「已**通过**验证」——这两者差别很大。
            # 对抗验证的结论有三种：证实、证伪、以及**验证者自己也判不了**
            # （NEEDS_HUMAN）。把第三种归进"通过验证"，会让读者以为结论已被
            # 独立确认过；实际上它只是被独立地看过一遍，然后被退回给人工。
            # 实测靶子上三条最重要的 finding 全部落在第三种。
            A("Agent 通过收口检查：七类覆盖度均已落终态、全部引擎候选已处置、"
              "所有 HIGH/CRITICAL 已提交独立对抗验证。")
            A("")
            vc: dict[str, int] = {}
            for f in ledger.findings.values():
                k = f.verification.verdict.value
                vc[k] = vc.get(k, 0) + 1
            if vc.get("CONFIRMED"):
                A(f"- {vc['CONFIRMED']} 条经独立对抗验证**证实**")
            if vc.get("FALSE_POSITIVE"):
                A(f"- {vc['FALSE_POSITIVE']} 条经对抗验证**证伪**，已从问题清单移除")
            if vc.get("NEEDS_HUMAN"):
                A(f"- ⚠️ **{vc['NEEDS_HUMAN']} 条验证后结论为「静态无法定论、"
                  f"需人工复核」**——这**不等于**已验证通过，是验证者把判断"
                  f"退回给了人。这些条目在人工核验前不应作为决策依据。")
            unver_high = [f for f in ledger.findings.values()
                          if f.is_active
                          and f.severity.rank >= Severity.HIGH.rank
                          and f.verification.verdict == Verdict.UNVERIFIED]
            if unver_high:
                A(f"- ⚠️ **{len(unver_high)} 条 HIGH 及以上未做对抗验证**"
                  f"（{'、'.join(f.id for f in unver_high)}）")
        elif agent_result.status == "forced":
            A("> ⚠️ Agent **强制收口**，以下条件在收口时仍未闭合：")
            for b in (ledger.conclusion.get("blockers") or []):
                A(f"> - {b}")
        elif agent_result.status == "budget_exhausted":
            A("> ⚠️ **Agent 因预算耗尽而停止，未能完成收口判定。**"
              "本报告的覆盖度声明可能不完整，请以第二、四节的实际状态为准。")
        elif agent_result.status == "no_llm":
            A("> ⚠️ **本次审计未运行 LLM Agent**（未配置支持 tool calling 的模型），"
              "报告内容**仅来自静态引擎**，不含数据流推理与可达性判断。"
              "误报率会显著高于正常运行模式。")
        elif agent_result.status == "error":
            A(f"> ❌ Agent 运行中断：{agent_result.error}")
        A("")
        if agent_result.compaction_count:
            A(f"- 上下文压缩 {agent_result.compaction_count} 次（压缩后以账本为准，"
              f"不影响结论的确定性）")
        if agent_result.truncation_retries:
            A(f"- 输出截断续写 {agent_result.truncation_retries} 次")
        # ★ 这一行是缺陷 #31 的可观测化。此前截断只在"什么都没发出来"时
        # 才被记账，而真正的截断形态（一轮发很多调用）永远有调用、永远不
        # 落账——于是它藏了十次运行，只在工具统计里留下一串被误读成
        # "模型写错参数"的 `bad_args`。
        if getattr(agent_result, "truncation_partial", 0):
            A(f"- 输出被截断 {agent_result.truncation_partial} 轮"
              f"（每轮仍有完整调用被执行），因此跳过残骸 "
              f"{agent_result.remnants_skipped} 个——"
              f"这些调用**没有执行**，是模型下一轮需要重发的部分")
        A("")

    # 方法学上的固有局限
    A("### 2.4 方法学固有局限")
    A("")
    A("- **静态分析不执行代码**，因此无法发现：运行期才构造的调用、"
      "依赖具体部署配置的行为、时序与竞态问题。")
    A("- **动态派发无法完全解析**：`getattr` 调用、Django 字符串视图引用、"
      "框架信号回调等，调用图中不可见。本报告已尽力通过入口提取与字符串搜索补充，"
      "但不保证完整。")
    A("- **认证/授权状态由静态推断**：报告中标注的鉴权状态来自装饰器与函数体检查，"
      "实际生效的鉴权还取决于网关、反向代理与部署配置——这部分**不在代码范围内**，"
      "相关结论已标注为需人工确认。")
    A("- **依赖组件的已知漏洞**需要 CVE 数据库比对，本轮覆盖情况见 2.1 的 C6 行。")
    A("")


def _findings(A, ledger) -> None:
    A("## 三、发现的问题")
    A("")
    # ★ 这句无条件前置。它曾经只写在「本次没有任何发现」的分支里——那是
    # 说反了：报告为空时读者本来就会警惕，真正容易让人松懈的恰恰是
    # 「列了几条问题、于是以为审完了」。问题清单是**第二节覆盖范围内**的
    # 清单，不是这个代码库的问题全集。
    A("> 本节列出的是**在第二节所述覆盖范围内**发现的问题。"
      "**这不等于**已经审完——某个类别没出现在这里，可能是「审了、没有」，"
      "也可能是「根本没审」，两者的区分见 2.1 节。")
    A("")
    findings = [f for f in ledger.findings.values()
                if f.verification.verdict != Verdict.FALSE_POSITIVE]
    findings.sort(key=lambda f: (-f.severity.rank, f.location.get("file", "")))

    if not findings:
        A("本次审计在第二节所述范围内未记录有效问题。")
        A("")
        A("> 这不等于「没有问题」，只等于「在上述覆盖范围内未发现问题」。"
          "请结合第二节的盲区清单判断该结论的适用范围。")
        A("")
        return

    for f in findings:
        icon = _SEV_ICON.get(f.severity.value, "")
        A(f"### {icon} {f.id}：{f.title}")
        A("")
        loc = f.location
        A(f"| | |")
        A(f"|---|---|")
        A(f"| **位置** | `{loc.get('file')}:{loc.get('line')}`"
          + (f"（{loc.get('function')}）" if loc.get("function") else "") + " |")
        A(f"| **严重度** | {f.severity.value} |")
        A(f"| **可利用性** | {f.exploitability.value} |")
        A(f"| **类别** | {f.category} |")
        A(f"| **归因** | {f.attribution.value}"
          + ("（改造版第三方代码，缺陷归项目）"
             if f.attribution == Attribution.PROJECT and
             (ledger.scope.get(loc.get('file', '')) or _N).forked_from else "")
          + " |")
        A(f"| **推理层** | {f.audit_layer.value} |")
        if f.cwe:
            A(f"| **CWE** | {f.cwe} |")
        if f.coverage_class:
            A(f"| **覆盖类** | {f.coverage_class.value} |")
        if f.in_critical_path:
            A(f"| **关键路径** | ★ 是 |")
        A(f"| **验证** | {_VERDICT_TXT.get(f.verification.verdict, '—')} |")
        A("")

        ev = f.evidence
        A("**证据**")
        A("")
        if ev.sink:
            A(f"- **sink**：{ev.sink}")
        if ev.source:
            A(f"- **source**：{ev.source}")
        if ev.reachability:
            A(f"- **reachability**：{ev.reachability}")
        if ev.sanitizer_check:
            A(f"- **sanitizer_check**：{ev.sanitizer_check}")
        if ev.attack_path:
            A("")
            A("**攻击路径**")
            A("")
            for i, s in enumerate(ev.attack_path, 1):
                A(f"{i}. {s}")
        if ev.dataflow:
            A("")
            A(f"**数据流**：`{' → '.join(ev.dataflow)}`")
        if ev.mitigations_found:
            A("")
            A("**已存在的缓解措施**（影响严重度判定）")
            A("")
            for m in ev.mitigations_found:
                A(f"- {m}")
        if ev.snippet:
            A("")
            A("**源码快照**（左侧数字为行号，与上方位置对应）")
            A("")
            A("```python")
            sn = ev.snippet.strip()
            # 上限按"能装下一条 24 行的带行号快照"取，避免把快照从中间切断——
            # 被截断的快照会让读者以为漏洞行之后就没有代码了。
            A(sn[:2400] + ("\n# …（快照过长，已截断）" if len(sn) > 2400 else ""))
            A("```")

        if f.verification.reasoning or f.verification.rebuttal:
            A("")
            A("**对抗验证记录**")
            A("")
            A(f"- 结论：{_VERDICT_TXT.get(f.verification.verdict, '—')}")
            if f.verification.reasoning:
                A(f"- 验证者推理：{f.verification.reasoning[:700]}")
            if f.verification.rebuttal:
                A(f"- 反驳：{f.verification.rebuttal[:500]}")
            if f.verification.sanitizers_checked:
                A(f"- 验证者实际检查过的净化措施：")
                for s in f.verification.sanitizers_checked[:6]:
                    A(f"  - {s[:200]}")
            if f.verification.verifier_context_hash:
                A(f"- 独立上下文指纹：`{f.verification.verifier_context_hash}`")

        if f.remediation.summary or f.remediation.patch_hint:
            A("")
            A("**修复建议**")
            A("")
            if f.remediation.summary:
                A(f.remediation.summary)
            if f.remediation.patch_hint:
                A("")
                A(f"```\n{f.remediation.patch_hint}\n```")
        A("")
        A("---")
        A("")

    # 误报区
    fps = [f for f in ledger.findings.values()
           if f.verification.verdict == Verdict.FALSE_POSITIVE]
    if fps:
        A("### 经对抗验证驳回的问题（不计入门禁）")
        A("")
        A("以下条目曾被提出，但被独立验证者推翻。**保留在此以便复核**——"
          "若你不同意驳回理由，请重新评估。")
        A("")
        for f in fps:
            A(f"- ~~{f.id}：{f.title}~~ — `{f.location.get('file')}:"
              f"{f.location.get('line')}`")
            A(f"  - 驳回理由：{f.verification.rebuttal or f.verification.reasoning}")
        A("")


def _candidates(A, ledger) -> None:
    A("## 四、候选处置台账")
    A("")
    A("两条来源的候选都必须有处置结论。**保留驳回理由**是本节的重点——"
      "驳回一个真实的漏洞与忽略它是两回事，理由让后者可以被复核。")
    A("")

    eng = [c for c in ledger.candidates.values() if c.source != "recall"]
    rec = [c for c in ledger.candidates.values() if c.source == "recall"]

    # ---- 4.1 静态引擎候选
    A("### 4.1 静态引擎候选")
    A("")
    if not eng:
        A("本次运行未产生引擎候选。")
        A("")
    else:
        _cand_table(A, eng)
        A("")

    # ---- 4.2 收敛对账线索
    # ★ 这一节是 06 §5.8 的产物，也是本报告里最该被仔细读的一节。
    # 它记的不是「引擎报了什么」，而是「**模型自己说过什么、却没写进账本**」。
    # 验收报告 §4 的结论是：实测漏报没有一条来自「读不懂代码」，
    # 全都来自「看见了、说出来了、没落账」——所以这些线索的处置理由，
    # 是判断本次审计有没有漏报的第一手材料。
    A("### 4.2 收敛对账线索")
    A("")
    A("收口前，引擎把**推理轨迹里提过、账本里却没有记录**的位置逐条提出来，"
      "要求模型逐条处置。它找的不是「引擎报的疑似漏洞」，而是"
      "「你说过这里、却没有留下任何结论」——实测漏报最主要的形态。")
    A("")
    if not rec:
        A("本次运行未产生对账线索（没有出现「提过但没记」的位置，"
          "或对账扫描未触发）。")
        A("")
    else:
        _cand_table(A, rec, cols=("线索类型", lambda c: {
            "mention": "提及对账", "file": "文件回访"}.get(c.rule, c.rule)))
        A("")


def _cand_table(A, cands: list, cols: tuple[str, object] | None = None) -> None:
    """候选处置表。`cols` 给第二列的列名与取值函数，默认用引擎名与规则名。"""
    counts: dict[str, int] = {}
    for c in cands:
        counts[c.status] = counts.get(c.status, 0) + 1
    A(f"共 {len(cands)} 条：" + "、".join(f"{k} {v}" for k, v in sorted(counts.items())))
    A("")
    head, val = cols if cols else ("引擎", lambda c: f"{c.source}")
    A(f"| 候选 | {head} | 规则 | 位置 | 严重度 | 处置 | 理由 |")
    A("|---|---|---|---|---|---|---|")
    for c in cands:
        reason = (c.reason or "—").replace("|", "\\|").replace("\n", " ")[:160]
        mark = {"open": "⬜**未处置**", "confirmed": "✅确认",
                "dismissed": "❌驳回", "deferred": "⏭️延后"}.get(c.status, c.status)
        A(f"| {c.id} | {val(c)} | {c.rule} | `{c.file}:{c.line}` | "
          f"{c.severity} | {mark} | {reason} |")
    A("")

    undecided = [c for c in cands if c.is_open]
    if undecided:
        ids = "、".join(c.id for c in undecided[:12])
        if any(c.source == "recall" for c in cands):
            A(f"> ⚠️ **{len(undecided)} 条对账线索未处置**（{ids}）。"
              f"这些位置**模型在推理里提过却没落账**，收口时也没能处置——"
              f"它们既不是已确认的漏洞，也不是已排除的误报，"
              f"是**本次审计留下的未复核线索**，建议人工优先复核这几处。")
        else:
            A(f"> ⚠️ **{len(undecided)} 条候选未处置**（{ids}）。"
              f"这些是静态引擎报出的、**未经任何判断**的命中，"
              f"既不能视为漏洞也不能视为误报。")
        A("")


def _entry_points(A, scope) -> None:
    A("## 五、外部入口与鉴权状态")
    A("")
    eps = list(getattr(scope, "entry_points", []) or [])
    if not eps:
        A("未提取到外部入口（可能使用了本工具未支持的框架，"
          "**此时可达性判断缺乏依据，请谨慎对待所有需要外部入口才能成立的结论**）。")
        A("")
        return

    na = [e for e in eps if e.auth == "none"]
    nz = [e for e in eps if e.auth == "required" and e.authz == "none"]
    A(f"共 {len(eps)} 个外部入口：**{len(na)} 个无认证**，"
      f"**{len(nz)} 个有认证但未见对象级授权**。")
    A("")
    A("> **认证与授权是两件事**：认证回答「你是谁」，授权回答「你能动谁」。"
      "「有认证、未见对象级授权」是**待核验线索**而非结论——"
      "读全局列表类的操作本就不需要对象级校验，而删除他人资源的需要。")
    A("")

    if na:
        A("### 5.1 无认证入口")
        A("")
        A("| 类型 | 位置 | 目标 | 说明 |")
        A("|---|---|---|---|")
        for e in na[:60]:
            A(f"| {e.kind} | `{e.file}:{e.line}` | `{e.target}` | "
              f"{e.note.replace('|', '\\|')[:90]} |")
        if len(na) > 60:
            A(f"| … | | 另有 {len(na) - 60} 个 | |")
        A("")

    if nz:
        A("### 5.2 有认证、未见对象级授权的入口")
        A("")
        A("| 类型 | 位置 | 目标 | 认证依据 |")
        A("|---|---|---|---|")
        for e in nz[:60]:
            A(f"| {e.kind} | `{e.file}:{e.line}` | `{e.target}` | "
              f"{e.auth_evidence[:80]} |")
        A("")


def _attribution(A, scope) -> None:
    A("## 六、代码归因")
    A("")
    A("**归因决定了缺陷算谁的。** 原样拷贝的第三方库不计入项目漏洞"
      "（但需要安排升级）；被项目改造过的 fork 则**计入项目**。")
    A("")
    by_attr: dict[str, list] = {}
    for fi in scope.files.values():
        by_attr.setdefault(fi.attribution, []).append(fi)

    A("| 归因 | 文件数 | 说明 |")
    A("|---|---|---|")
    A(f"| project | {len(by_attr.get('project', []))} | 项目自有代码 |")
    A(f"| vendored | {len(by_attr.get('vendored', []))} | 原样引入的第三方库 |")
    A(f"| suspected | {len(by_attr.get('suspected', []))} | 归因待人工裁决 |")
    A("")

    forked = [f for f in scope.files.values() if f.forked_from]
    if forked:
        A(f"### 6.1 改造版第三方代码（{len(forked)} 个）——**缺陷归项目**")
        A("")
        A("| 文件 | 源自 | 判定依据 |")
        A("|---|---|---|")
        for fi in forked:
            reasons = "；".join(fi.attribution_reasons)[:180].replace("|", "\\|")
            A(f"| `{fi.rel}` | {fi.forked_from} | {reasons} |")
        A("")

    susp = by_attr.get("suspected", [])
    if susp:
        A(f"### 6.2 待裁决（{len(susp)} 个）")
        A("")
        for fi in susp:
            A(f"- `{fi.rel}` — {fi.library or '来源未知'}")
        A("")


def _transcript(A, ledger, agent_result, per_entry: int = 300,
                budget: int = 12_000) -> None:
    """渲染 Agent 的推理轨迹（7.4）。

    **为什么不能只写一句"完整轨迹见 JSON"**：报告的可复核性来自
    "读者能自己查"。一条 finding 说"这里有无鉴权的全表重写"，读者要能顺着
    轨迹看到 Agent 是在第几轮、读哪个文件时得出的这个判断。把轨迹藏进一个
    读者不会打开的 JSON，等于没有轨迹——更糟的是，曾经 7.4 节就是这么写的，
    而那个 JSON 里连 transcript 字段都没有：它指引读者去一个空地方。

    轨迹与 finding 的分工必须说清楚：finding 的 evidence 是**结论的证据**
    （代码位置、数据流，可核验）；轨迹是**结论的产生过程**（Agent 当时的
    措辞，未经核验）。后者不是事实来源，但它是发现"声称审过、实际没看"
    这类问题的唯一途径——本项目的漏报诊断正是靠它做的。
    """
    tr = list(getattr(agent_result, "transcript", None) or [])
    # 事件数为 0 时不能说"含每次工具调用与覆盖度依据"——那些东西根本不存在。
    # 引擎跑到一半的产物最容易出现这种话（本次 --engines-only 就是这样），
    # 而它读起来像一句有内容的说明。
    if ledger.events:
        A(f"账本记录事件 {len(ledger.events)} 条，含每次工具调用、每次账本变更"
          f"与完整的覆盖度依据（见同目录 ledger.json）。")
    else:
        A("本次**没有运行 Agent**，账本里没有事件——"
          "引擎候选记录在 `ledger.json` 的 `candidates` 中，未处置。")
    A("")
    if not tr:
        A("> 本次未留下推理轨迹：未启用 Agent，或模型未输出任何文本/思考块。")
        return
    n_think = sum(1 for e in tr if e.get("kind") == "thinking")
    A(f"Agent 推理轨迹 {len(tr)} 条（其中思考 {n_think} 条）。"
      "**轨迹是 Agent 当时的自述，不是核验过的事实**——可核验的是每条 "
      "finding 的 evidence 字段；保留轨迹是为了让「它何时说了什么」可被复核。")
    A("")
    used, shown, skipped = 0, 0, 0
    for e in tr:
        txt = re.sub(r"\s+", " ", (e.get("text") or "")).strip()
        if not txt:
            continue
        if used >= budget:
            skipped += 1
            continue
        kind = {"thinking": "思考", "assistant_text": "输出"}.get(
            e.get("kind"), e.get("kind") or "?")
        cut = len(txt) > per_entry
        A(f"- **第 {e.get('turn')} 轮**（{kind}）{txt[:per_entry]}"
          + ("…" if cut else ""))
        used += min(len(txt), per_entry)
        shown += 1
    if skipped:
        A("")
        A(f"> 另有 {skipped} 条未在此展开（篇幅所限）。完整文本见 "
          f"`audit-report.json` 的 `agent.transcript`。")


def _appendix(A, scope, ledger, engines, meta, agent_result=None) -> None:
    A("## 七、附录")
    A("")
    A("### 7.1 审计范围")
    A("")
    A(f"- 仓库文件总数：{len(scope.files)}")
    A(f"- 在审文件：{len(scope.in_scope)}（已排除归因明确为 vendored、"
      f"解析失败、无实质代码、以及 {len(scope.excluded)} 个排除项）")
    A("")

    A("### 7.2 引擎运行统计")
    A("")
    A("| 引擎 | 状态 | 命中 | 分析文件 | 跳过 |")
    A("|---|---|---|---|---|")
    for name, res in (engines or {}).items():
        if res is None:
            continue
        A(f"| {name} | {'✅' if res.ok else '❌'} | {len(res.hits)} | "
          f"{res.analyzed_files} | {len(res.skipped_files)} |")
    A("")

    if agent_result_tools := (meta.get("tool_stats") or {}):
        A("### 7.3 Agent 工具调用统计")
        A("")
        A("| 工具 | 调用次数 | 失败次数 |")
        A("|---|---|---|")
        calls = agent_result_tools.get("calls") or {}
        errs = agent_result_tools.get("errors") or {}
        for name in sorted(calls, key=lambda n: -calls[n]):
            A(f"| {name} | {calls[name]} | {errs.get(name, 0)} |")
        A(f"| **合计** | **{sum(calls.values())}** | **{sum(errs.values())}** |")
        A("")

    A("### 7.4 审计轨迹")
    A("")
    _transcript(A, ledger, agent_result)
    A("")
    # ★ 只要跑过 Agent，这一段就必须出现——**拿不到数也要出现**。
    # 这里原先是 `if meta.get("data_sent_external"):`，于是"没跑 Agent"和
    # "跑了但没量到"在报告里长得一模一样：都什么都不显示。对一份合规声明来说，
    # 沉默是最不能有的一种表达——读者会把"没写"读成"没有外发"。
    if agent_result is not None:
        A("### 7.5 数据外发声明")
        A("")
        eg = egress_figures(agent_result, meta)
        if eg["available"]:
            # ★ 括号**必须是分解式**。原写作「累计发送 1,387,834 tokens
            # （输入 269,626 / 输出 60,424）」，两项相加 330,050，与总数
            # 差 1,118,208——差额正是缓存读；而"输出"根本不参与这个总数。
            # 自校验结果随报告一起写出，读者不必自己验算。
            A(f"本次审计向外部 LLM 服务发送了代码内容用于分析。"
              f"**累计发送 {eg['tokens_sent_external']:,} tokens**，"
              f"= 输入 {eg['input_tokens']:,}"
              f" + 缓存读 {eg['cache_read_tokens']:,}"
              f" + 缓存写 {eg['cache_write_tokens']:,}。"
              f"（输出 {eg['output_tokens_not_counted']:,} tokens **不计入**："
              f"那是模型生成的内容，不是送出去的东西。）")
            if not eg["reconstructs"]:
                A("")
                A(f"> ⚠️ **本报告自校验未通过**：分项相加不等于总数，"
                  f"差 {eg['tokens_sent_external'] - eg['input_tokens'] - eg['cache_read_tokens'] - eg['cache_write_tokens']:,}。"
                  f"请以服务端计费用量为准，并把这次不一致当作工具缺陷上报。")
            A("")
            A("这个数字取自服务端回报的 usage"
              "（`input_tokens` + `cache_read_input_tokens` + "
              "`cache_creation_input_tokens`），而非本地估算。三点须说明：")
            A("")
            A("- **缓存读不等于「本轮又发了一遍」**。它指服务端在上一轮已经"
              "收到的前缀，本轮由服务端从缓存中读取、**没有经网络重新传输**。"
              "把它计入，是因为这些内容**此刻仍存在于对方服务端**——"
              "对一份数据外发声明来说，「还在不在那里」比「这一轮有没有再发」"
              "更要紧。")
            A("- **本地估算不能用作此数**：实测同一段文本，本地 `estimate()` "
              "报 4,474，服务端实际收到 3,405（**高估 31%**）。所以要报就报"
              "服务端回报的。")
            A("- 该端点**自动做前缀缓存**（本工具从不发送 `cache_control` "
              "断点），因此缓存读占比高是正常的，不表示外发量被重复计算。")
            A("")
            A("若被审代码含敏感信息，请确认已按组织的数据分级要求处理。")
        else:
            # 数值为 0 不等于"没有外发"：Agent 每轮都把提示词发出去过，
            # 只是服务端没有回报 usage。这两件事必须能被读者区分开。
            A("本次审计向外部 LLM 服务发送了代码内容用于分析。"
              "**但本次运行未能取得发送量：LLM 服务端没有回报 usage。**"
              f"（Agent 实际跑了 {eg.get('turns', 0)} 轮、"
              f"{eg.get('tool_calls', 0)} 次工具调用，代码确实是随工具结果"
              "一轮轮发出去的。）**请勿把这里的空缺读作「没有外发」。**"
              "需要准确数字时以服务端计费用量为准。")
        A("")

    # 凭据清单放在附录而不是正文：它是**证据**而不是结论——是否构成问题
    # 取决于该凭据的用途、有效期与暴露面，那需要人来判断。
    sec = (engines or {}).get("secret")
    if sec is not None and sec.hits:
        A("### 7.6 凭据清单（值已脱敏）")
        A("")
        A("> 本表**不含凭据明文**：只保留类型、长度、前 3 位与 SHA256 指纹。"
          "前 3 位用于人工确认凭据类型；指纹用于判断多处出现的是否为同一个值。"
          "需要原值请到源码对应位置查看——报告本身不是密钥的传播渠道。")
        A("")
        A("| 类型 | 位置 | 长度 | 指纹 | 预览 | 出现处 |")
        A("|---|---|---|---|---|---|")
        for h in sec.hits:
            extra = h.extra or {}
            r = extra.get("redaction") or {}
            occ = extra.get("occurrences") or []
            locs = "、".join(f"`{o.get('file')}:{o.get('line')}`" for o in occ[:4])
            if len(occ) > 4:
                locs += f" …另 {len(occ) - 4} 处"
            A(f"| `{r.get('kind', '?')}` | `{h.file}:{h.line}` "
              f"| {r.get('length', '')} | `{r.get('fingerprint', '')}` "
              f"| `{r.get('preview', '')}` | {locs or '—'} |")
        A("")
        A("**处置顺序**：先轮换凭据，再改代码。反过来做会让轮换失去紧迫感，"
          "而已经扩大的暴露面并不会因为代码改好了而缩小。")
        A("")

    _build_info(A, meta)

    A("---")
    A("")
    A(f"*本报告由 ai-audit 生成。报告中所有结论的覆盖范围以第二节为准；"
      f"标注为「需人工确认」的条目在人工核验前不应作为决策依据。*")


class _N:
    forked_from = None


def _build_info(A, meta) -> None:
    """7.7 构建指纹。**两份报告能不能互相对照，靠的就是这一节。**"""
    b = (meta or {}).get("build") or {}
    A("### 7.7 构建指纹")
    A("")
    if not b:
        # ★ 拿不到指纹时**仍然出这一节**，明说拿不到。
        # 静默省略会让读者把"这一节不存在"读成"这次运行不需要指纹"，
        # 而实际上他正打算拿这份报告去和上次的对比。
        A("> ⚠️ **本次未能生成构建指纹**（渲染时没有拿到运行配置）。"
          "这意味着**无法确认这份报告与其它运行是否可比**——"
          "拿它去和别的报告对照时请自行确认代码与配置未变。")
        A("")
        return
    A("同一靶子上的两次运行，只有在**代码与配置都相同**时才谈得上对照。"
      "本节把这句话变成可核的：把两份报告的 `code_digest` 摆在一起比一下即可。"
      "**不同就是不具可比性**——任何「这次比上次好」的结论都不成立，"
      "因为改变的可能是工具本身，而不是模型的表现。")
    A("")
    A(f"- 代码指纹：`{b.get('code_digest', '?')}`"
      f"（`engine/` + `audit.py` 共 {b.get('code_files', '?')} 个文件）")
    cfg = b.get("config") or {}
    if cfg:
        A("- 配置快照：" + "、".join(f"`{k}={v}`" for k, v in cfg.items() if v is not None))
    A("")


# ---------------------------------------------------------------- 构建指纹

def _build_meta(cfg) -> dict:
    """当次运行的构建指纹 + 关键配置快照。

    配置项刻意只挑**会改变审计结果**的那些：预算、阈值、对账开关、引擎开关。
    把所有字段都塞进去，指纹就会因为一个无关的路径设置而变，反而失去可比性。
    """
    a = getattr(cfg, "agent", None)
    snapshot = {
        "agent_enabled": getattr(a, "enabled", None),
        "max_turns": getattr(a, "max_turns", None),
        "max_tokens": getattr(a, "max_tokens", None),
        "compact_at_ratio": getattr(a, "compact_at_ratio", None),
        "require_adversarial_for": getattr(a, "require_adversarial_for", None),
        "recall_enabled": getattr(a, "recall_enabled", None),
        "recall_after_ratio": getattr(a, "recall_after_ratio", None),
        "recall_max_mention": getattr(a, "recall_max_mention", None),
        "recall_max_file": getattr(a, "recall_max_file", None),
        "recall_max_total": getattr(a, "recall_max_total", None),
        "recall_max_mention_total": getattr(a, "recall_max_mention_total", None),
        "recall_max_file_total": getattr(a, "recall_max_file_total", None),
        "provider": getattr(getattr(cfg, "llm", None), "provider", None),
        "model": getattr(getattr(cfg, "llm", None), "model", None),
        # ★ `max_output_tokens` 决定"一轮能发多少个工具调用而不被砍断"，
        # 是缺陷 #31（截断残骸被误报成 `bad_args`）的直接根因，必须进快照。
        # 此前它不在快照里：两次运行即使一个用 4096、一个用 8192，指纹也相同，
        # 会被当成"同构建可比"——而它们的截断行为完全不同。
        "max_output_tokens": getattr(getattr(cfg, "llm", None),
                                     "max_output_tokens", None),
    }
    try:
        return build_fingerprint(snapshot)
    except OSError as e:                    # 源码不可读时不阻断出报告
        return {"code_digest": f"unavailable: {e}", "config": snapshot}


# ---------------------------------------------------------------- JSON

def build_json(scope, ledger, agent_result=None, engines=None, meta=None) -> dict:
    findings = [f.to_dict() for f in ledger.findings.values()]
    active = [f for f in ledger.findings.values() if f.is_active]
    return {
        "schema": "ai-audit/report/v1",
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "repo": str(scope.repo),
        "engine": {"name": "ai-audit", "version": meta.get("version", "0.1")
                   if meta else "0.1"},
        # 与 Markdown 7.7 同一份指纹。JSON 侧也要有，否则拿 JSON 做对比的
        # 工具链（CI、看板）就无从判断两份结果可不可比。
        "build": (meta or {}).get("build") or {},
        "summary": {
            "files_total": len(scope.files),
            "files_in_scope": len(scope.in_scope),
            "entry_points": len(getattr(scope, "entry_points", []) or []),
            "findings_total": len(findings),
            "findings_active": len(active),
            "by_severity": _count_by(active, lambda f: f.severity.value),
            "by_coverage_class": _count_by(
                [f for f in active if f.coverage_class],
                lambda f: f.coverage_class.value),
            "verdicts": _count_by(list(ledger.findings.values()),
                                  lambda f: f.verification.verdict.value),
        },
        "coverage": [e.to_dict() for e in ledger.coverage.values()],
        "coverage_complete": not ledger.pending_coverage(),
        "findings": findings,
        "candidates": ledger.to_dict()["candidates"],
        "candidates_open": len(ledger.open_candidates),
        "candidates_recall": len([c for c in ledger.candidates.values()
                                  if c.source == "recall"]),
        "candidates_recall_open": len([c for c in ledger.open_candidates
                                       if c.source == "recall"]),
        "attribution": _count_by(list(scope.files.values()),
                                 lambda f: f.attribution),
        "forked_files": [{"file": f.rel, "from": f.forked_from,
                          "reasons": f.attribution_reasons}
                         for f in scope.files.values() if f.forked_from],
        "engines": {
            name: {
                "ok": res.ok,
                "hits": len(res.hits),
                "analyzed_files": res.analyzed_files,
                "skipped_files": res.skipped_files,
                "skipped_reason": res.skipped_reason,
                "raw_counts": res.raw_counts,
                "error": res.error,
            } for name, res in (engines or {}).items() if res is not None
        },
        "agent": {
            "status": getattr(agent_result, "status", None),
            "turns": getattr(agent_result, "turns", 0),
            "tokens": getattr(agent_result, "tokens", 0),
            "input_tokens": getattr(agent_result, "input_tokens", 0),
            "output_tokens": getattr(agent_result, "output_tokens", 0),
            # ★ 缓存两项原先**没有序列化**。后果不是"少两个字段"这么轻：
            # 7.5 节报出的外发量（1,387,834）里有一百万来自缓存读，
            # 而 JSON——那份声称"完整轨迹见同目录 JSON"的产物——里
            # 既没有这两个分量，也没有总数。数字只在正文里，无从核验。
            # 这与 7.4 节 `transcript` 曾经缺失是同一类缺陷，见其注释。
            "cache_read_tokens": getattr(agent_result, "cache_read_tokens", 0),
            "cache_write_tokens": getattr(agent_result, "cache_write_tokens", 0),
            "seconds": round(getattr(agent_result, "seconds", 0.0), 1),
            "compaction_count": getattr(agent_result, "compaction_count", 0),
            # ★ 截断两个计数也必须进 JSON，理由同下面 `transcript`：正文里写了、
            # JSON 里没有，就等于机器侧无从核验——而"两次运行的截断行为是否
            # 相同"正是判断可比性时要问的问题（见缺陷 #31）。
            "truncation_retries": getattr(agent_result, "truncation_retries", 0),
            "truncation_partial": getattr(agent_result, "truncation_partial", 0),
            "remnants_skipped": getattr(agent_result, "remnants_skipped", 0),
            "conclusion": ledger.conclusion,
            "tool_stats": getattr(agent_result, "tool_stats", {}),
            # ★ 轨迹是审计的**可复核性**所在，必须真的落盘。
            # 曾经 7.4 节写着"完整轨迹见同目录的 JSON 报告"，而 JSON 里
            # 根本没有这个字段——那是比不写更糟的：它让读者以为能查到。
            "transcript": getattr(agent_result, "transcript", []),
            "error": getattr(agent_result, "error", ""),
        },
        # ★ 数据外发量（合规声明）必须进 JSON，与 7.5 节同源。
        # 原先它只存在于 `meta` 里，而 `meta` 从不写盘——于是"本次审计
        # 向外发了多少"这个最该被机器读到的数字，只在正文里有一份，
        # CI/看板拿不到，核对脚本也无从判它是否被改动。
        "data_egress": egress_figures(agent_result, meta),
        "gate": evaluate_gate(ledger, meta.get("gate_fail_on") if meta else None),
    }


def egress_figures(agent_result, meta: dict | None = None) -> dict:
    """★ 数据外发量的**唯一来源**：Markdown 7.5 与 JSON `data_egress` 都取这里。

    一份合规数字若在两处各算一遍，迟早会不一致——而这正是本报告 §5.3
    反复记下的同一类缺陷（统计口径错、低估 36 倍、拿不到就整节消失）。
    所以这里只算一次，两处引用同一份。

    ★ 分项与总数的自校验：`reconstructs` 直接记在产物里。
    起因是一次真实失守——7.5 原写作「累计发送 1,387,834 tokens
    （输入 269,626 / 输出 60,424）」，**括号里两项相加是 330,050，
    与总数差 1,118,208**（差额正是缓存读）。那个括号长得像分解式，
    却不是分解式：先放的是"输出"（它根本不计入外发），又漏了缓存。
    连跑七次没人发现，因为核对脚本当时只检查"不低报"。
    现在把这个判断写进产物本身，读者不必自己验算。
    """
    meta = meta or {}
    if agent_result is None:
        return {"available": False, "reason": "no_agent"}
    sent = int(meta.get("data_sent_external") or 0)
    if not sent:
        ts = getattr(agent_result, "tool_stats", {}) or {}
        return {"available": False, "reason": "no_usage",
                "turns": getattr(agent_result, "turns", 0),
                "tool_calls": ts.get("total_calls", 0)}
    ti = int(meta.get("tokens_in") or 0)
    to = int(meta.get("tokens_out") or 0)
    cr = int(getattr(agent_result, "cache_read_tokens", 0) or 0)
    cw = int(getattr(agent_result, "cache_write_tokens", 0) or 0)
    return {
        "available": True,
        "tokens_sent_external": sent,
        "input_tokens": ti,
        "cache_read_tokens": cr,
        "cache_write_tokens": cw,
        # 输出**不计入外发**：那是模型生成的内容，不是送出去的东西。
        # 记在这里是为了让 JSON 读者看得到它被排除，而不是以为漏了。
        "output_tokens_not_counted": to,
        "formula": "input + cache_read + cache_write",
        # Anthropic 语义前提：input 不含缓存，三者相加才是完整提示词。
        # 实测确认见 out/_probe_usage.py（未命中 3,405；命中 205+3,200）。
        "semantics": "anthropic",
        "reconstructs": ti + cr + cw == sent,
        "source": "server_usage",
    }


def _count_by(items, key) -> dict:
    out: dict[str, int] = {}
    for it in items:
        k = key(it)
        out[k] = out.get(k, 0) + 1
    return out


# ---------------------------------------------------------------- 门禁

_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def evaluate_gate(ledger, fail_on: str | None = None) -> dict:
    """CI 门禁判定（04 §4.2）。

    ★ 只看 **is_active** 的 finding：
    被对抗验证判为误报的、被 baseline 的、判定为不可利用的，都不拦门。
    ——这正是那套对抗验证机制存在的意义：它挡住了误报进入 CI，
    否则开发团队会在第三次被误报拦下之后关掉这个门禁。
    """
    fail_on = (fail_on or "high").upper()
    thr = _RANK.get(fail_on, 3)
    blocking = [f for f in ledger.findings.values()
                if f.is_active and f.severity.rank >= thr]
    return {
        "fail_on": fail_on,
        "blocking": len(blocking),
        "passed": not blocking,
        "blocking_ids": [f.id for f in blocking],
        "blocking_detail": [
            {"id": f.id, "severity": f.severity.value,
             "exploitability": f.exploitability.value,
             "file": f.location.get("file"), "line": f.location.get("line"),
             "title": f.title,
             "verified": f.verification.verdict.value}
            for f in sorted(blocking, key=lambda x: -x.severity.rank)
        ],
        "coverage_complete": not ledger.pending_coverage(),
        "note": ("门禁已通过" if not blocking else
                 f"{len(blocking)} 条达到或超过 {fail_on} 的已验证问题"),
    }


# ---------------------------------------------------------------- 落盘

def write_reports(cfg, scope, ledger, agent_result=None, engines=None,
                  meta: dict | None = None) -> dict[str, Path]:
    out = Path(cfg.resolved_out_dir())
    meta = dict(meta or {})
    if agent_result is not None:
        meta.setdefault("tool_stats", getattr(agent_result, "tool_stats", {}))
    meta.setdefault("gate_fail_on", cfg.gate.fail_on)
    # ★ 构建指纹（验收报告 §六-9）。写在报告里而不是另存一个文件：
    # 报告会被转发、被引用、被拿去对照，指纹必须跟着报告走。
    # 两次运行的报告摆在一起而指纹不同，读者立刻知道它们**不可比**——
    # 这句话以前只能靠人在正文里声明，而声明本身无法被核对。
    meta.setdefault("build", _build_meta(cfg))

    written: dict[str, Path] = {}
    formats = set(getattr(cfg.report, "formats", ["md", "json"]) or ["md", "json"])

    if "md" in formats:
        p = out / "audit-report.md"
        p.write_text(render_markdown(scope, ledger, agent_result, engines,
                                     cfg, meta), encoding="utf-8")
        written["md"] = p
    if "json" in formats:
        p = out / "audit-report.json"
        p.write_text(json.dumps(build_json(scope, ledger, agent_result, engines,
                                           meta),
                                ensure_ascii=False, indent=2, default=str),
                     encoding="utf-8")
        written["json"] = p

    # 账本原始数据单独落一份，便于复核与重放
    lp = out / "ledger.json"
    ledger.save(lp)
    written["ledger"] = lp
    return written
