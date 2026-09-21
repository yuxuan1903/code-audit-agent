# -*- coding: utf-8 -*-
"""对抗验证（06 §7）—— 独立验证者。

**为什么不能"让主 Agent 再检查一遍"**：同一段推理自己复核自己，只会强化原结论。
实测（06 §7 记录的偏差模式）：主 Agent 在记录了 finding 之后，被要求"确认一下"时
倾向于复述自己的证据，而不是去找反证。

因此验证者必须**独立**，具体体现在三处：
  1. **独立上下文**：只给 finding 的证据与相关代码，**不给**主 Agent 的推理过程、
     不给账本摘要、不给审计范围清单。它不知道主 Agent 想证明什么。
  2. **独立工具**：只给只读工具（读代码/搜代码/查调用/查归因），
     **拿不到任何写账本的工具**——它改变不了结论，只能报告。
  3. **强制净化枚举**：先枚举路径上所有可能的净化措施并逐条判断是否覆盖该数据流，
     **之后**才能下结论。顺序强制，用来对抗"看到 sink 就确认"的确认偏误。

验证者结论落到 Verdict：CONFIRMED / FALSE_POSITIVE / PARTIAL / NEEDS_HUMAN。
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from .registry import A, I, S, Tool, ToolRegistry, ToolResult, obj
from ..schema import Verdict


# ---------------------------------------------------------------- 提示词

_VERIFIER_SYSTEM = """\
你是安全审计的**独立验证者**。你的任务不是确认一个结论，而是**主动尝试证伪它**。

另一位审计员报告了一个疑似漏洞。你的职责是找出它为什么**不成立**：
可能是数据流被阻断、可能有你没被告知的净化措施、可能那条路径根本不可达、
可能报告者把框架语义理解错了。

工作方式：
1. 先用 read_code 读取报告者引用的代码位置，**自己看**，不要采信他的转述。
2. 用 find_callers 沿调用方向向上追溯，确认是否真有外部入口能到达这里。
3. **强制步骤**：用 search_code 与 read_code 枚举这条数据流路径上所有可能的净化措施
   ——参数化查询、转义/编码函数、白名单校验、类型强制、框架自带的转义（模板自动转义、
   ORM 的参数绑定）、权限装饰器。**逐条判断它是否覆盖该数据流**，并写进
   sanitizers_enumerated。哪怕你最后判定漏洞成立，也必须先列出你检查过什么。
4. 特别注意这些容易误报的形态：
   · `%` 或 `f-string` 拼接**但拼进去的是经过引用的标识符**（如 Django 的
     `qn()` / `quote_name`），而真正的用户输入走的是参数化占位符 → 不成立
   · 调用了危险函数，但参数是**常量**或来自服务端配置 → 不可控，不成立
   · 函数无鉴权装饰器，但调用它的上层入口有 → 不可达，不成立
   · 代码位于 vendored 依赖或被改造的 fork 中 → 归因影响是否计入项目
5. 判定：
   · CONFIRMED       —— 你尽力证伪但未能推翻，且路径可达、数据可控、无有效净化
   · FALSE_POSITIVE  —— 你找到了确凿的反证（给出反证）
   · PARTIAL         —— 漏洞成立但影响被削弱（如需要高权限前提、仅影响自己）
   · NEEDS_HUMAN     —— 代码之外的事实决定结论（如部署配置、网关是否鉴权），
                        静态无法判定。**不要为了给结论而猜**。

最后调用 submit_verdict 提交。rebuttal 里写你的证伪尝试及其结果——
如果你尝试了但失败了，就写"我尝试了 X、Y、Z 证伪，均未推翻"。\
"""

_VERDICT_TOOL = obj({
    "verdict": S("你的判定", enum=["CONFIRMED", "FALSE_POSITIVE",
                                   "PARTIAL", "NEEDS_HUMAN"]),
    "sanitizers_enumerated": A(
        "★强制：你实际检查过的净化措施，每条写明「措施 — 是否覆盖该数据流 — 依据」。"
        "即使判定漏洞成立也必须给出（可写「未发现任何净化措施」并说明搜索过程）。",
        items={"type": "string"}),
    "reasoning": S("你的推理过程，以及你为证伪做了哪些尝试、结果如何"),
    "rebuttal": S("若判定 FALSE_POSITIVE 或 PARTIAL，给出具体反证；否则留空"),
    "severity_adjustment": S("严重度是否需要调整", enum=["none", "up", "down"]),
    "adjusted_severity": S("adjustment 非 none 时给出新严重度",
                           enum=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]),
    "additional_evidence": A("你找到的、原报告未提及的关键代码事实",
                             items={"type": "string"}),
}, ["verdict", "sanitizers_enumerated", "reasoning"])


@dataclass
class VerificationOutcome:
    finding_id: str
    verdict: Verdict
    reasoning: str
    rebuttal: str
    sanitizers: list[str]
    context_hash: str
    turns_used: int
    tool_calls: int
    ok: bool = True
    error: str = ""


# ---------------------------------------------------------------- 提示构造

def build_verifier_prompt(finding, scope, index=None) -> str:
    """构造验证者看到的一切。**刻意不包含主 Agent 的推理链与账本摘要。**"""
    loc = finding.location
    ev = finding.evidence

    L = [
        "## 待验证的结论",
        f"**标题**：{finding.title}",
        f"**位置**：{loc.get('file')}:{loc.get('line')}"
        + (f"-{loc.get('end_line')}" if loc.get("end_line") else ""),
        f"**报告者声称的严重度**：{finding.severity.value}",
        f"**报告者声称的类别**：{finding.category}",
        "",
        "## 报告者给出的证据",
        f"**sink（危险操作）**：{ev.sink}",
        f"**source（污点来源）**：{ev.source}",
        f"**reachability（可达路径）**：{ev.reachability}",
        f"**sanitizer_check（报告者说净化不足的理由）**：{ev.sanitizer_check}",
    ]
    if ev.attack_path:
        L.append("**声称的攻击步骤**：")
        L.extend(f"  {i+1}. {s}" for i, s in enumerate(ev.attack_path))
    if ev.dataflow:
        L.append("**声称的数据流**：" + " → ".join(ev.dataflow))
    if ev.snippet:
        L.append("**代码片段**：")
        L.append("```")
        L.append(ev.snippet[:1800])
        L.append("```")

    L += [
        "",
        "## 你的任务",
        "以上是报告者的全部陈述。**它可能有错**——你的职责是独立核实，"
        "尤其是：那条路径真的从外部入口可达吗？数据真的可控吗？"
        "**真的没有净化措施吗？**",
        "先自己读代码，再回答。最后调用 submit_verdict。",
    ]

    # 归因事实必须告知——这是代码之外的关键前提
    fi = scope.get(loc.get("file", ""))
    if fi is not None:
        L.insert(4, f"**文件归因**：{fi.attribution}"
                    + (f"（改造版，源自 {fi.forked_from}）" if fi.forked_from else "")
                    + (f"（vendored: {fi.library}）" if fi.library else ""))
    return "\n".join(L)


def _context_hash(finding) -> str:
    """验证者上下文的指纹，用于报告里证明"验证是独立发生的"。"""
    raw = json.dumps({
        "id": finding.id, "title": finding.title,
        "loc": finding.location, "sev": finding.severity.value,
        "sink": finding.evidence.sink, "source": finding.evidence.source,
    }, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


# ---------------------------------------------------------------- 验证者循环

_READONLY_TOOLS = ("read_code", "search_code", "find_callers", "trace_calls",
                   "check_vendored", "find_symbol", "outline", "get_entry_points")


def verify_finding(ctx, finding, provider=None, max_turns: int = 8) -> VerificationOutcome:
    """跑一次对抗验证。

    验证者拿到一个**只读工具子集**与独立上下文，最多 `max_turns` 轮。
    它无法修改账本——只能通过 submit_verdict 报告结论。
    """
    provider = provider or ctx.provider
    chash = _context_hash(finding)
    if provider is None:
        return VerificationOutcome(finding.id, Verdict.UNVERIFIED, "", "",
                                   [], chash, 0, 0, ok=False,
                                   error="未配置 LLM，无法对抗验证")

    # 只读子集 + 提交工具
    from .tools import build_registry, ToolContext
    sub_ctx = ToolContext(cfg=ctx.cfg, scope=ctx.scope, ledger=ctx.ledger,
                          index=ctx.index, vendored=ctx.vendored,
                          parsed=ctx.parsed, provider=None, turn=ctx.turn,
                          repo=ctx.repo)
    full = build_registry(sub_ctx)
    reg = ToolRegistry(ctx.cfg)
    for name in _READONLY_TOOLS:
        if name in full:
            reg.register(full.tools[name])

    submitted: dict = {}

    def _submit(args):
        submitted.update(args)
        return ToolResult(True, "结论已提交。验证结束。")

    reg.register(Tool("submit_verdict",
        "提交你的验证结论。必须在你完成核查之后调用，且 sanitizers_enumerated "
        "要如实填写你检查过的净化措施。",
        _VERDICT_TOOL, _submit, group="D"))

    messages = [{"role": "user",
                 "content": [{"type": "text",
                              "text": build_verifier_prompt(finding, ctx.scope,
                                                            ctx.index)}]}]

    turns = tool_calls = 0
    for turn in range(max_turns):
        turns = turn + 1
        try:
            # ★ 必须用关键字传参：complete() 的签名是 (messages, system="", tools=None)，
            # 按位置传 (system, messages, tools) 会把前两个参数整个对调。
            resp = provider.complete(messages, system=_VERIFIER_SYSTEM,
                                     tools=reg.specs())
        except Exception as e:
            return VerificationOutcome(finding.id, Verdict.UNVERIFIED, "", "",
                                       [], chash, turns, tool_calls, ok=False,
                                       error=f"验证者 LLM 调用失败：{e}")
        messages.append(resp.assistant_message())

        if not resp.tool_calls:
            if turn >= 1 and not submitted:
                messages.append({"role": "user", "content": [{"type": "text",
                    "text": "请调用 submit_verdict 提交你的结论。"}]})
                continue
            break

        results = []
        for tc in resp.tool_calls:
            tool_calls += 1
            r = reg.call(tc.name, tc.arguments)
            results.append({"type": "tool_result", "tool_use_id": tc.id,
                            "content": r.render(5000)})
        messages.append({"role": "user", "content": results})
        if submitted:
            break

    return _parse_outcome(submitted, finding.id, chash, turns, tool_calls)


def _parse_outcome(d: dict, fid: str, chash: str,
                   turns: int, tool_calls: int) -> VerificationOutcome:
    if not d:
        return VerificationOutcome(fid, Verdict.NEEDS_HUMAN,
                                   "验证者未在预算内提交结论。",
                                   "无法自动核实，需人工复核。",
                                   [], chash, turns, tool_calls)
    v = str(d.get("verdict", "NEEDS_HUMAN")).upper()
    try:
        verdict = Verdict(v)
    except ValueError:
        verdict = Verdict.NEEDS_HUMAN
    san = list(d.get("sanitizers_enumerated") or [])
    return VerificationOutcome(
        finding_id=fid, verdict=verdict,
        reasoning=str(d.get("reasoning", "")),
        rebuttal=str(d.get("rebuttal") or ""),
        sanitizers=san, context_hash=chash,
        turns_used=turns, tool_calls=tool_calls,
    )


def apply_outcome(finding, out: VerificationOutcome) -> str:
    """把验证结论写回 finding。返回给主 Agent 的说明文本。"""
    finding.verification.stage = "adversarial"
    finding.verification.verdict = out.verdict
    finding.verification.reasoning = out.reasoning
    finding.verification.rebuttal = out.rebuttal or None
    finding.verification.verifier_context_hash = out.context_hash
    finding.verification.sanitizers_checked = out.sanitizers

    msg = {
        Verdict.CONFIRMED:
            f"✅ 验证者尝试证伪但未能推翻（检查了 {len(out.sanitizers)} 项净化措施）。",
        Verdict.FALSE_POSITIVE:
            f"❌ 验证者推翻了这个结论：{out.rebuttal or out.reasoning[:200]}",
        Verdict.PARTIAL:
            f"⚠️ 漏洞成立但影响被削弱：{out.rebuttal or out.reasoning[:200]}",
        Verdict.NEEDS_HUMAN:
            f"🟡 静态无法判定，需人工复核：{out.reasoning[:200]}",
    }.get(out.verdict, "验证完成。")

    if out.verdict == Verdict.FALSE_POSITIVE:
        msg += "\n该 finding 已标记为误报，不再参与门禁判定（但仍保留在报告中）。"
    return msg


# ---------------------------------------------------------------- 工具封装

def make_adversarial_tool(ctx) -> Tool:
    def handler(args: dict) -> ToolResult:
        fid = str(args["finding_id"])
        f = ctx.ledger.findings.get(fid)
        if f is None:
            return ToolResult(False,
                              f"finding {fid} 不存在。已有："
                              + "、".join(list(ctx.ledger.findings)[:12]),
                              error="not_found")
        out = verify_finding(ctx, f, max_turns=int(args.get("max_turns") or 8))
        if not out.ok:
            return ToolResult(False, f"对抗验证未能完成：{out.error}", error="verify_failed")
        msg = apply_outcome(f, out)
        ctx.ledger.log("adversarial_verified", id=fid, verdict=out.verdict.value,
                       context_hash=out.context_hash, turn=ctx.turn)
        detail = (f"\n验证者推理：{out.reasoning[:600]}"
                  if out.reasoning else "")
        if out.sanitizers:
            detail += "\n验证者检查过的净化措施：\n" + "\n".join(
                f"  · {s[:180]}" for s in out.sanitizers[:8])
        return ToolResult(True,
                          f"{fid} 对抗验证完成：{msg}{detail}\n"
                          f"（验证者独立上下文指纹 {out.context_hash}，"
                          f"用了 {out.turns_used} 轮 / {out.tool_calls} 次工具调用）",
                          {"verdict": out.verdict.value, "rebuttal": out.rebuttal})
    return Tool(
        "adversarial_verify",
        "对一条 finding 发起**独立对抗验证**：另起一个隔离上下文的验证者，"
        "它看不到你的推理过程，只能读代码，任务是主动证伪这条结论。"
        "**所有 HIGH/CRITICAL 必须过这一关才能收口**——这是防止误报进入门禁的机制。"
        "返回 CONFIRMED / FALSE_POSITIVE / PARTIAL / NEEDS_HUMAN；"
        "被判 FALSE_POSITIVE 的会自动退出门禁判定。",
        obj({"finding_id": S("finding id，如 F-001"),
             "max_turns": I("验证者最多轮次，默认 8")}, ["finding_id"]),
        handler, group="D", mutating=True)
