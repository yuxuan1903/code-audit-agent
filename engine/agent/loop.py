# -*- coding: utf-8 -*-
"""Agentic 主循环（任务 1.12，06 §5）。

**这是"由模型自主决定调用哪些工具、以什么顺序调用"的落地点。**
循环本身不编排任何固定步骤——它只做四件事：

  1. 每轮把**账本的确定性摘要**注入上下文（防漂移，06 §5.7）
  2. 执行模型选择的工具，把结果回填（工具集见 tools.py）
  3. 在预算节点给出提示（nudge，06 §5.6）
  4. 用账本判定能否收口（06 §2）

**"有边界的自主"的分界线在这里**：循环体内不做任何业务判断——
不决定先审哪个文件、不决定某条命中算不算漏洞、不决定何时算审完。
这些全部由模型决定，而模型的决定受工具契约与账本终态约束。
循环只负责：给它自主权，并把它的自主权约束在可审计的边界内。

运行时保障（06 §5，全部在本文件实现）：
  5.1 截断检测与续写      —— resp.truncated
  5.2 参数校验            —— 在 registry._validate
  5.3 归因门禁            —— 在 ledger.record_finding + check_vendored 工具
  5.4 双预算（轮次+token）—— Budget
  5.5 上下文压缩          —— _compact()
  5.6 nudge               —— prompts.nudge_for
  5.7 外部账本每轮注入    —— Ledger.digest()
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import prompts
from .ledger import Ledger
from .registry import ToolRegistry, ToolResult
from .tools import ToolContext, build_registry, tool_group_summary
from ..providers.base import estimate_messages_tokens
from ..schema import Budget


@dataclass
class AgentResult:
    status: str                    # concluded | forced | budget_exhausted | error | no_llm
    turns: int = 0
    tokens: int = 0
    seconds: float = 0.0
    stop_reason: str = ""
    error: str = ""
    tool_stats: dict = field(default_factory=dict)
    transcript: list = field(default_factory=list)
    compaction_count: int = 0
    truncation_retries: int = 0
    # 截断了但仍有完整调用可执行的轮数，以及因此跳过的残骸块数。
    # 与 `truncation_retries`（"续写"次数）是两码事，见 `__init__` 的注释。
    truncation_partial: int = 0
    remnants_skipped: int = 0
    # ★ 真实用量分解，取自 provider.usage_total（服务端回报的 usage），
    # 而不是本地估算。**输入量是"数据外发"的唯一可信依据**——它是每轮
    # 实际发出去的整个提示词（系统提示词 + 账本摘要 + 工具结果里的代码）
    # 的累计，而任何基于账本事件的本地估算都必然低估：它数的是"每个事件
    # 的文本长度之和"，而真正的发送量是"每轮把整个历史重发一遍"的累加。
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0

    @property
    def ok(self) -> bool:
        return self.status in ("concluded", "forced")

    def summary(self) -> str:
        icon = {"concluded": "✅", "forced": "⚠️", "budget_exhausted": "⏱️",
                "error": "❌", "no_llm": "➖"}.get(self.status, "?")
        L = [f"{icon} Agent 状态：{self.status}"
             f"（{self.turns} 轮 / {self.tokens:,} tokens / {self.seconds:.0f}s）"]
        if self.compaction_count:
            L.append(f"   上下文压缩 {self.compaction_count} 次")
        if self.truncation_retries:
            L.append(f"   截断续写 {self.truncation_retries} 次")
        if self.truncation_partial:
            L.append(f"   截断 {self.truncation_partial} 轮（有完整调用可执行）"
                     f"，跳过残骸 {self.remnants_skipped} 个")
        if self.tool_stats:
            L.append(f"   工具调用 {self.tool_stats.get('total_calls', 0)} 次，"
                     f"失败 {self.tool_stats.get('total_errors', 0)} 次")
        if self.error:
            L.append(f"   {self.error[:300]}")
        return "\n".join(L)


class AuditAgent:
    def __init__(self, cfg, scope, report, ledger: Ledger,
                 index=None, vendored=None, provider=None,
                 candidates: list | None = None) -> None:
        self.cfg = cfg
        self.scope = scope
        self.report = report
        self.ledger = ledger
        self.index = index
        self.vendored = vendored
        self.provider = provider

        acfg = cfg.agent
        self.budget = Budget(max_turns=acfg.max_turns, max_tokens=acfg.max_tokens,
                             max_seconds=acfg.max_seconds)
        self.messages: list[dict] = []
        self.result = AgentResult(status="error")
        self.compacted = 0
        self.trunc_retries = 0
        # ★ 与 `trunc_retries` 是两件事，别混：
        #   · `trunc_retries`   —— 什么都没发出来、只能"续写"的次数（原有语义）
        #   · `truncation_partial` —— 截断了但**有**完整调用可执行的轮数
        #   · `remnants_skipped`  —— 因此跳过的残骸块总数
        # 后两个若不上报，截断在产物里就依然不可观测——这正是它此前能藏十次
        # 运行、留下 33 次误报 `bad_args` 的原因。
        self.truncation_partial = 0
        self.remnants_skipped = 0
        self.text_only_streak = 0
        self.concluded = False
        self.conclude_args: dict = {}

        self.ctx = ToolContext(cfg=cfg, scope=scope, ledger=ledger, index=index,
                               vendored=vendored, parsed=report.modules,
                               provider=provider, turn=0, repo=Path(scope.repo))
        self.registry = build_registry(self.ctx)
        self.candidates = candidates or []

    # ============================================================ 入口

    def run(self) -> AgentResult:
        t0 = time.time()
        if self.provider is None or not getattr(self.provider, "caps", None) \
                or not self.provider.caps.supports_tool_calling:
            self.result.status = "no_llm"
            self.result.error = ("未配置支持 tool calling 的 LLM，"
                                 "已跳过 Agentic 分析（引擎结果仍然有效）")
            self.result.seconds = time.time() - t0
            return self.result

        self._seed()
        try:
            self._loop()
        except KeyboardInterrupt:
            self.result.status = "error"
            self.result.error = "用户中断"
        except Exception as e:                      # 兜底：绝不让异常吞掉已有账本
            self.result.status = "error"
            self.result.error = f"主循环异常：{type(e).__name__}: {e}"
            self.ledger.log("loop_error", error=str(e)[:400])

        self.result.turns = self.budget.turns_used
        self.result.tokens = self.budget.tokens_used
        self.result.seconds = time.time() - t0
        self.result.tool_stats = self.registry.stats()
        self.result.compaction_count = self.compacted
        self.result.truncation_retries = self.trunc_retries
        self.result.truncation_partial = self.truncation_partial
        self.result.remnants_skipped = self.remnants_skipped
        # 服务端回报的用量优先。拿不到（如 mock provider 没填）就留 0，
        # 由报告层如实显示"未取得"，而不是退回去用本地估算冒充真实值。
        u = getattr(self.provider, "usage_total", None)
        if u is not None:
            self.result.input_tokens = u.input_tokens
            self.result.output_tokens = u.output_tokens
            self.result.cache_read_tokens = u.cache_read_tokens
            self.result.cache_write_tokens = u.cache_write_tokens
        # ★ 轨迹必须包含 thinking。模型常把全部推理放进 thinking 块，
        # text 块留空——只收 assistant_text 会让轨迹几乎为空：实测 40 轮
        # 审计里 assistant_text 仅 1 条（96 字符），而 thinking 有 39 条
        # （47K 字符）。轨迹的可审计性全靠后者，漏了它等于没有轨迹。
        # 账本里的 thinking/assistant_text 写入时已按上限裁剪（见 _clip），
        # 这里照搬即可——**不要再截一次**，否则会把 _clip 加的截断说明本身裁掉，
        # 又变回"看不出被截断"。
        self.result.transcript = [
            {"turn": e.get("turn"), "kind": e.get("kind"),
             "text": e.get("text") or ""}
            for e in self.ledger.events
            if e.get("kind") in ("assistant_text", "thinking")
        ]
        return self.result

    # ============================================================ 初始化

    def _seed(self) -> None:
        scope_digest = self.scope.to_prompt() if hasattr(self.scope, "to_prompt") \
            else f"（范围摘要不可用：{len(self.scope.files)} 个文件）"

        eps = getattr(self.scope, "entry_points", []) or []
        no_auth = [e for e in eps if e.auth == "none"]
        entry_digest = (
            f"### 外部入口 {len(eps)} 个"
            + (f"，其中 **{len(no_auth)} 个无鉴权**：\n"
               + "\n".join(f"  · {e.file}:{e.line} {e.kind} {e.target}"
                           for e in no_auth[:20])
               if no_auth else "（无无鉴权入口，或入口提取未覆盖该框架）\n")
        ) if eps else "### 外部入口\n未提取到入口点。"

        text = prompts.FIRST_USER_TEMPLATE.format(
            scope_digest=scope_digest,
            entry_digest=entry_digest,
            tool_digest=tool_group_summary(self.registry),
            n_candidates=len(self.candidates),
        )
        self.messages.append({"role": "user",
                              "content": [{"type": "text", "text": text}]})

    # ============================================================ 主循环

    def _loop(self) -> None:
        acfg = self.cfg.agent
        last_nudge = ""

        while not self.budget.exhausted:
            # ---- 预算记账
            self.budget.turns_used += 1
            self.ctx.turn = self.budget.turns_used
            before = estimate_messages_tokens(self.messages, prompts.SYSTEM)
            self.budget.tokens_used = max(self.budget.tokens_used, before)

            # ---- 上下文压缩（5.5）
            # ★ 按**上下文窗口填充率**触发，不是按总预算消耗比例。
            # 曾经写成 budget.ratio_used >= compact_at_ratio：ratio_used 是总预算
            # （轮次/token）的消耗比例，单调递增且不因压缩回落，于是预算用掉 60%
            # 之后**每一轮都压缩**。实测 15 轮压缩 7 次，把 Agent 刚读过的代码
            # 从上下文里抹掉，直接导致同一文件被反复重读（settings.py 读 3 遍）。
            # 压缩省不下已经计费的 token——它唯一的用途是别撑爆模型上下文，
            # 因此唯一的正确触发依据是「当前上下文有多大」。
            if before >= self._ctx_window() * acfg.compact_at_ratio:
                self._compact()

            # ---- nudge（5.6）
            nudge = prompts.nudge_for(self.budget.ratio_used, self.cfg)
            if nudge and nudge != last_nudge:
                self.messages.append({"role": "user",
                                      "content": [{"type": "text", "text": nudge}]})
                last_nudge = nudge

            # ---- 请求
            resp = self._call_model()
            if resp is None:
                return
            self.budget.tokens_used = max(self.budget.tokens_used,
                                          before + resp.usage.total)

            # ---- 截断（5.1）
            # ★ 判定条件**不能**是 `resp.truncated and not resp.tool_calls`。
            #
            # 十次真实运行的账本里有 33 次「参数为 `{}` 的调用被拒」（`bad_args`），
            # 特征指向截断而非模型疏忽：空调用落在**轮内最后一个**位置的概率
            # 7.3%、非最后位置 1.1%（7 倍），且与该轮并行调用数呈剂量-反应——
            # 1–3 个时 3.9% 的轮次出现空调用，4–9 个时 10.3%，**10 个以上 72.7%**。
            #
            # 因果由受控探针坐实（`out/_probe_truncation.py`，同一提示词只改
            # max_tokens）：上限 400 → `stop_reason=max_tokens`，3/3 次都在最后
            # 一个工具调用块上留下 `input={}`；上限 8000 → 12 个块全部完整、0 个空。
            #
            # 而"一轮发很多调用"恰恰是最容易撞上 max_tokens 的形态，它一定**有**
            # 工具调用——于是原条件在有调用时永远不触发，截断被静默吞掉。残骸块
            # 被当普通调用执行，注册表回一句"参数校验失败：缺少必填参数"，模型
            # 于是只能理解成"我把参数写错了"。它真的这么想了：`real-group` 第 35
            # 轮思考原文是 "the previous attempt dropped because I emitted an
            # empty call"。它花轮次重发、把预算烧在自我纠正上，而它本来要记的
            # 东西可能就此丢失。
            #
            # 现在：截断照样记账；**有调用时也走这条路**——刀口之前那些参数完整
            # 的块照常执行（那是有效工作，丢掉才是浪费），残骸跳过并如实说明成因。
            if resp.truncated:
                # 计数用的是**精判后**的残骸（截断 + 空参 + 该工具确有必填字段），
                # 不是原始的 `tc.remnant`——后者会把合法的无参调用也数进去。
                n_rem = sum(1 for tc in resp.tool_calls
                            if tc.remnant
                            and self.registry.has_required_args(tc.name))
                if resp.tool_calls:
                    self.truncation_partial += 1
                    self.ledger.log("truncation_partial", turn=self.ctx.turn,
                                    calls=len(resp.tool_calls),
                                    remnant=n_rem, skipped=n_rem)

            self.messages.append(resp.assistant_message())
            if resp.text.strip():
                self.ledger.log("assistant_text", turn=self.ctx.turn,
                                text=_clip(resp.text.strip(), 8000))

            # ---- 无工具调用：模型想说话
            if not resp.tool_calls:
                if resp.truncated:
                    # 截断且什么都没发出来 → 只能续写，没有 tool_result 要回。
                    if self.trunc_retries < acfg.max_truncation_retries:
                        self.trunc_retries += 1
                        self.ledger.log("truncation_continue",
                                        turn=self.ctx.turn, n=self.trunc_retries)
                        self.messages.append({"role": "user", "content": [
                            {"type": "text",
                             "text": prompts.TRUNCATION_CONTINUE}]})
                        continue
                    # 续写次数用尽：如实记录，不假装输出完整
                    self.ledger.log("truncation_exhausted", turn=self.ctx.turn)
                    self.messages.append({"role": "user", "content": [{"type": "text",
                        "text": "（输出多次被截断，本轮的推理未完成。"
                                "请用工具把已有结论落到账本上。）"}]})
                    continue
                if self._handle_text_only(resp):
                    return
                continue

            # ---- 执行工具（截断时跳过残骸，并如实说明成因）
            results = self._execute(resp.tool_calls, truncated=resp.truncated)
            self.messages.append({"role": "user", "content": results})

            # ---- 账本注入（5.7）
            self._inject_digest()

            if self.concluded:
                self._finish_concluded()
                return

        # 预算耗尽
        self.result.status = "budget_exhausted"
        self.result.stop_reason = ("预算耗尽（轮次或 token）")
        self.ledger.log("budget_exhausted", turn=self.budget.turns_used,
                        tokens=self.budget.tokens_used)

    def _call_model(self):
        try:
            resp = self.provider.complete(
                self.messages, system=prompts.SYSTEM,
                tools=self.registry.specs(),
                max_tokens=self.provider.cfg.max_output_tokens,
            )
        except Exception as e:
            name = type(e).__name__
            self.ledger.log("llm_error", error=f"{name}: {e}"[:400],
                            turn=self.ctx.turn)
            # 上下文溢出 → 压缩后重试一次；其它错误 → 带着已有账本退出
            if name == "ContextOverflowError" or "context" in str(e).lower():
                self._compact(force=True)
                try:
                    resp = self.provider.complete(
                        self.messages, system=prompts.SYSTEM,
                        tools=self.registry.specs())
                except Exception as e2:
                    self.result.status = "error"
                    self.result.error = f"压缩后仍失败：{type(e2).__name__}: {e2}"
                    return None
            else:
                self.result.status = "error"
                self.result.error = (f"LLM 调用失败，已停止 Agentic 分析"
                                     f"（引擎结果与已入账候选不受影响）：{e}")
                return None

        if resp.thinking:
            self.ledger.log("thinking", turn=self.ctx.turn,
                            text=_clip(resp.thinking, 8000))
        return resp

    # ============================================================ 工具执行

    def _execute(self, tool_calls, truncated: bool = False) -> list[dict]:
        self.text_only_streak = 0
        results = []
        n_remnant = 0        # 截断残骸：没传完，已跳过
        n_exec = 0           # 真正交给注册表执行过的（成功与否都算——"执行过"
                             # 才是模型重发时会不会写重账本的判据，不是"成功"）
        n_parse = 0          # 参数不是合法 JSON，被拒
        for tc in tool_calls:
            if tc.parse_error:
                n_parse += 1
                results.append({"type": "tool_result", "tool_use_id": tc.id,
                                "content": f"❌ 工具参数不是合法 JSON：{tc.parse_error}。"
                                           f"请重新调用 {tc.name}，注意引号与逗号。",
                                "is_error": True})
                continue

            # ★ 截断残骸：**不能**当普通调用执行。注册表会回一句"参数校验失败：
            # 缺少必填参数"，而模型收到这句只能理解成"我把参数写错了"——事实
            # 是它什么都没写错，是输出被砍断了。这里既不执行它，也不给一句像
            # "你写错了"的反馈，而是把**真实成因**写清楚（见 prompts.TOOL_REMNANT）。
            #
            # ★ `has_required_args` 这一层不能省：`tc.remnant` 只说"本轮被截断
            # **且**参数为空"，而空参数在**没有必填字段**的工具上是合法的
            # （`list_candidates` 就是）。少了这一层，截断轮里那些正常调用会被
            # 一起跳过——多花一轮重发，还会让模型以为它们也出了问题。
            if tc.remnant and self.registry.has_required_args(tc.name):
                n_remnant += 1
                self.ledger.log("tool_remnant", turn=self.ctx.turn, name=tc.name,
                                note="输出被 max_tokens 截断，参数未传完，已跳过")
                results.append({"type": "tool_result", "tool_use_id": tc.id,
                                "content": prompts.TOOL_REMNANT.format(name=tc.name),
                                "is_error": True})
                continue

            r = self.registry.call(tc.name, tc.arguments)
            self.ledger.log("tool", turn=self.ctx.turn, name=tc.name,
                            ok=r.ok, args=_brief(tc.arguments), error=r.error)
            n_exec += 1

            # 成功收口
            if tc.name == "conclude" and r.ok:
                self.concluded = True
                self.conclude_args = tc.arguments

            text = r.render(self.cfg.agent.tool_result_max_chars)
            entry = {"type": "tool_result", "tool_use_id": tc.id, "content": text}
            if not r.ok:
                entry["is_error"] = True
            results.append(entry)

        # 整批的说明接在最后。★ `n_exec` 必须报出来：不说清楚哪些已经执行过，
        # 模型会以为整批都没成，把已执行的**重发一遍**——那些副作用（往账本里
        # 写发现、标候选已处置）就重复了。
        if truncated and results:
            self.remnants_skipped += n_remnant
            results.append({
                "type": "text",
                "text": prompts.truncation_notice(
                    n_calls=len(tool_calls), n_exec=n_exec,
                    n_remnant=n_remnant, n_parse=n_parse),
            })
        return results

    def _handle_text_only(self, resp) -> bool:
        """模型没调工具。判断它是想收尾、还是卡住了。"""
        text = (resp.text or "").strip()
        self.text_only_streak += 1

        # ★ 连续纯文本要有上限。否则模型卡住时会把预算全烧在空转的 nudge 上，
        # 最后一轮 token 耗尽、什么都没记下来——这是最坏的失败形态。
        if self.text_only_streak >= 3:
            self.ledger.log("text_only_giveup", turn=self.ctx.turn,
                            text=text[:400])
            self.result.status = "budget_exhausted"
            self.result.stop_reason = ("模型连续 3 轮未调用工具，主动停止以免空转"
                                       "烧尽预算")
            return True

        # 看起来在收尾但没有真正 conclude
        if self.ledger.can_conclude:
            # 这里也要强制对账：模型已经进入收尾语气，是最典型的一次
            # "马上要给结论了"的时刻，而对账的意义正是在那一刻之前问一句
            # "你说过的东西都记下了吗"。
            self._inject_digest(force_recall=True)
            self.messages.append({"role": "user", "content": [{"type": "text",
                "text": "账本显示所有硬性条件已满足，但你还没有调用 conclude。"
                        "请调用 conclude 提交最终结论（summary + limitations）。"
                        "若你还有话要说，把要点放进 summary。"}]})
            return False

        # 还在缺东西却停止调工具
        blockers = self.ledger.blockers()
        self.messages.append({"role": "user", "content": [{"type": "text",
            "text": "你没有调用任何工具就结束了本轮，但账本显示还有未闭合项：\n"
                    + "\n".join(f"  · {b}" for b in blockers)
                    + "\n请继续用工具处理它们。若某条确实无法完成，"
                      "用 set_coverage(skipped) 或 dispose_candidate(deferred) "
                      "如实记录并说明理由。"}]})
        self.ledger.log("text_only_nudge", turn=self.ctx.turn, text=text[:400])
        return False

    # ============================================================ 账本注入

    def _inject_digest(self, force_recall: bool = False) -> None:
        """★ 每轮注入账本的确定性状态（06 §5.7 / 对策 D1）。

        模型看到的不是"它记得什么"，而是"账本实际记下了什么"。
        即使模型发生漂移，账本仍然完整，收敛检测仍然有效。

        注入之前先做一次**收敛对账**（06 §5.8）：把"推理里提过、账本里没有"
        的位置提成待处置候选。对账放在这里而不是别处，是因为注入的正是
        "账本实际记了什么"，而漏报恰恰发生在账本与轨迹的差集上。

        `force_recall=True` 用于 `conclude` 被调用的时刻——那里不能有门槛：
        一次快速收敛的运行也必须先对过账。否则跑得越顺，越没人检查。
        """
        if force_recall or self.budget.ratio_used >= self.cfg.agent.recall_after_ratio:
            self.ledger.recall_scan(self.ctx.turn)

        blocked = self.ledger.blockers()
        parts = [self.ledger.digest()]
        if blocked:
            parts.append("**未闭合项（收口前必须处理）**：")
            parts.extend(f"  · {b}" for b in blocked)
        else:
            parts.append("✅ 所有硬性条件已满足，可以调用 conclude 收口。")
        parts.append(f"预算：第 {self.budget.turns_used}/{self.budget.max_turns} 轮，"
                     f"约 {self.budget.tokens_used:,}/{self.budget.max_tokens:,} tokens。")

        self.messages.append({"role": "user", "content": [
            {"type": "text", "text": "[账本状态]\n" + "\n".join(parts)}]})

    # ============================================================ 压缩

    def _ctx_window(self) -> int:
        """上下文窗口大小。**以 provider 声明的为准**，配置值只作兜底。

        用错这个数会以两种方式失败：估大了永远不触发压缩，直到 API 直接
        报上下文超限（一轮白跑）；估小了压缩过频，把 Agent 刚建立的认识
        反复抹掉。provider 从模型名推断出的窗口比配置里的固定值更可信——
        它至少跟着 `--model` 走。
        """
        caps = getattr(self.provider, "caps", None)
        w = int(getattr(caps, "max_context_tokens", 0) or 0) if caps else 0
        if w > 8_000:
            return w
        return self.cfg.agent.context_window_tokens

    def _compact(self, force: bool = False) -> None:
        """上下文压缩（06 §5.5）。

        **压缩后保留的不是对话摘要，而是账本摘要**——这是刻意的：
        对话摘要会带入模型的措辞与偏见，账本是确定性的、可核对的。
        压缩丢掉的正是"模型的推理过程"，保留的是"模型做过的事"。
        """
        acfg = self.cfg.agent
        # 保留多少：按 token 而非消息条数。一条 tool_result 可能顶几十条短消息，
        # 按条数保留会让压缩后的实际大小完全失控。
        keep_tokens = int(self._ctx_window()
                          * (1 - acfg.compact_at_ratio) * 0.5)
        idx = len(self.messages)
        acc = 0
        while idx > 1 and acc < keep_tokens:
            idx -= 1
            acc += estimate_messages_tokens([self.messages[idx]])
        # 保留点必须落在 assistant 上：tool_use 与它的 tool_result 被切断，
        # 下一次请求会被 API 直接拒绝。
        while idx < len(self.messages) and \
                self.messages[idx].get("role") != "assistant":
            idx += 1
        if idx >= len(self.messages) or idx <= 1:
            # 攒不出可压的部分——上下文本来就小，压缩没有意义。
            # 早期版本在预算过半后仍强压，把刚读过的代码抹掉，得不偿失。
            if not force:
                return
            idx = max(1, len(self.messages) - 2)
            while idx < len(self.messages) and \
                    self.messages[idx].get("role") != "assistant":
                idx += 1
            if idx >= len(self.messages):
                return

        head = self.messages[:1]                 # 任务书
        tail = self.messages[idx:]
        bridge = {"role": "user", "content": [{"type": "text", "text":
            "（早先的对话细节已压缩移除。以下是你目前已做的事的**确定性记录**，"
            "以它为准，不要凭记忆推断。"
            "「已读过的文件」清单列出的是你已经看过的内容——"
            "只有不在清单里的文件、或清单里未覆盖的行区间，才需要重新读。）\n\n"
            + self.ledger.digest(max_findings=20, max_cands=20)}]}

        old = estimate_messages_tokens(self.messages, prompts.SYSTEM)
        self.messages = head + [bridge] + tail
        new = estimate_messages_tokens(self.messages, prompts.SYSTEM)
        self.compacted += 1
        self.ledger.log("compacted", turn=self.ctx.turn,
                        tokens_before=old, tokens_after=new)
        # ★ 不退还 token 预算。压缩省下的是**上下文占用**，不是钱——被压掉的
        # 内容已经作为 prompt 发出并计过费了。退还预算会让 ratio_used 虚假回落，
        # 使 nudge 与停止判定失真（且下一轮的 max() 又会把它拉回去，
        # 那条语句实际上从未生效，只是伪装成了"压缩有收益"）。

    # ============================================================ 收口

    def _finish_concluded(self) -> None:
        args = self.conclude_args or {}
        forced = bool(args.get("force"))
        self.result.status = "forced" if forced else "concluded"
        self.result.stop_reason = str(args.get("summary", ""))[:500]
        self.ledger.conclusion = {
            "summary": str(args.get("summary", "")),
            "limitations": list(args.get("limitations") or []),
            "forced": forced,
            "blockers": self.ledger.blockers() if forced else [],
        }
        self.ledger.log("concluded", forced=forced, turn=self.budget.turns_used)


# ---------------------------------------------------------------- 辅助

def _clip(text: str, limit: int) -> str:
    """截断长文本，并**显式标注**被截断。

    ★ 静默截断与空字段是同一类问题：产物看起来完整，读者却无从分辨
    "推理到这里就结束了"和"我们把它切了"。实测 2000 字符的上限下，
    两次 40 轮运行各有 13 条 / 17 条思考撞上上限（约占三分之一），
    而切掉的正是推理的**结尾**——下结论的那一句（实测断在
    "But limited. **Let me hold.**" 的 "Let" 上）。
    轨迹是审计可复核性的载体，它不能悄悄少一截。
    """
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n…（记录被截断，原文另有 {len(text) - limit} 字符）"


def _brief(args: dict, max_len: int = 200) -> str:
    try:
        s = json.dumps(args, ensure_ascii=False)
    except (TypeError, ValueError):
        s = str(args)
    return s[:max_len]
