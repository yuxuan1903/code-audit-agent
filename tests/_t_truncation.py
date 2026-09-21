# -*- coding: utf-8 -*-
"""缺陷 #31：截断残骸被误报成 `bad_args` —— 离线回归测试。

★ 这个测试在防什么

`loop.py` 原来的截断分支写作：

    if resp.truncated and not resp.tool_calls:

而截断最容易发生的形态（一轮发 10–24 个带证据文本的调用）**一定有**工具调用，
于是这条分支在有调用时永不触发。被 max_tokens 砍断后留下的残骸块
（`input == {}`）被当普通调用执行，注册表回一句

    参数校验失败：缺少必填参数（必填：...）

模型收到这句只能理解成"我把参数写错了"。它在 `real-group` 第 35 轮的思考里
就是这么想的：`the previous attempt dropped because I emitted an empty call`。
十次运行的账本里留下了 33 次这样的误报。

★ 三条断言，对应修法的三个要点

  T1 残骸**不执行** —— 注册表里不能出现那次调用（否则就是误报的源头）
  T2 反馈说的是**真成因** —— 回给模型的话里不能出现"参数校验失败/缺少必填参数"，
     必须出现"截断"和残骸工具的**名字**（它得知道该重发哪一个）
  T3 已执行的**要报数** —— 不说清楚哪些执行过，模型会把已执行的**重发一遍**，
     那些副作用（往账本里写发现、标候选已处置）就写重了

★ 还有一条对照，防"修过头"

  C1 非截断的一轮里，合法给 `{}` 的调用（`list_candidates` 的参数全是可选）
     **必须照常执行**。只看"参数为空"就跳过，会把正常调用也误伤。

全部离线：MockProvider 脚本化响应，不花 API 调用、不需要密钥。
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from engine.util import force_utf8
force_utf8()

from engine.agent.ledger import Ledger
from engine.agent.loop import AuditAgent
from engine.agent.tools import ToolContext, build_registry
from engine.collect import collect
from engine.config import Config
from engine.context import CodeIndex
from engine.providers.mock import MockProvider

sys.path.insert(0, str(Path(__file__).resolve().parent))   # -I 隐含 -P：脚本自身目录不在 sys.path
from _target import require_target

TARGET = require_target()

_fails: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    print(f"  {'✅' if ok else '❌'} {name}")
    if detail:
        print(f"      {detail}")
    if not ok:
        _fails.append(name)


cfg = Config.load(TARGET)
scope, report = collect(cfg)
idx = CodeIndex(scope, report)

print("=" * 74)
print("缺陷 #31 回归：截断残骸不再被误报成 bad_args")
print("=" * 74)

# ------------------------------------------------------------------ T1/T2/T3
# 一轮**被截断**的响应，形状照抄真实现场：
#   块 1  完整调用（应执行）
#   块 2  完整调用（应执行）
#   块 3  残骸——参数 `{}`，因为输出在这一块上被砍断
# `record_finding` 的必填字段很多，若残骸被当普通调用执行，注册表**一定**
# 回 `bad_args`——这正是要复现的那个误报。
led = Ledger(scope, cfg)
ctx = ToolContext(cfg=cfg, scope=scope, ledger=led, index=idx,
                  parsed=report.modules, repo=TARGET)
reg = build_registry(ctx)

script = [
    {"type": "multi_tool", "stop_reason": "max_tokens",
     "thinking": "先看候选清单，再读代码。",
     "tools": [
         # 带参数的完整调用：在刀口之前，是有效工作，必须执行
         {"name": "list_candidates", "input": {"status": "open"}},
         # ★ 空参数，但 `list_files` **没有必填字段**（`list_candidates` /
         # `get_entry_points` 同理）——这是**合法**调用。它在被截断的一轮里，
         # 若判定只看"参数为空"就会被误伤。留着它，专门盯住那一层判断。
         # （注意别拿 `outline` 当例子：它有必填的 `file`，空参确实非法。）
         {"name": "list_files", "input": {}},
         # ★ 残骸：截断砍出来的空 input。模型**没有**打算不带参数调用
         # `record_finding`——它是想在证据文本里写完再发的。
         {"name": "record_finding", "input": {}},
     ]},
    {"type": "tool_use", "name": "conclude", "input": {
        "summary": "回归测试：仅验证截断处理路径，未做实际审计。",
        "limitations": ["测试用脚本化响应，非真实审计"]}},
]

provider = MockProvider(cfg.llm, script=script)
agent = AuditAgent(cfg, scope, report, led, index=idx, provider=provider)
prev_turns = cfg.agent.max_turns
cfg.agent.max_turns = 3
try:
    result = agent.run()
finally:
    cfg.agent.max_turns = prev_turns

tool_events = [e for e in led.events if e.get("kind") == "tool"]
remnant_events = [e for e in led.events if e.get("kind") == "tool_remnant"]
rec_find = [e for e in tool_events if e.get("name") == "record_finding"]
list_files = [e for e in tool_events if e.get("name") == "list_files"]

print("\n--- T1 残骸不执行 ---")
check("账本里没有 `record_finding` 的执行记录（注册表根本没被调用）",
      len(rec_find) == 0,
      f"实际 {len(rec_find)} 条"
      + (f"：{[(e.get('ok'), e.get('error')) for e in rec_find]}" if rec_find else ""))
check("账本里有 `tool_remnant` 事件，且点名了 `record_finding`",
      any(e.get("name") == "record_finding" for e in remnant_events),
      f"{len(remnant_events)} 条 remnant 事件")
check("★ 全轮**零** `bad_args`——这正是此前 33 次误报里的一句话",
      not any(e.get("error") == "bad_args" for e in tool_events),
      f"bad_args 计数：{sum(1 for e in tool_events if e.get('error') == 'bad_args')}")
check("残骸**前面**的完整调用照常执行了（丢掉有效工作同样是错的）",
      len([e for e in tool_events if e.get("name") == "list_candidates"]) == 1,
      f"list_candidates 执行 {len([e for e in tool_events if e.get('name') == 'list_candidates'])} 次")

print("\n--- T2 反馈说真成因 ---")
# ★ 不能只看"最后一条 user 消息"——截断通知发出后，循环还会继续注入账本摘要
# 和覆盖度催办，那些也是 user 消息。要**在整条请求流水里搜**那条通知本身。
blob = ""
for t in provider.trace:
    for m in t["messages"]:
        if m.get("role") != "user":
            continue
        for b in (m.get("content") or []):
            if isinstance(b, dict):
                blob += str(b.get("content", "")) + "\n" + str(b.get("text", "")) + "\n"

check("回给模型的话里出现了「截断」",
      "截断" in blob, f"片段：{blob[:160]!r}")
check("★ 回给模型的话里**没有**「缺少必填参数」这类会误导它自我归咎的措辞",
      "缺少必填参数" not in blob and "参数校验失败" not in blob)
check("点出了该重发哪一个（残骸工具名出现）",
      "record_finding" in blob)
check("★ 报出了实际执行数——否则模型会把已执行的**重发一遍**、账本写重",
      "已经执行" in blob or "已执行" in blob)

print("\n--- T2b 截断轮里的**合法**空参调用不能被误伤 ---")
# 判定的第二层：`list_files` 没有必填字段，空参数是合法的，即使在截断轮里
# 也该照常执行。少了这一层，截断轮里所有空参调用都会被跳过——多花一轮重发，
# 还会让模型以为它们也出了问题。
lf_ev = [e for e in tool_events if e.get("name") == "list_files"]
check("★ 截断轮里 `list_files({})` 照常执行（空参 + 无必填字段 ⇒ 合法调用）",
      len(lf_ev) == 1, f"实际执行 {len(lf_ev)} 次")
check("它没被记成 remnant",
      not any(e.get("kind") == "tool_remnant" and e.get("name") == "list_files"
              for e in led.events))
check("`remnants_skipped` 只数了真正的残骸（1 个，不是 2 个）",
      result.remnants_skipped == 1, f"实际 {result.remnants_skipped}")

print("\n--- T3 计数进产物 ---")
check("result.truncation_partial == 1", result.truncation_partial == 1,
      f"实际 {result.truncation_partial}")
check("result.remnants_skipped == 1", result.remnants_skipped == 1,
      f"实际 {result.remnants_skipped}")

# ------------------------------------------------------------------ C1 对照
# 非截断的一轮里，`{}` 是**合法参数**（`list_candidates` 的参数全是可选）。
# 若修法写成"参数为空就跳过"，这里会误伤——所以必须有这一条。
print("\n--- C1 对照：非截断的合法空参调用不能被误伤 ---")
led2 = Ledger(scope, cfg)
ctx2 = ToolContext(cfg=cfg, scope=scope, ledger=led2, index=idx,
                   parsed=report.modules, repo=TARGET)
reg2 = build_registry(ctx2)
script2 = [
    {"type": "tool_use", "name": "list_candidates", "input": {}},
    {"type": "tool_use", "name": "conclude", "input": {
        "summary": "对照：非截断的空参调用。",
        "limitations": ["测试用脚本化响应"]}},
]
prov2 = MockProvider(cfg.llm, script=script2)
prev2 = cfg.agent.max_turns
cfg.agent.max_turns = 3
try:
    res2 = AuditAgent(cfg, scope, report, led2, index=idx,
                      provider=prov2).run()
finally:
    cfg.agent.max_turns = prev2

lc = [e for e in led2.events if e.get("kind") == "tool"
      and e.get("name") == "list_candidates"]
check("非截断轮里 `list_candidates({})` 照常执行（未被当成残骸）",
      len(lc) == 1, f"实际执行 {len(lc)} 次")
check("它也没被记成 remnant",
      not any(e.get("kind") == "tool_remnant" for e in led2.events))
check("对照轮 truncation_partial 仍为 0",
      res2.truncation_partial == 0 and res2.remnants_skipped == 0,
      f"partial={res2.truncation_partial} skipped={res2.remnants_skipped}")

print()
print("=" * 74)
if _fails:
    print(f"❌ {len(_fails)} 项失败：")
    for f in _fails:
        print(f"   · {f}")
    raise SystemExit(1)
print("✅ 全部通过")
