#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""对账机制参数的离线扫描 —— 在**已有的真实账本**上重放，不调用模型。

存在的理由：一次真实 40 轮运行约 7 分钟、27 万个输入 token。调一个参数就跑
一次真实运行是不可行的，而"这个参数该取多少"必须有依据。四份真实账本
（`real-final` / `real-full` / `real-fix` / `real-reap`）就是现成的实验台：
它们的推理文本、finding、覆盖度都是真的，只有**扫描器参数**是变量。

★ 被逼出这个脚本的现场（`real-reap`）：
  第 37 轮（倒数第 3 轮）模型在推理里提到了 `lib/ylinux_xmlrpc.py:120`——
  正是 V10 的 basename 净化点，落在真值窗口 105±25 内。但 A 类 6 条配额
  **已在第 32 轮用完**，这条提及永远没变成线索。V10 因此成为三条真值里
  唯一仍未落账的。
  而用掉的那 6 条里，**5 条最终被 `_reap_stale` 自动回收**——提名它们的时候
  那个位置还没有结论，随后模型自己补上了。配额烧在了"再等两轮它自己就
  落账了"的位置上。

所以扫描要回答两个问题，而不是一个：
  · **捞到了吗** —— V9/V10/V11 所在位置有没有进入提名（这是机制存在的理由）
  · **浪费了吗** —— 提名的条数里有多少最终被自动回收（模型本不必看）

只优化前者会把参数推向"提得越多越好"，而提得越多，模型要处置的就越多——
real-fix 实测 12 条线索只处置了 1 条。**配额的价值在于被逐条看过**，
提出却没人看，比不提更糟：报告会多出一段"未复核"的清单。

★ 这个脚本逼出了配额语义的改动，两版对照留在下面（同一个网格、同一批账本）：

    冷静期 3 配额 6   real-final  real-full   real-fix   real-reap
    累计提名量          11/9/2     12/10/2★    12/7/5★    12/10/2      ← 捞不到 V10
    同时待处置量        17/10/7    18/10/8★    19/8/11★   23/12/11★    ← 捞到了

右边的读数与 real-reap 的**实测**结果（12 提名 / 10 回收 / 2 待表态，
且 100% 处置完毕）逐字吻合，这是重放忠实性的证据——它不是一段自说自话
的模拟。改动落地后这里只剩"同时待处置量"一张表（引擎已改，再模拟累计
语义就跑不出东西了，留一个看起来能跑、实则两支同值的开关是个陷阱）。

★ **重放有一件事做不到，读这张表时必须知道**：配额是**从零开始计**的，而真实
运行里配额是**在第 N 轮被占满**的。所以它回答的是"从头就配 X 条，捞得到吗"，
**不是**"第 32 轮配额恰好满着，第 37 轮那条提及还进得来吗"——而 real-reap 的
现场是后者。这张表在**所有**参数组合下都给 V10 打 ★（包括配额 2），正是因为
重放让每条提及都从空账本出发；换成真实运行，同样的提及会被前面 6 条挡在门外。
调参时可以把这张表当作"配额不至于让某条提及永远进不来"的下界证据，**但不能
拿它当作"改了配额语义就能捞到 V10"的证明**——那个只能由真实运行回答
（见 `out/real-batch`）。

用法：
    python tests/_tune_recall.py <账本目录> [更多目录 ...]     # 必须显式给出
"""
from __future__ import annotations

import json
import sys
from itertools import product
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from engine.util import force_utf8
force_utf8()

from engine.collect import collect
from engine.config import Config
from engine.agent import recall as R

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _probe_recall import _FakeLedger                       # noqa: E402
from _target import require_target                          # noqa: E402

ROOT = Path(__file__).resolve().parent.parent

# real-reap 里那条被配额挡掉的提及，是本次扫描要解释的对象
V10_WINDOW = ("lib/ylinux_xmlrpc.py", 105 - 25, 105 + 25)

# 扫描网格。冷静期与总量是两个独立的问题：
#   · 冷静期管"**什么时候**问"——太短则问了刚要自行落账的位置
#   · 总量管"**一共问几条**"——太少则后期提及（信息最完整）挤不进来
GRACES = (2, 3, 5)
TOTALS = (2, 4, 6, 8)


def _clean(path: Path, scope, cfg) -> _FakeLedger:
    """加载账本并**清空对账线索**，只留真值（finding / 覆盖度 / 读过的行）。

    要问的是"配置是 X 时会提名哪些"，所以上一次运行提过什么必须擦掉，
    否则 `_emitted` 与账面候选会一起把答案限定成"和上次一样"。
    """
    led = _FakeLedger(json.loads(path.read_text(encoding="utf-8")), scope, cfg)
    led.candidates = {k: v for k, v in led.candidates.items()
                      if getattr(v, "source", "") != "recall"}
    led.events = [e for e in led.events
                  if e.get("kind") not in ("recall_flagged", "recall_reaped")]
    return led


def _replay(base: _FakeLedger, grace: int, total: int, start: int,
            end: int) -> dict:
    """按轮重放一次扫描。**逐轮调用**是关键——配额与去重都是跨轮状态，
    一次性扫全部文本得到的答案与真实运行不同。"""
    led = _FakeLedger.__new__(_FakeLedger)       # 浅拷贝容器，不重跑 __init__
    led.__dict__.update(base.__dict__)
    led.candidates = dict(base.candidates)
    led.events = list(base.events)
    led._cand_seq = len(led.candidates)

    old = R.MENTION_GRACE_TURNS
    R.MENTION_GRACE_TURNS = grace
    all_findings = dict(led.findings)
    try:
        led.recall = R.RecallScanner(
            led.scope, max_mention=4, max_file=2, max_total=6,
            max_mention_total=total, max_file_total=6)
        for t in range(start, end + 1):
            # ★ 必须**按轮次**重建账本，而不是一上来就给它运行结束时的账本。
            # 曾经这里用的是终态账本，于是"白问"一列恒为 0——所有早期提名
            # 都被 `covers()` 用**后来才记的** finding 提前挡住了，看起来
            # 每条提名都"必需"。而真实运行里 finding 是逐步累积的：第 20 轮
            # 提名时它还没记，第 25 轮才补上，于是那条提名成了白问。
            # `recorded_at_turn` 把这层时间信息保留在账本里，用它。
            led.findings = {k: v for k, v in all_findings.items()
                            if int(getattr(v, "recorded_at_turn", 0) or 0) <= t}
            led.recall_scan(t)
    finally:
        R.MENTION_GRACE_TURNS = old
    led.findings = all_findings

    led._reap_stale(turn=end + 1)                # 收尾回收，统计"白问"的条数
    rec = [c for c in led.candidates.values()
           if getattr(c, "source", "") == "recall"]
    auto = [c for c in rec if "系统自动回收" in (c.reason or "")]
    need = [c for c in rec if c not in auto]
    v10 = [c for c in rec
           if c.file == V10_WINDOW[0] and V10_WINDOW[1] <= c.line <= V10_WINDOW[2]]
    return {"asked": len(rec), "wasted": len(auto), "need": len(need),
            "v10": len(v10), "v10_open": sum(1 for c in v10 if c.is_open)}


def main() -> int:
    cfg = Config.load(require_target())
    scope, _ = collect(cfg)

    # ★ 这里的默认值原先写死 ROOT/"out"/…。历史运行输出已按归档流程移入
    #   归档/02-旧版原型与历史验证/out/，该目录不再存在——而它当时的实际表现是
    #   「退出码 0，打一张空表」，把「找不到账本」伪装成了「账本里什么都没有」。
    #   静默降级正是这套工具最该拒绝的行为，所以改成要求显式给出目录。
    dirs = [Path(a) for a in sys.argv[1:]]
    if not dirs:
        print("用法：python tests/_tune_recall.py <账本目录> [更多目录 ...]")
        print("说明：本脚本在已有的真实账本上离线重放，不调用模型。")
        print("      历史账本在工作区 归档/02-旧版原型与历史验证/out/ 下（随交付包不发布）。")
        return 2
    books = []
    for d in dirs:
        p = (d if d.is_absolute() else ROOT / d) / "ledger.json"
        if not p.exists():
            continue
        # 起始轮：用该次运行实际第一次产出线索的轮次（`recall_after_ratio`
        # 在真实运行里的落点），这样重放的起点与当时一致。
        raw = json.loads(p.read_text(encoding="utf-8"))
        flagged = [int(e.get("turn") or 0) for e in raw.get("events") or []
                   if e.get("kind") == "recall_flagged"]
        end = max((int(e.get("turn") or 0) for e in raw.get("events") or []),
                  default=40)
        start = min(flagged) if flagged else max(1, end // 2)
        books.append((p.parent.name, _clean(p, scope, cfg), start, end))
        print(f"  载入 {p.parent.name}：起始轮 {start}，总轮次 {end}")

    print("=" * 74)
    print("配额口径：**同时待处置量**（回收即释放，引擎当前的实现）")
    print("=" * 74)
    print(f"{'冷静期':>6} {'配额':>5} | " +
          " | ".join(f"{n[:10]:>10}" for n, _, _, _ in books) + " |   合计")
    print(f"{'':>6} {'':>5} | " + " | ".join(
        f"{'问/废/必':>12}" for _ in books) + " |")

    best = []
    for grace, total in product(GRACES, TOTALS):
        row, tw = [], {"asked": 0, "wasted": 0, "need": 0, "v10": 0}
        for _name, led, start, end in books:
            r = _replay(led, grace, total, start, end)
            for k in tw:
                tw[k] += r[k]
            row.append(f"{r['asked']:>3}/{r['wasted']:>3}/{r['need']:>3}"
                       + ("★" if r["v10"] else " "))
        best.append((tw["need"], -tw["wasted"], tw["v10"], grace, total, row))
        print(f"{grace:>6} {total:>5} | " + " | ".join(row) +
              f" | 必{tw['need']} 废{tw['wasted']}")

    best.sort(key=lambda x: (-x[2], -x[0], -x[1]))
    print("  ★ 优先看：捞到 V10 的组合（那是本次实验要解释的对象）")
    for need, nw, v10, grace, total, _row in best:
        if v10:
            print(f"     冷静期 {grace} 配额 {total}：必需 {need} 条、"
                  f"白问 {-nw} 条、V10 ✅")

    print("\n『问/废/必』= 提名条数 / 其中被自动回收 / 其中需模型自己表态")
    print("★ = 该组合捞到了 V10 窗口（105±25）内的位置")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
