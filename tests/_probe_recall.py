#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""对账扫描器在**两次真实运行的账本**上的回放。

存在的理由：这套判据（危险词、行容差、冷静期）全都可以调，而调参的
唯一正当依据是"它在真实轨迹上捞出了什么"。拿已知的漏报当靶子——
若它捞不出 V9/V10/V11，那它就是一段好看的废代码；
若它把 34 条引擎候选全捞一遍，那它会烧光预算。

用法：
    python tests/_probe_recall.py out/real-final out/real-full
"""
from __future__ import annotations

import json
import sys
from dataclasses import fields, is_dataclass
from enum import Enum
from pathlib import Path
from typing import get_type_hints

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from engine.util import force_utf8
force_utf8()

from engine.collect import collect
from engine.agent import recall
from engine.agent.ledger import Candidate, Ledger as _Ledger
from engine.config import Config
from engine.schema import CoverageEntry, Finding

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))   # -I 隐含 -P：脚本自身目录不在 sys.path
from _target import require_target

TARGET = require_target()

# 基准真值里"两次运行都没捞到"的位置，用来检验扫描器能不能看见它们
PROBE = {
    "lib/ylinux_xmlrpc.py": [60, 105],
    "app/account/views.py": [38],
    "settings.py": [18, 79, 162, 164],
}


def _cv(v, t):
    """按**类型标注**把 JSON 里的值还原成真对象（枚举、嵌套 dataclass、枚举列表）。"""
    for o in (t if isinstance(t, tuple) else [t]):
        if isinstance(o, type) and issubclass(o, Enum):
            try:
                return o(v)
            except ValueError:
                return v                   # 旧账本里可能有已废弃的取值
        if isinstance(o, type) and is_dataclass(o) and isinstance(v, dict):
            return _real(o, v)
    origin, args = getattr(t, "__origin__", None), getattr(t, "__args__", ())
    if origin is list and args and v:
        inner = args[0]
        if isinstance(inner, type) and issubclass(inner, Enum):
            return [_cv(x, inner) for x in v]
    return v


def _real(cls, d: dict):
    """用**真实的 dataclass** 还原一条记录，而不是手写一个 duck-type 假对象。

    ★ 假对象这条路已经连着炸了三次，而且每次都是同一个原因：
    字段表是**人工同步**的。

        `_F.id`            ← `Accounted.by_file` 要用它写回收理由
        `_Cand.is_open`    ← `_reap_stale` 走 `open_candidates`
        `_Cand.rule`       ← `_reap_stale` 要按 mention/file 分流

    三次都是引擎先改完、回放时才炸。而这是**幸运**的那一半——假对象
    多一个真对象没有的字段不会报错，那时回放跑的就不是真实路径了，
    绿得毫无意义（这个文件开头记着同一类事故：假账本测的是判据、
    测不到接线）。用 `dataclasses` 构造，字段永远与引擎同源。
    """
    hints = get_type_hints(cls)
    return cls(**{f.name: _cv(d[f.name], hints.get(f.name))
                  for f in fields(cls) if f.name in d})


class _FakeLedger(_Ledger):
    """把旧账本灌进**真实的 Ledger**，只换掉数据、不换代码。

    ★ 为什么要继承真实的 Ledger，而不是自己 duck-type 一个：
    曾经这里是纯 duck-type 的假账本，回放全绿——而真实路径上
    `recall_scan` 一调用就抛 TypeError（`log(kind, **kw)` 与 `kind=it["kind"]`
    撞名），异常被 `run()` 的兜底 except 吞成 loop_error。
    **假账本测的是判据，测不到接线。** 判据再准，接不上就是零。
    现在回放走 `Ledger.recall_scan` 全路径：add_candidate、log、Accounted 都真跑。

    记录本身也一律用真 dataclass 还原（`_real`），理由见那里。
    """

    def __init__(self, d: dict, scope, cfg) -> None:
        super().__init__(scope, cfg)
        self.events = list(d["events"])
        self.findings = {f["id"]: _real(Finding, f) for f in d["findings"]}
        self.coverage = {c["coverage_class"]: _real(CoverageEntry, c)
                         for c in d["coverage"]}
        self.candidates = {c["id"]: _real(Candidate, c) for c in d["candidates"]}
        self.reviewed = {k: [tuple(x) for x in v] for k, v in d["reviewed"].items()}
        self._cand_seq = len(self.candidates)      # 新候选 id 不与旧账本撞车


def main() -> int:
    cfg = Config.load(TARGET)
    scope, _ = collect(cfg)
    print(f"范围：{len(scope.in_scope)} 个在审文件\n")

    bad = 0
    for out in sys.argv[1:]:
        p = ROOT / out / "ledger.json"
        led = _FakeLedger(json.loads(p.read_text(encoding="utf-8")), scope, cfg)

        print("=" * 72)
        print(f"{out}")

        last_turn = max((int(e.get("turn") or 0) for e in led.events), default=0)
        # ★ 走**真实**的 Ledger.recall_scan，而不是直接调扫描器。
        # 接线（add_candidate / log / 事件流）坏掉时，这里必须炸出来而不是静默。
        before = len(led.candidates)
        before_events = len(led.events)
        # 账本里**已经提过**的位置。★ 回放是"空账本重扫"——扫描器的
        # `_emitted`（问过哪些位置）和全局配额计数都只活在内存里，回放时
        # 是空的。当前这**不是缺陷**：引擎没有从账本续跑的路径，账本从不
        # 在运行中被重新加载。但它决定了这段输出怎么读——
        #   · "空账本重扫能捞出什么"  → 判据校准，本脚本的用途
        #   · "当时会被问几次"        → **不能**用这里的数字，它偏多
        # 分开报，免得下一个人拿着偏多的数字去调配额。
        _key = lambda c: (f"F|{c.file}" if c.rule == "file"      # noqa: E731
                          else f"M|{c.file}|{c.line}")
        prior = {_key(c) for c in led.candidates.values()
                 if c.source == "recall"}
        try:
            got = led.recall_scan(last_turn)
        except Exception as e:                       # noqa: BLE001
            bad += 1
            print(f"  ❌ recall_scan 抛异常（接线断了）：{type(e).__name__}: {e}")
            continue

        sc = led.recall
        print(f"  抽取到 {sc.stats['mentions']} 条危险提及，"
              f"涉及 {sc.stats['files_mentioned']} 个文件")

        # 全部提及按位置统计（不限冷静期），看抽得准不准
        from collections import Counter
        top = Counter(f"{r['file']}:{r['line']}" for r in sc._mentions)
        print(f"  提及最多的位置：{top.most_common(8)}")

        dup_prior = [c for c in got if _key(c) in prior]
        print(f"  账本已有线索 {len(prior)} 条；空账本重扫产出 {len(got)} 条"
              f"（候选 {before} → {len(led.candidates)}），"
              f"其中 {len(dup_prior)} 条与账面位置重合"
              f"{'（读取产出数时请扣掉）' if dup_prior else ''}：")
        for c in got:
            mark = "↺重提 " if _key(c) in prior else "  "
            print(f"   {mark}[{c.rule}] {c.file}:{c.line} — {c.message}")

        # 只数**本次回放新增**的事件：账本里原本就有的 recall_flagged 是
        # 上一次真实运行留下的，把它算进来会让这条检查恒不通过。
        flagged = [e for e in led.events[before_events:]
                   if e.get("kind") == "recall_flagged"]
        if len(flagged) != len(got):
            bad += 1
            print(f"  ❌ 事件流缺记录：产出 {len(got)} 条，"
                  f"新增 recall_flagged 只有 {len(flagged)} 条")
        else:
            print(f"  ✅ 事件流已记录 {len(flagged)} 条 recall_flagged（可审计）")

        # —— 靶子检验：漏报的位置有没有被看见
        hits = {c.file for c in got}
        for rel, lines in PROBE.items():
            if rel not in scope.files:
                continue
            men = sorted({r["line"] for r in sc._mentions if r["file"] == rel})
            mark = "✅命中" if set(lines) & set(men) else ""
            file_level = "（文件级回访 ✅）" if rel in hits else ""
            print(f"  · 真值 {rel}: {lines} → 提及行号 {men[:12]} {mark}{file_level}")

        # —— 过时线索的自动回收（`_reap_stale`，在 recall_scan 开头执行）
        # 这批旧账本是**修复前**跑的，里面的线索从没被回收过；回放走真实
        # 路径时才第一次跑这一步。所以这里看到的正是"当时如果有它，
        # 会回收掉哪些、留下哪些"——留下的那些，就是真该追问的。
        reaped = [c for c in led.candidates.values()
                  if c.source == "recall" and c.status == "dismissed"
                  and "系统自动回收" in (c.reason or "")]
        rec_all = [c for c in led.candidates.values() if c.source == "recall"]
        open_after = [c for c in rec_all if c.is_open]
        if reaped:
            print(f"  ♻️ 过时线索自动回收 {len(reaped)} 条"
                  f"；回收后仍未处置 {len(open_after)} 条")
            for c in reaped:
                print(f"     {c.file}:{c.line} [{c.rule}] "
                      f"{c.reason.split('——')[0].strip()}")
            for c in open_after:
                print(f"     ⬜ 仍须模型表态 {c.file}:{c.line} [{c.rule}]")
            # ★ 回收是系统**替模型**下的结论。理由必须能独立核对——读者要能
            # 顺着 finding id 自己去看那条结论是否真的覆盖了这个位置。
            # 只写"已覆盖"等于让读者信我，那不是账本该有的东西。
            vague = [c for c in reaped if "F-" not in (c.reason or "")]
            if vague:
                bad += 1
                print(f"  ❌ {len(vague)} 条回收理由没写明依据哪条 finding")
            else:
                print("  ✅ 每条回收理由都写明了覆盖它的 finding（可独立核对）")
        if reaped and not [e for e in led.events if e.get("kind") == "recall_reaped"]:
            bad += 1
            print("  ❌ 回收没有记进事件流（隐式行为）")
    print()
    print("回放本身" + ("✅ 全部通过" if not bad else f"❌ {bad} 项异常"))
    return 1 if bad else 0


def _ratio(led, scope):
    """从 reviewed 重算读过的行占比（与 Ledger.coverage_of_file 同义）。"""
    def f(rel):
        fi = scope.get(rel)
        if fi is None or fi.lines <= 0:
            return 0.0
        n = sum(e - s + 1 for (s, e) in led.reviewed.get(fi.rel, []))
        return min(1.0, n / fi.lines)
    return f


if __name__ == "__main__":
    raise SystemExit(main())
