#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""真实运行的产物核对（验收报告 §六-8 的可执行版本）。

存在的理由：§六-8 列了一份"下一次真实运行的核对清单"，但它是**写给人看的**。
手工翻五份产物找五个数字，做一次可以，做第二次就会漏——而这份清单要盯的
恰恰是**沉默型缺陷**：报告里没写的、写错一个数的、两种上限并存的。
这类缺陷不会让人皱眉头，只会让人少看到一条该看到的东西。

所以把它变成脚本：每次真实运行后跑一遍，对着 red 行看。

用法：
    python tests/_check_reports.py out/real-recall out/real-final out/real-full

判据分两级：
  · **H 硬性**——不过就是缺陷（外发量自相矛盾、快照全空、指纹缺失）
  · **· 观察项**——只报数，不下结论（截断频次、上限对照、真值命中）
    · 观察项不是不重要，是"多少算多"还需要人来判；脚本只保证**不漏看**。

★ **跑历史产物会看到一批红行，那是预期的，不是脚本坏了。**
`out/real-*` 是**冻结的证据**，记录的是修好之前那一版代码的行为——它们
**不应该**被改写成绿色（改了就毁掉了"缺陷真的发生过"这个事实）。
所以本脚本的正确用法是：**每次真实运行后，拿最新那一个目录跑**。
把全部历史一起跑只在一种情况下有意义——统计"这些缺陷各影响过几次运行"。
"""
from __future__ import annotations

import json
import re
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from engine.util import force_utf8
force_utf8()

ROOT = Path(__file__).resolve().parent.parent

# 人工已复核的真值漏报（验收报告 §3.2）。三次运行都没捞到的三条，
# 是本项目的**核心指标**——对账机制的全部意义就是让它们不再消失。
#
# ★ 坐标与窗口**从真值文件读**，不在这里手抄一份。
# 手抄版曾经是 V9 容差 15 / V10 容差 12 / V11 容差 14（真值分别是 12/25/25，
# 全是我自己拍的），实测后果：`V11 app/account/views.py:38` 在本脚本里判
# ❌ 未落账，而 `tests/score.py` 判 ✅ 落账（F-003 记在 :58，落在真值
# 38+25 的窗口内）。**同一条真值、两个脚本、相反的结论**，读报告的人
# 无从判断该信哪个。手工同步的副本一定会漂移——那次是回放假对象缺字段，
# 这次是坐标副本缺窗口，属于同一个失效模式。
def _load_truth(ids: tuple[str, ...] = ("V9", "V10", "V11")) -> list[dict]:
    d = json.loads((ROOT / "tests" / "ground_truth" / "ylinux.json")
                   .read_text(encoding="utf-8"))
    found: dict[str, dict] = {}

    def walk(o) -> None:
        if isinstance(o, dict):
            if o.get("id") in ids and "file" in o:
                found[str(o["id"])] = o
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)

    walk(d)
    missing = [i for i in ids if i not in found]
    if missing:
        raise SystemExit(f"真值文件里找不到 {missing}——基准被动过了？")
    return [found[i] for i in ids]


TRUTH = _load_truth()

sys.path.insert(0, str(Path(__file__).resolve().parent))   # -I 隐含 -P：脚本自身目录不在 sys.path
from _target import require_target

TARGET = require_target()

# 快照行号前缀（tools._fill_snippet）：右对齐 5 位 + " | "
SNAPSHOT_LINE = re.compile(r"^\s*\d+ \| ", re.M)
SNAP_ROW = re.compile(r"^\s*(\d+) \| (.*)$", re.M)


def snapshot_faults(finding: dict, repo: Path) -> list[str]:
    """核对一条快照是不是**磁盘原文**。返回问题列表（空 = 干净）。

    ★ 只验"有没有行号"会被拼出来的片段骗过。实测（real-quota）：

      · F-010/F-011 的 "snippet" 是模型的**笔记**，没有行号 —— 格式检查能抓到；
      · F-008 的 "snippet" 是**拼的**：「18 | DEBUG = True」与「49 |
        DATABASE_PASSWORD = ...」之间夹着 `...`，**每一行都对得上磁盘**，
        但两行之间隔着 30 行 —— 格式检查抓不到，还给了绿勾。

    所以这里做两件事：**行号连续**、**内容逐字一致**。快照的用途是让读者
    不打开文件也能核对指控，一段拼接出来的"原文"恰好把这件事变成假的：
    它看起来核过了。
    """
    ev = finding.get("evidence") or {}
    s = ev.get("snippet") or ""
    loc = finding.get("location") or {}
    rel = (loc.get("file") or "").replace("\\", "/")
    if not s.strip() or not rel:
        return []
    rows = SNAP_ROW.findall(s)
    if not rows:
        return ["没有行号，无法核对来源"]
    nums = [int(n) for n, _ in rows]
    faults: list[str] = []
    if nums != list(range(nums[0], nums[0] + len(nums))):
        faults.append(f"行号不连续（{nums[0]}…{nums[-1]} 共 {len(nums)} 行）")
    try:
        lines = (repo / rel).read_text(encoding="utf-8",
                                       errors="replace").splitlines()
    except OSError:
        return faults + ["读不到磁盘上的该文件"]
    mism = [n for n, c in zip(nums, (c for _, c in rows))
            if not (1 <= n <= len(lines)) or lines[n - 1].rstrip() != c.rstrip()]
    if mism:
        faults.append(f"{len(mism)} 行与磁盘不符（行号 {mism[:4]}）")
    return faults
SENT_RE = re.compile(r"\*\*累计发送 ([\d,]+) tokens\*\*")
# 7.5 的分解式："= 输入 X + 缓存读 Y + 缓存写 Z"
SENT_DECOMP_RE = re.compile(
    r"=\s*输入 ([\d,]+)\s*\+\s*缓存读 ([\d,]+)\s*\+\s*缓存写 ([\d,]+)")
TRUNC_MARK = "（记录被截断"

hard_bad = 0
note: list[str] = []


def h(label: str, cond: bool, detail: str = "") -> None:
    global hard_bad
    if not cond:
        hard_bad += 1
    print(f"    {'✅' if cond else '❌'} {label}" + (f"  {detail}" if detail else ""))


def o(label: str, detail: str) -> None:
    print(f"    ·  {label}  {detail}")


def _dist(turns: list[int]) -> str:
    """轮次列表 → 紧凑分布（`20×1 21×2 39×7`）。空列表给「无」。"""
    c = Counter(turns)
    return " ".join(f"{t}×{n}" for t, n in sorted(c.items())) or "无"


def load(out: Path) -> dict:
    d: dict = {"dir": out}
    for key, name in (("ledger", "ledger.json"),
                      ("report", "audit-report.json")):
        p = out / name
        d[key] = json.loads(p.read_text(encoding="utf-8")) if p.exists() else None
    p = out / "audit-report.md"
    d["md"] = p.read_text(encoding="utf-8") if p.exists() else ""
    return d


def in_range(findings, rel, line, tol) -> list:
    hit = []
    for f in findings:
        loc = f.get("location") or {}
        if loc.get("file") != rel:
            continue
        a = int(loc.get("line") or 0)
        b = int(loc.get("end_line") or a)
        if a - tol <= line <= b + tol:
            hit.append(f)
    return hit


def check_one(out: Path) -> None:
    d = load(out)
    led, rep, md = d["ledger"], d["report"], d["md"]
    print("=" * 74)
    print(f"{out.name}")
    print("=" * 74)

    if led is None or rep is None:
        h("产物齐备（ledger.json + audit-report.json）", False,
          f"ledger={'有' if led else '缺'} report={'有' if rep else '缺'}")
        return

    agent = rep.get("agent") or {}
    findings = rep.get("findings") or []
    cands = rep.get("candidates") or []

    # ---------------------------------------------- 1 usage 是否回报
    # ★ 这是 §六-8 说的"必须第一个确认的事"。real-final 的 input_tokens=0
    # 让"端点不回报"与"代码没接上"两种可能无法区分，整条外发量声明悬空。
    ti = agent.get("input_tokens") or 0
    to = agent.get("output_tokens") or 0
    o("usage", f"input={ti:,} output={to:,} "
               f"（{'端点已回报' if ti else '⚠️ 端点未回报，外发量只能声明未取得'}）")

    # ---------------------------------------------- 2 H1 外发量自洽
    # §六-8 第 10、14 项：real-final 里 7.5 显示 2,486、agent.input_tokens 是 0，
    # 同一份报告里两个数字互相矛盾。这是硬性缺陷，不是观察项。
    #
    # ★ 判据在 2026-09-19 收紧：原判据是 `7.5 >= input`——**它只查"不低报"**，
    # 于是刚好放过了一个真缺陷：7.5 写「累计发送 1,387,834 tokens
    # （输入 269,626 / 输出 60,424）」，括号两项相加 330,050，与总数差
    # 1,118,208。1,387,834 ≥ 269,626 成立，判绿，连过七次。
    # 现在要求**能还原**：总数必须等于各分项之和，且与 JSON 同源。
    m = SENT_RE.search(md)
    egress = rep.get("data_egress") or {}
    if ti:
        md_sent = int(m.group(1).replace(",", "")) if m else None
        # (a) 报告正文自称的构成必须能还原它自己的总数
        dec = SENT_DECOMP_RE.search(md)
        if dec:
            parts = [int(x.replace(",", "")) for x in dec.groups()]
            h("7.5 的分项相加 = 它自己报的总数（能还原，不只是不低报）",
              md_sent == sum(parts),
              f"{' + '.join(f'{p:,}' for p in parts)} = {sum(parts):,}"
              + ("" if md_sent == sum(parts)
                 else f" ≠ 总数 {md_sent:,}，差 {md_sent - sum(parts):,}"))
        else:
            # 旧格式（"（输入 X / 输出 Y）"）不是分解式——它列的是输出，
            # 而输出不计入外发。这种写法本身就是那条缺陷，判红并说明。
            h("7.5 的括号是分解式（而非「输入/输出」式）", False,
              "括号里放的是不计入外发的输出，读者无法据以核对总数")
        # (b) JSON 里必须有同一个数——否则合规数字只在正文里，无从核验
        if egress:
            h("JSON 的 data_egress 与 7.5 同源（数字不在两处各算一遍）",
              egress.get("tokens_sent_external") == md_sent,
              f"json={egress.get('tokens_sent_external'):,} "
              f"md={md_sent:,}" if md_sent else "md 无数字")
            h("JSON 自校验 reconstructs=true", bool(egress.get("reconstructs")),
              f"input={egress.get('input_tokens'):,} "
              f"cache_r={egress.get('cache_read_tokens'):,} "
              f"cache_w={egress.get('cache_write_tokens'):,}")
        else:
            h("JSON 里带得走外发量（data_egress）", False,
              "产物缺该字段——合规数字只在正文里，CI/看板读不到")
    else:
        h("拿不到 usage 时 7.5 明说未取得（而不是显示 0）",
          "未能取得发送量" in md and not m,
          "报告须把「没数」与「零」区分开")

    # ---------------------------------------------- 3 H2 源码快照带行号
    # §六-8 第 11 项：靶子上 7 条 finding 的 snippet 长度全为 0，
    # 报告里一行真实代码都没有——读者被告知"第 60 行有问题"却看不到第 60 行。
    with_snip = [f for f in findings
                 if (f.get("evidence") or {}).get("snippet", "").strip()]
    numbered = [f for f in with_snip
                if SNAPSHOT_LINE.search((f.get("evidence") or {})["snippet"])]
    if findings:
        h("finding 的源码快照已自动填充", len(with_snip) == len(findings),
          f"{len(with_snip)}/{len(findings)} 条有快照")
        if with_snip:
            h("快照带行号（读者可不打开文件核对指控）",
              len(numbered) == len(with_snip),
              f"{len(numbered)}/{len(with_snip)} 条带行号")
            h("报告正文里出现了这些快照",
              bool(SNAPSHOT_LINE.search(md)), "markdown 中可见")
            # ★ 上面两条只验**格式**，而格式是最容易装出来的东西。这条验来源：
            # 快照的每一行是不是磁盘上的原文、行号连不连续。见 snapshot_faults。
            flt = {f.get("id", "?"): snapshot_faults(f, TARGET) for f in with_snip}
            bad_snap = {k: v for k, v in flt.items() if v}
            h("每条快照都是磁盘原文（不是模型自述或拼接）", not bad_snap,
              "；".join(f"{k} {v[0]}" for k, v in bad_snap.items())
              if bad_snap else f"{len(with_snip)} 条逐字核对通过")
    else:
        o("源码快照", "本次无 finding，无快照可查")

    # ---------------------------------------------- 4 截断标注（观察）
    # §六-8 第 13 项：thinking 上限从 2000 提到 8000 后，还剩多少条撞顶。
    # 出现得多说明 8000 仍不够，该考虑收敛提示词而不是继续抬高上限。
    tr = agent.get("transcript") or []
    thinks = [e for e in tr if e.get("kind") == "thinking"]
    clipped = [e for e in thinks if TRUNC_MARK in (e.get("text") or "")]
    o("轨迹", f"{len(tr)} 条；thinking {len(thinks)} 条，"
              f"其中 {len(clipped)} 条撞上 8000 上限并已标注")
    if clipped:
        lens = sorted(len(e["text"]) for e in clipped)
        o("截断详情", f"长度 {lens[:6]}（标注本身约 22 字符）")

    # ---------------------------------------------- 5 两种上限并存（观察）
    # §六-8 第 4 条：缺口 7 未改动，tool.args 仍截断在 200。
    evs = led.get("events") or []
    tool_args = [len(e.get("args") or "") for e in evs if e.get("kind") == "tool"]
    th_text = [len(e.get("text") or "") for e in evs if e.get("kind") == "thinking"]
    o("账本上限", f"tool.args 最长 {max(tool_args, default=0)} 字符"
                  f"（{len(tool_args)} 次调用） / "
                  f"thinking 最长 {max(th_text, default=0)} 字符"
                  f"（{len(th_text)} 条）")

    # ---------------------------------------------- 6 H3 构建指纹
    # §六-8 第 9 条：A/B 对照应当带上产生它的构建标识，否则"同条件"只能靠嘴说。
    b = rep.get("build") or {}
    h("报告带构建指纹", bool(b.get("code_digest")),
      f"code_digest={str(b.get('code_digest'))[:16]} "
      f"({b.get('code_files', '?')} 文件)")
    h("指纹里有配置快照（改参数也要看得出来）",
      bool(b.get("config")), f"{len(b.get('config') or {})} 项")

    # ---------------------------------------------- 7 收敛对账（本轮新增）
    rec = [c for c in cands if c.get("source") == "recall"]
    rec_open = [c for c in rec if c.get("status") == "open"]
    dist: dict[str, int] = {}
    for c in rec:
        dist[c.get("status", "?")] = dist.get(c.get("status", "?"), 0) + 1
    o("收敛对账", f"线索 {len(rec)} 条（{dist or '无'}），未处置 {len(rec_open)} 条")
    # ★ 重复提名检测。这条是**被一次真实运行打出来的**：46 条线索里 40 条
    # 只来自 6 个文件（admin/views.py 18 次、wiki/views.py 17 次）。
    # 手工翻 JSON 才发现的事，不该再靠手工翻第二次——它不报错、不影响
    # 任何断言，只是让模型在最后一轮面对一份做不完的清单。
    dup = {f: n for f, n in Counter(c.get("file") for c in rec
                                    if c.get("rule") == "file").items() if n > 1}
    h("同一文件不被重复提名", not dup,
      f"重复：{dup}" if dup else "（无重复）")
    # 同上，A 类也不能重复：`M|文件|行` 的问过标记曾经只写不读（同一处
    # 每轮重新提名），这条盯的是它的另一条通道。
    dup_m = {k: n for k, n in Counter(
        f"{c.get('file')}:{c.get('line')}" for c in rec
        if c.get("rule") == "mention").items() if n > 1}
    h("同一位置不被重复提名（A 类）", not dup_m,
      f"重复：{dup_m}" if dup_m else "（无重复）")

    # ★ 过时线索的自动回收（`_reap_stale`）。回收是系统**替模型**下的结论，
    # 所以它的理由必须能独立核对——读者要能顺着 finding id 自己去看那条
    # 结论是否真的覆盖了这个位置。只写"已覆盖"等于让读者信我。
    reaped = [c for c in rec if "系统自动回收" in (c.get("reason") or "")]
    if reaped:
        vague = [c for c in reaped if "F-" not in (c.get("reason") or "")]
        o("自动回收", f"{len(reaped)} 条（{len(rec) - len(rec_open)} 条已处置中）")
        h("每条回收理由都写明了覆盖它的 finding", not vague,
          f"{len(vague)} 条含糊" if vague else "（可独立核对）")
        h("回收记进了事件流（不是隐式行为）",
          any(e.get("kind") == "recall_reaped" for e in evs))
        for c in reaped:
            o("", f"♻️ {c.get('file')}:{c.get('line')} — "
                  f"{(c.get('reason') or '').split('——')[0].strip()}")
    for c in rec:
        reason = (c.get("reason") or "").strip()
        why = (c.get("message") or "").strip()
        mark = {"confirmed": "✅确认", "dismissed": "🚫驳回",
                "deferred": "⏭️延后", "open": "⬜未处置"}.get(c.get("status"), "?")
        o("", f"{mark} {c.get('file')}:{c.get('line')} — {why[:80]}"
              + (f" → {reason[:70]}" if reason else ""))
    # 未处置的线索必须在报告里显眼，否则它只是从一个静默变成另一个静默
    if rec_open:
        h("未处置的线索在报告里被显式警告",
          "条对账线索未处置" in md, f"{len(rec_open)} 条")
    else:
        h("无未处置线索时报告不出现该警告", "条对账线索未处置" not in md)

    # ★ 配额语义（本轮改动）：从"累计提名量"改成"同时待处置量"——回收即释放。
    # 这个改动有一个**不必读引擎代码就能在账本上验证**的推论：提名总数会
    # 超过配额。旧实现 `_n_mention` 只增不减，提名数**永远 ≤ 配额**；新实现
    # 下回收一条腾一格，整场运行提名的总数可以远超它。
    # 之所以要在这里钉一下：真值 V10 没落账的病因就是配额被"反正马上会自行
    # 落账"的线索占着（real-reap 用掉的 6 条里 5 条随后被自动回收），而这个
    # 病不报错、不影响任何断言——只有把"释放确实发生过"变成一行可读的数，
    # 才不用靠人记得去翻。
    _cfgq = (rep.get("build") or {}).get("config") or {}
    _qm, _qf = _cfgq.get("recall_max_mention_total"), _cfgq.get("recall_max_file_total")
    if rec and _qm:
        _nm = len([c for c in rec if c.get("rule") == "mention"])
        _nf = len([c for c in rec if c.get("rule") == "file"])
        # ★ 判据取"总数 > 两类配额之和"，而不是"某一类 > 它自己的配额"。
        # 旧实现下 A ≤ 6 且 B ≤ 6，**总数不可能超过 12**——越界这件事在旧
        # 实现里是数学上做不到的，所以它是一个铁证。反之"某类超了自己的
        # 配额"只在那一类恰好提得够多时才成立，运气成分太大：分类各自接近
        # 上限、总数早已越界的情况会被它误判成"看不出"。
        _ok = _nm + _nf > (_qm + (_qf or _qm))
        o("配额语义", f"提名 A {_nm}（配额 {_qm}）/ B {_nf}（配额 {_qf}）"
                      f"，合计 {_nm + _nf} vs 上限 {_qm + (_qf or _qm)} → "
                      + ("回收即释放已生效（旧语义下总数不可能越界）" if _ok else
                         "⚠️ 总数未越界，看不出释放是否发生过"))

    # 处置与回收**发生在第几轮**？这是"随到随处置"那句话的唯一直观证据：
    # 处置若集中在最后一两轮，说明模型仍在攒，中间那段配额是满的——新语义
    # 就只兑现了一半（提名靠系统回收流动，不靠模型处置流动）。分散开才是
    # 提示词真的起了作用。回收轮次同理：它分散说明"提名→模型随后自己落账"
    # 是持续发生的，而不是最后一波。
    #
    # ★ 回收**也走 `dispose_candidate`**，所以 `candidate_disposed` 事件里
    # 混着两种东西。第一版这里直接数事件，把 real-reap 的 10 条系统回收
    # 全算成了"模型处置 12 条"——而实测是模型只处置了 2 条。
    # 区分依据只能是理由文本（`_reap_stale` 写的那句"系统自动回收"）。
    # 同理不按 `recall_reaped` 事件数回收条数：那是**批量**记的一条事件带
    # 多个 id，数事件会得到 4 而不是 10。
    _rec_ids = {c.get("id") for c in rec}
    _disp = [e for e in evs if e.get("kind") == "candidate_disposed"
             and e.get("id") in _rec_ids]
    _human = sorted(int(e.get("turn") or 0) for e in _disp
                    if "系统自动回收" not in (e.get("reason") or ""))
    _auto = sorted(int(e.get("turn") or 0) for e in _disp
                   if "系统自动回收" in (e.get("reason") or ""))
    if _disp:
        o("线索流动", f"模型处置 {len(_human)} 条 @轮次 {_dist(_human)}；"
                      f"系统回收 {len(_auto)} 条 @轮次 {_dist(_auto)}")

    # ---------------------------------------- 7b 收口状态与积压（决定读数可用性）
    # ★ 这两条必须放在真值命中之前，因为它们决定后面那些数字能不能用。
    # 做 real-quota 与 real-reap 的逐项对比时，我把它俩当成同等地位的两轮来读，
    # 直到发现 real-quota 的 `conclusion` 是**空的**、事件流末尾是
    # `budget_exhausted`——**那次从没 conclude**。一个预算耗尽而中断的运行和
    # 一个正常收敛的运行，召回率根本不该放在同一张表里比。
    _status = str(agent.get("status") or "?")
    _concl = led.get("conclusion") or {}
    if _concl and _status in ("concluded", "forced"):
        o("收口状态", f"✅ 已 conclude（{_status}）"
          + ("　⚠️ force=true 强制收口，报告里声明了未闭合项" if _status == "forced" else ""))
    else:
        o("收口状态", f"❌ **{_status}**——从未 conclude（`conclusion` 为空）。"
          + ("预算耗尽中断：" if _status == "budget_exhausted" else "")
          + "下文召回率是「没跑完的运行」的读数，与已收口的运行不可直接对比")

    _openall = [c for c in cands if c.get("status") == "open"]
    if cands:
        _by_src: dict[str, int] = {}
        for c in _openall:
            k = c.get("source") or "?"
            _by_src[k] = _by_src.get(k, 0) + 1
        # 有积压 vs 没积压，是两种不同的"没跑完"：前者是处置没跟上（real-quota：
        # 37/58 停在 open），后者只差最后一步（real-reap：46 条全处置完，只是
        # 没顾上 conclude）。分开说，读者才知道缺口在哪。
        o("候选积压", f"{len(_openall)}/{len(cands)} 条停在 open　{_by_src}"
          if _openall else
          f"0/{len(cands)} 积压（候选全部落终态——若有缺口，缺口在别处）")

    # 处置的**调用形态**：逐条发还是成组发。收口前几十条挤在一起逐条发，
    # 正是把输出撑爆的那件事——real-quota 打算一轮发 45 个 dispose_candidate，
    # 被长度上限截断，**一条都没发出去**。成组工具上线后这个比值应当翻转。
    _tools: dict[str, int] = {}
    for e in evs:
        if e.get("kind") == "tool":
            k = e.get("name") or "?"
            _tools[k] = _tools.get(k, 0) + 1
    _dc, _dcs = _tools.get("dispose_candidate", 0), _tools.get("dispose_candidates", 0)
    if _dc or _dcs:
        # ★ 只数**模型自己处置**的候选。系统回收（`_reap_stale`）也写
        # `candidate_disposed`，把它算进来会让读数虚高——real-group 实测：
        # 已处置 56 条里 11 条是系统回收的，模型真正处置的是 45 条。
        # （判据用理由里的标记；账本没有单独的字段，这是当前能拿到的最硬的东西。）
        _model_ids = {e.get("id") for e in evs
                      if e.get("kind") == "candidate_disposed"
                      and "系统自动回收" not in (e.get("reason") or "")}
        # ★ **成组的单元是"组"不是"条"。** 一次 `dispose_candidates` 调用的
        # `items` 是数组，每一组各有一个理由——所以"条数 ÷ 调用次数"是个会
        # 骗人的指标：real-group 那次 1 个调用处置 45 条，读作"平均每次 45 条"
        # 像是一把梭，而实际是 **19 组**、每组条数 [10,5,3,3,3,3,2×5,1×9]，
        # 9 个单条组恰好证明它没有为了凑数硬塞。**同一理由即同一组**，这是
        # `dispose_candidates` 的语义本身，可以直接聚合出真实组数。
        _groups: dict[str, list[str]] = {}
        for e in evs:
            if (e.get("kind") == "candidate_disposed"
                    and "系统自动回收" not in (e.get("reason") or "")):
                _groups.setdefault((e.get("reason") or "").strip(), []).append(
                    e.get("id") or "?")
        _gsz = sorted((len(v) for v in _groups.values()), reverse=True)
        _glen = sorted(len(k) for k in _groups) or [0]
        o("处置形态", f"逐条 {_dc} 次 / 成组 {_dcs} 次"
          + (f"；模型处置 {len(_model_ids)} 条 → **{len(_groups)} 组**"
             f"（每组条数 {_gsz[:7]}{'…' if len(_gsz) > 7 else ''}）"
             if _dcs else "　⚠️ 全程逐条——尚未用上成组工具"))
        if _groups:
            o("成组理由", f"{len(_groups)} 组，理由长度 最短 {_glen[0]} / "
                          f"中位 {_glen[len(_glen) // 2]} / 最长 {_glen[-1]} 字符"
              + ("　⚠️ 有理由短于 40 字符——成组时一句话要盖住整组位置，"
                 "太短就意味着这句话没法被独立核对" if _glen[0] < 40
                 else "　（每组理由都需能被独立读懂）"))
            # **一把梭的判据不是"组多大"，而是"理由还点不点得住它盖住的位置"。**
            # 所以这里不替读者判"多大算大"（那取决于代码本身），只把最大的一组
            # 原样摆出来——让人自己看那句理由是否配得上它的覆盖面。
            _big = max(_groups.items(), key=lambda kv: len(kv[1]))
            if len(_big[1]) >= 5:
                o("最大一组", f"{len(_big[1])} 条共用一个 {len(_big[0])} 字符的理由"
                  f"（{_big[1][0]}…{_big[1][-1]}）：{_big[0][:104]}…")
        _auto_n = len(cands) - len(_openall) - len(_model_ids)
        if _auto_n > 0:
            o("系统回收", f"{_auto_n} 条由 `_reap_stale` 回收，**不计入上面的"
                          f"模型处置数**——理由不是模型写的，是引擎按\"该位置"
                          f"随后已被 finding 覆盖\"判定的")
    o("候选查询", f"list_candidates 调用 {_tools.get('list_candidates', 0)} 次"
                  + ("（反复查清单通常意味着模型在找下手方式而没找到）"
                     if _tools.get("list_candidates", 0) >= 8 else ""))

    # ---------------------------------------------- 8 真值命中（终局指标）
    # 判据与 `tests/score.py` 一致：行号落在真值 `line .. line+window` 内。
    # 两个脚本必须用同一把尺子，否则同一条真值会出现相反的结论。
    print("    —— 真值漏报（人工已复核的三条，坐标与窗口取自真值文件）——")
    for it in TRUTH:
        rel, line = it["file"], int(it["line"])
        tol = int(it.get("window") or 25)
        hit = in_range(findings, rel, line, tol)
        rec_hit = [c for c in rec if c.get("file") == rel]
        rec_done = [c for c in rec_hit if c.get("status") in
                    ("confirmed", "dismissed", "deferred")]
        state = ("✅ 落账 " + ",".join(f.get("id", "?") for f in hit)) if hit else "❌ 未落账"
        extra = (f"；对账线索 {len(rec_hit)} 条"
                 f"（已处置 {len(rec_done)}）") if rec_hit else ""
        o(f"{it['id']} {rel}:{line}±{tol}", f"{state}{extra}  {it.get('title', '')}")

    print()


def main() -> int:
    dirs = [Path(a) for a in sys.argv[1:]]
    if not dirs:
        print(__doc__)
        return 2
    for out in dirs:
        if not out.is_absolute():
            out = ROOT / out
        if not out.is_dir():
            print(f"❌ 目录不存在：{out}")
            continue
        check_one(out)

    # 跨运行可比性：代码指纹不同的两次运行，报告长得再像也不可对照
    digs = {}
    for out in dirs:
        p = (out if out.is_absolute() else ROOT / out) / "audit-report.json"
        if p.exists():
            digs[out.name] = (json.loads(p.read_text(encoding="utf-8"))
                              .get("build") or {}).get("code_digest")
    if len(digs) > 1:
        print("=" * 74)
        print("跨运行可比性")
        print("=" * 74)
        for k, v in digs.items():
            print(f"  {k:16s} {v}")
        uniq = {v for v in digs.values() if v}
        # ★ 缺失不能被当成相同。这里原本是 `uniq = {... if v}` 然后只看
        # `len(uniq)`——于是"一个运行有指纹、另一个没有"被判成"✅ 一致"
        # （None 被过滤掉，剩下的恰好只有一个值）。这正是本项目反复出现的
        # 那个失效模式换了个位置：**把"没数"读成了"相同"**。
        # 没有指纹的运行产生于指纹机制上线之前，它不是"同条件"，是"不可知"。
        missing = [k for k, v in digs.items() if not v]
        if missing:
            print(f"\n  ⚠️ {len(missing)} 个运行**没有构建指纹**：{', '.join(missing)}"
                  "\n     它们产生于指纹机制上线之前，**无法确认与其它运行可比**——"
                  "\n     不要因为它们跑出相似的数字，就把它们当作同条件对照。")
        elif len(uniq) > 1:
            print(f"\n  ⚠️ 代码指纹不同（{len(uniq)} 种）——这些运行**不可直接对照**。"
                  "报告长得像不代表条件相同。")
        elif uniq:
            print("\n  ✅ 代码指纹一致，可对照。")
    print()
    print("硬性核对：" + ("✅ 全部通过" if not hard_bad else f"❌ {hard_bad} 项不通过"))
    return 1 if hard_bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
