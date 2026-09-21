#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""两条核心要求的可执行判据。

存在的理由：要求是**结构性的**——

    1. 具备真正的 Tool Calling 结构，即由模型自主决定调用哪些工具、
       以什么顺序调用，而不是固定顺序的脚本串联或一次性的 prompt 拼接。
    2. 能完成一个完整闭环，即从开始分析到给出最终结论之间的各个环节
       可以自动串起来。

——而验收报告里曾经用**效果指标**（召回率、误报数、收口次数）去回答它们。
那是两把尺子量错对象：效果差可以是"机制成立、效果不好"，机制不成立才是
没满足要求。反过来，一个固定顺序的脚本串联也能跑出高召回。**两者不可互证。**

所以这份脚本只测结构，不测效果。

用法：
    python tests/_check_requirements.py out/ctl-a out/ctl-b

★ **判据 A 需要两个运行目录。** 只给一个时它报"待判"，不是失败——
  单次运行的序列不与任何东西可比，"是否重复"这个问题在单次运行上无意义。

判据一览（每条都写明它**为什么能证伪**）：

  要求 1 —— 谁在决定
    A  跨运行序列**不相同**      脚本串联 => 序列必然逐字重复，相同即证伪
    B  工具失败后**改变做法**    "自主"的定义。脚本收到错误只会原样重试
    C  工具面**真实约束**        未注册的工具名也被接受 => "调用工具"是装饰

  要求 2 —— 是否自动串联
    D  链路**完整**              五阶段产物齐备，无缺环、无人工断点
    E  结论**落盘**              至少一次到达最终结论，且结论真的写进产物
    F  收口**由账本判定**        候选未处置完却 concluded => 收口是宣布的，不是判定的

★ 已知的判据边界（写在这里，免得读的人高估结论）：
  · B 的"同参数"用的是账本里的 `args`，而账本按 200 字符裁剪（`loop._brief`）。
    两个不同的长参数可能裁成同一个前缀，被判成"未改变"。**偏差方向是低估
    自主性**，不会把脚本误判成自主——所以它作为证伪判据是安全的。
  · F 只能检查"已收口的运行候选是否清零"。它证伪不了"账本被绕过"，
    只证伪得了"收口与账本状态矛盾"。
"""
from __future__ import annotations

import difflib
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from engine.util import force_utf8
force_utf8()

ROOT = Path(__file__).resolve().parent.parent

# 分析类工具与记账类工具。预算去向是个观察项——它回答"为什么没跑完"，
# 不直接判定任何一条要求，但读者一定会问，所以顺手算出来。
ANALYZE = {"read_code", "search_code", "outline", "list_files",
           "get_entry_points", "list_candidates"}
BOOK = {"dispose_candidate", "dispose_candidates", "set_coverage",
        "record_finding", "adversarial_verify", "check_vendored"}

FAILS: list[str] = []


def head(title: str) -> None:
    print()
    print("=" * 78)
    print(title)
    print("=" * 78)


def check(hard: bool, label: str, detail: str = "") -> None:
    icon = "✅" if hard else "❌"
    if not hard:
        FAILS.append(label)
    print(f"  {icon} {label}")
    if detail:
        for line in detail.splitlines():
            print(f"      {line}")


def note(label: str, detail: str = "") -> None:
    """观察项：只报数，不下结论。"""
    print(f"  · {label}")
    if detail:
        for line in detail.splitlines():
            print(f"      {line}")


# ---------------------------------------------------------------- 读取

def load(run: Path) -> dict:
    """读一份运行的产物。缺文件不是崩溃，是证据本身。"""
    out: dict = {"dir": run, "ok": True, "missing": []}
    for name, key in (("ledger.json", "ledger"),
                      ("audit-report.json", "json"),
                      ("audit-report.md", "md")):
        p = run / name
        if not p.exists():
            out["missing"].append(name)
            out["ok"] = False
            continue
        if name.endswith(".json"):
            out[key] = json.loads(p.read_text(encoding="utf-8"))
        else:
            out[key] = p.read_text(encoding="utf-8", errors="replace")
    led = out.get("ledger")
    if isinstance(led, dict):
        out["events"] = led.get("events") or []
    elif isinstance(led, list):
        out["events"] = led
    else:
        out["events"] = []
    out["tools"] = [e for e in out["events"] if e.get("kind") == "tool"]
    out["seq"] = [e.get("name") for e in out["tools"]]
    out["fingerprint"] = ((out.get("json") or {}).get("build") or {}).get(
        "code_digest", "—")
    return out


# ---------------------------------------------------------------- 要求 1

def check_requirement_1(runs: list[dict]) -> None:
    head("要求 1 —— 真正的 Tool Calling 结构（谁在决定）")

    # ---- A：跨运行序列不相同
    if len(runs) < 2:
        note("A 跨运行序列不相同 —— **待判**（只给了一个运行目录）",
             "判据 A 问的是「序列是否会重复」，单次运行的序列\n"
             "不与任何东西可比。退出时用两个目录再跑。")
    else:
        pairs = []
        for i in range(len(runs)):
            for j in range(i + 1, len(runs)):
                a, b = runs[i], runs[j]
                if not a["seq"] or not b["seq"]:
                    continue
                r = difflib.SequenceMatcher(None, a["seq"], b["seq"]).ratio()
                pairs.append((a, b, r))
        if not pairs:
            note("A 跨运行序列不相同 —— 可比的运行对为空")
        else:
            same = [p for p in pairs if p[2] >= 0.999]
            worst = max(p[2] for p in pairs)
            best = min(p[2] for p in pairs)
            same_fp = [p for p in pairs
                       if p[0]["fingerprint"] == p[1]["fingerprint"]
                       and p[0]["fingerprint"] != "—"]
            fps = {r["fingerprint"] for r in runs if r["fingerprint"] != "—"}
            detail = (f"可比的运行对 {len(pairs)} 组，"
                      f"相似度 {best*100:.1f}%–{worst*100:.1f}%。")
            if same_fp:
                r = same_fp[0][2]
                detail += (f"\n其中**同构建**（{same_fp[0][0]['fingerprint']}）"
                           f"那一对是 {r*100:.1f}%——这一对不受构建差异干扰，"
                           f"是本判据最干净的证据。")
            elif len(fps) > 1:
                # 构建真的不同。这时的序列差异**混了两件事**，不能说清是哪件。
                detail += (f"\n⚠️ 这些运行跨了 {len(fps)} 个构建"
                           f"（{sorted(fps)}），序列差异有一部分可能来自"
                           "提示词或工具集变动，**不是纯的自主性证据**。\n"
                           "   要做干净判定，请在同一构建上连跑两次。")
            elif len(pairs) == 1 and any(r["fingerprint"] == "—"
                                         for r in runs):
                # 少见的第三种情况：构建其实是同一个（或只有一个），
                # 但有一方**没有指纹字段**（旧构建早于指纹功能上线）。
                # 把它说成"跨多个构建"是错的——那会把读者的注意力
                # 引到不存在的问题上。
                detail += ("\n⚠️ 无法确认是否同构建：有一方产物里**没有指纹"
                           "字段**（早于该功能上线的旧构建）。\n"
                           "   这里只能确认『序列不相同』，不能确认"
                           "『同条件下仍不相同』。")
            else:
                detail += "\n（未识别出同构建的运行对。）"
            check(not same, "A 跨运行序列不相同（脚本串联会逐字重复）", detail)

    # ---- B：工具失败后改变做法
    #
    # ★ "改了做法"有两种，必须分开报，因为它们的说服力不同：
    #   · **换工具**——失败后改调另一个工具。最直观。
    #   · **同工具换参数**——比如 record_finding 发出一个空调用被拒，
    #     下一次用同一个工具补全了字段。**这才是实测里最常见的形态**
    #     （模型自己在思考里写 "the previous attempt dropped because I
    #     emitted an empty call"），而它比"换工具"更能说明问题：
    #     模型不是绕开障碍，是**修正了自己**。
    # 曾经把两者混成一句"改做 X"，当 X 恰好等于原工具时读起来自相矛盾。
    changed_tool = changed_args = unchanged = orphan = 0
    ex_tool: list[str] = []
    ex_args: list[str] = []
    for r in runs:
        fails = [e for e in r["tools"] if not e.get("ok")]
        for f in fails:
            t = f.get("turn") or 0
            nxt = next((e for e in r["tools"] if (e.get("turn") or 0) > t), None)
            if nxt is None:
                orphan += 1
                continue
            if nxt.get("name") != f.get("name"):
                changed_tool += 1
                if len(ex_tool) < 2:
                    ex_tool.append(f"{r['dir'].name} 第 {t} 轮："
                                   f"{f.get('name')} 失败 → 改用 {nxt.get('name')}")
            elif nxt.get("args") != f.get("args"):
                changed_args += 1
                if len(ex_args) < 3:
                    # ★ 只陈述**观察到的事实**：两次的参数不同。
                    # 不断言"补全了"——参数在账本里按 200 字符裁剪，
                    # 我只知道它们不同，不知道第二次是不是更完整。
                    # （唯一的例外是空调用：`{}` 是个确定的观察，
                    #   说得出"上次是空的"，且模型自己在思考里也是这么说的。）
                    was = str(f.get("args"))
                    if was in ("{}", "", "None"):
                        ex_args.append(
                            f"{r['dir'].name} 第 {t} 轮：{f.get('name')} "
                            f"发出**空调用**被拒 → 重发时带上了参数"
                            f"（模型修正自己）")
                    else:
                        ex_args.append(
                            f"{r['dir'].name} 第 {t} 轮：{f.get('name')} "
                            f"参数被拒 → 重发时换了参数"
                            f"（{was[:32]}… → {str(nxt.get('args'))[:32]}…）")
            else:
                unchanged += 1
    changed = changed_tool + changed_args
    total = changed + unchanged
    if total == 0:
        note("B 工具失败后改变做法 —— **本轮无失败可供判定**",
             f"（{orphan} 次失败发生在最后一轮，没有后续动作可比）\n"
             "没有失败就没有这条证据，不能据此判过。")
    else:
        lines = [f"失败 {total} 次：换工具 {changed_tool} 次、"
                 f"同工具换参数 {changed_args} 次、原样重试 {unchanged} 次。"]
        if ex_args:
            lines.append("同工具换参数（模型修正自己）：")
            lines += ["  " + e for e in ex_args]
        if ex_tool:
            lines.append("换工具（模型绕开障碍）：")
            lines += ["  " + e for e in ex_tool]
        check(unchanged == 0,
              "B 工具失败后**改变做法**（脚本只会原样重试）",
              "\n".join(lines))

    # ---- C：工具面真实约束（对产物）
    unknown = [(r["dir"].name, e) for r in runs for e in r["tools"]
               if e.get("error") == "unknown_tool"]
    bad = Counter(e.get("name") for r in runs for e in r["tools"]
                  if e.get("error") == "bad_args")
    n_args_rejected = sum(bad.values())
    check(not unknown,
          "C 产物中零 `unknown_tool`（模型从未调通不存在的工具）",
          f"bad_args 被拒 {n_args_rejected} 次"
          + ("：" + "、".join(f"{k}×{v}" for k, v in bad.most_common())
             if bad else "（无）"))


def probe_registry() -> None:
    """直接问注册表：未注册的名字会不会被拒？

    ★ 这一条**不依赖任何真实运行**。产物里零 `unknown_tool` 有两种可能：
    模型没幻觉过工具名，或者注册表根本没在挡。跑一次真实运行去分辨代价太高、
    且不可控（模型不一定配合）。直接构造一个注册表问它一句就确定了——
    这是**确定性证据**，比从产物里统计强。
    """
    try:
        from types import SimpleNamespace
        from engine.agent.tools import ToolContext, build_registry

        scope = SimpleNamespace(repo=str(ROOT), files={})
        ctx = ToolContext(cfg=SimpleNamespace(), scope=scope,
                          ledger=SimpleNamespace(), repo=ROOT)
        reg = build_registry(ctx)
    except Exception as e:                       # 探针失败不该掩盖主判据
        note("C 注册表直接探针 —— 无法构造（跳过）",
             f"{type(e).__name__}: {e}")
        return

    r1 = reg.call("this_tool_does_not_exist", {})
    r2 = reg.call("read_code", {})               # 缺必填参数
    check((not r1.ok) and r1.error == "unknown_tool",
          "C 注册表直接探针：未注册的工具名被拒",
          f"调用 `this_tool_does_not_exist` → ok={r1.ok}, "
          f"error={r1.error!r}")
    check(not r2.ok,
          "C 注册表直接探针：必填参数缺失被拒",
          f"调用 `read_code` 空参数 → ok={r2.ok}, error={r2.error!r}")


# ---------------------------------------------------------------- 要求 2

def check_requirement_2(runs: list[dict]) -> None:
    head("要求 2 —— 完整闭环（是否自动串联）")

    # ---- D：链路完整
    bad_chain = []
    for r in runs:
        if r["missing"]:
            bad_chain.append(f"{r['dir'].name} 缺产物：{r['missing']}")
            continue
        J = r["json"]
        eng = J.get("engines") or {}
        ran = [k for k, v in eng.items() if isinstance(v, dict)
               and not v.get("error")]
        if not ran:
            bad_chain.append(f"{r['dir'].name} 无任何引擎运行记录")
        if not r["events"]:
            bad_chain.append(f"{r['dir'].name} 账本为空（未进入 Agent）")
    detail_d = (f"检查了 {len(runs)} 个运行目录，无缺环。" if not bad_chain
                else f"检查了 {len(runs)} 个运行目录，有缺环：\n"
                     + "\n".join(bad_chain))
    check(not bad_chain,
          "D 链路完整：引擎 → 候选 → Agent → 账本 → 报告，五环齐备",
          detail_d)

    # ---- E：结论落盘
    concluded = []
    for r in runs:
        a = (r.get("json") or {}).get("agent") or {}
        c = a.get("conclusion") or {}
        if a.get("status") in ("concluded", "forced"):
            concluded.append((r["dir"].name, bool(c.get("summary")),
                              len(c.get("limitations") or []),
                              r["fingerprint"]))
    good = [c for c in concluded if c[1]]
    check(bool(good),
          "E 至少一次到达最终结论，且结论**真的写进产物**",
          f"{len(runs)} 个运行中收口 {len(concluded)} 次，"
          f"其中结论有正文 {len(good)} 次。\n"
          + "\n".join(f"{n}：summary={'有' if s else '**空**'}，"
                      f"limitations={l}，指纹 {fp}"
                      for n, s, l, fp in concluded)
          if concluded else "（无任何运行收口）")

    # ---- F：收口由账本判定
    def open_n(j):
        v = j.get("candidates_open")
        return v if isinstance(v, int) else len(v or [])

    bad = []
    rows = []
    for r in runs:
        J = r.get("json") or {}
        a = J.get("agent") or {}
        op = open_n(J)
        st = a.get("status")
        cov = J.get("coverage_complete")
        rows.append(f"{r['dir'].name:14s} {str(st):18s} "
                    f"未处置候选={op:<4d} 覆盖完成={cov}")
        if st in ("concluded", "forced") and op > 0:
            bad.append(f"{r['dir'].name} 已 concluded 却仍有 {op} 条候选未处置")
    check(not bad,
          "F 收口由账本判定：concluded 的运行候选必须清零",
          "\n".join(rows) + ("\n" + "\n".join(bad) if bad else ""))

    # ---- 观察项：预算去向
    lines = []
    for r in runs:
        n = len(r["seq"])
        if not n:
            continue
        a = sum(1 for x in r["seq"] if x in ANALYZE)
        b = sum(1 for x in r["seq"] if x in BOOK)
        st = ((r.get("json") or {}).get("agent") or {}).get("status")
        lines.append(f"{r['dir'].name:14s} 总 {n:4d}  分析 {a:4d} ({a/n*100:4.1f}%)"
                     f"  记账 {b:4d} ({b/n*100:4.1f}%)  终止={st}")
    if lines:
        note("预算去向（观察项：回答「为什么没跑完」，不判定任何要求）",
             "\n".join(lines))

    # ---- 观察项：指纹
    #
    # ★ 分三种情况说，因为它们的**结论不同**：
    #   · 真的不同 → 不可作对照（这才是最该警告的）
    #   · 只有一方缺字段 → 无法确认，不是"不同"
    #   · 缺失多于一方 → 全都不可比
    # 曾经把三种都说成"指纹不同"，而其中两种并不是——把读者的注意力
    # 引到一个不存在的问题上，同时**掩盖了真正该看的那个**。
    fp_list = [r["fingerprint"] for r in runs]
    missing = sum(1 for f in fp_list if f == "—")
    fps = {f for f in fp_list if f != "—"}
    rows = "\n".join(f"{r['dir'].name:14s} {r['fingerprint']}" for r in runs)
    if len(fps) > 1:
        note("⚠️ 这些运行的构建指纹**确实不同**——不可作对照", rows +
             "\n指纹不同即代码不同。`build_fingerprint` 的存在就是为了让"
             "「同条件复跑」可核，\n而不是靠人声明。")
    elif missing and len(runs) > 1:
        note(f"⚠️ 无法确认是否同构建：{missing} 个产物**没有指纹字段**"
             f"（早于该功能上线的旧构建）", rows +
             "\n这些运行只能各自单独看，**不能**互相作对照，"
             "也不能据此说「同条件下结果不同」。")
    else:
        note("构建指纹一致（或无值）", rows)


# ---------------------------------------------------------------- 入口

def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 2
    runs = []
    for a in argv:
        p = Path(a)
        if not p.is_absolute():
            p = ROOT / p
        if not p.exists():
            print(f"⚠️ 目录不存在：{p}")
            continue
        runs.append(load(p))
    if not runs:
        return 2

    fps = {r["fingerprint"] for r in runs if r["fingerprint"] != "—"}
    print(f"待判运行 {len(runs)} 个，构建指纹 {sorted(fps) or '（均无）'}")

    check_requirement_1(runs)
    probe_registry()
    check_requirement_2(runs)

    print()
    print("=" * 78)
    if FAILS:
        print(f"❌ 未通过 {len(FAILS)} 条：")
        for f in FAILS:
            print(f"   · {f}")
    else:
        print("✅ 所有硬性判据通过")
    print("=" * 78)
    return 1 if FAILS else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
