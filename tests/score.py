#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""对照 ground truth 给一次审计结果打分。

用法：
    python tests/score.py out/real-full              # 目录（找其中的 ledger.json）
    python tests/score.py out/real-full/ledger.json  # 或直接给文件

**为什么必须要有这个脚本**：一份审计报告读起来永远是通顺的——它不会自己
承认漏了什么。只有把它按到一个事先写好的标准答案上，才知道哪些是"看起来
审过了"和"真的审出来了"之间的差距。

评分维度刻意分成四项而不是一个加权总分：召回、误报、归因、元信息。
把它们揉成一个数字会让"多报一些凑召回"变成有收益的策略。
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from engine.util import force_utf8
force_utf8()

GT = Path(__file__).resolve().parent / "ground_truth" / "ylinux.json"

OK, NO, WARN = "✅", "❌", "⚠️ "


# ------------------------------------------------------------------ 载入

def load_ledger(path: Path) -> dict:
    if path.is_dir():
        for name in ("ledger.json", "audit-report.json"):
            p = path / name
            if p.exists():
                path = p
                break
        else:
            raise SystemExit(f"❌ {path} 里找不到 ledger.json / audit-report.json")
    d = json.loads(path.read_text(encoding="utf-8"))
    # audit-report.json 把账本放在 "ledger" 键下
    if "ledger" in d and isinstance(d["ledger"], dict):
        d = d["ledger"]
    return d


def _as_list(v) -> list:
    if isinstance(v, list):
        return v
    if isinstance(v, dict):
        return list(v.values())
    return []


# ------------------------------------------------------------------ 匹配

def _match(finding: dict, item: dict, window_default: int = 25) -> bool:
    """一条 finding 是否命中一个 ground truth 条目。

    先用文件+行号窗口——这是最硬的证据。行号对不上时退到「同文件 + 类别
    命中」，因为 Agent 可能把问题记在函数入口而不是 sink 那一行。
    """
    loc = finding.get("location") or {}
    if (loc.get("file") or "").replace("\\", "/") != item["file"].replace("\\", "/"):
        return False

    line = loc.get("line") or 0
    end = loc.get("end_line") or line
    w = item.get("window", window_default)
    lo, hi = item["line"], item["line"] + w
    if lo <= line <= hi or (line <= hi and end >= lo):
        return True

    # 兜底：同文件 + 类别关键词
    fc = (finding.get("category") or "").lower()
    if fc:
        for c in item.get("categories") or []:
            c = c.lower()
            if c in fc or fc in c:
                return True

    # 兜底：同文件 + 关键标识符出现在标题/证据里。
    # 这条是为「Agent 把多个问题合并成一条」准备的——合并本身会丢信息
    # （少了「哪个方法无鉴权」这个最关键的区分），但其中的每一项确实
    # 被看到了，不该算漏报。
    blob = (finding.get("title") or "") + json.dumps(
        finding.get("evidence") or {}, ensure_ascii=False)
    for kw in item.get("keywords") or []:
        if kw in blob:
            return True

    fn = (loc.get("function") or "")
    if fn and fn in item.get("title", ""):
        return True
    return False


def _cand_loc(c: dict) -> tuple[str, int]:
    """候选的 file/line —— 账本里是扁平字段，报告 JSON 里可能嵌在 location。"""
    loc = c.get("location") or {}
    f = loc.get("file") or c.get("file") or ""
    ln = loc.get("line") or c.get("line") or 0
    return f.replace("\\", "/"), int(ln or 0)


# 「看漏了净化」的表述：说「未见 basename」的时候，真相往往是 basename
# 就在几行之隔。词面匹配会被这种否定句骗过去，所以要单独识别。
_NEG_BASENAME = re.compile(r"(?:未|没有|没|不含?|缺少?|无)[^\n]{0,20}basename")


def _find_match(findings: list[dict], item: dict):
    for f in findings:
        if _match(f, item):
            return f
    return None


# ------------------------------------------------------------------ 评分

def score(gt: dict, ledger: dict, blob: str = "") -> dict:
    """blob 是报告全文（md）。「报告是否声明了 X」这类检查必须看报告，
    账本里没有那些文字——早先只读 ledger.json，把列全了的清单误判成
    「4/9 未提及」。"""
    findings = _as_list(ledger.get("findings"))
    candidates = _as_list(ledger.get("candidates"))

    active = [f for f in findings
              if (f.get("attribution") or "project") == "project"]
    non_project = [f for f in findings
                   if (f.get("attribution") or "project") != "project"]

    out = {"recall": [], "false_positive": [], "attribution": [],
           "meta": [], "candidates": []}

    # ---- 召回：必须报出的
    for item in gt["must_report"]:
        f = _find_match(active, item)
        rec = {"id": item["id"], "item": item}
        if not f:
            # 也可能报了但归因为非项目——那是归因问题，不是漏报
            f2 = _find_match(non_project, item)
            rec["status"] = "misattributed" if f2 else "missed"
            rec["finding"] = f2
        else:
            rec["status"] = "hit"
            rec["finding"] = f
            # V10 专项：报了 path_traversal 但要判断它究竟看没看见 basename。
            # 光做词面匹配会被「未见 os.path.basename」这种否定句骗过去——
            # 而那恰恰是"看漏了净化"的标准表述。
            trap = item.get("trap") or ""
            if "basename" in trap:
                fc = (f.get("category") or "").lower()
                ev = json.dumps(f.get("evidence") or {}, ensure_ascii=False)
                if "traversal" in fc:
                    if _NEG_BASENAME.search(ev) or "basename" not in ev:
                        rec["status"] = "right_area_wrong_chain"
                        rec["chain_note"] = ("声称未见 basename" if "basename" in ev
                                             else "完全未提及 basename")
        out["recall"].append(rec)

    # ---- 误报：必须不报的
    for item in gt["must_not_report"]:
        f = _find_match(active, item)
        rec = {"id": item["id"], "item": item, "finding": f}

        if item.get("trap") == "attribution":
            # 报出不算错——把第三方库代码算成项目缺陷才算错。
            f_any = _find_match(findings, item)
            rec["finding"] = f_any
            if f_any and (f_any.get("attribution") or "project") == "project":
                rec["status"] = "attributed_to_project"
            else:
                rec["status"] = "not_reported"
        elif not f:
            rec["status"] = "clean"
        else:
            # S3 特例：报为 LOW/INFO 可接受
            if item["id"] == "S3":
                sev = (f.get("severity") or "").upper()
                rec["status"] = "clean" if sev in ("LOW", "INFO") else "reported_high"
            else:
                rec["status"] = "reported"
        out["false_positive"].append(rec)

    # ---- 归因
    for item in gt["must_not_report"]:
        if item.get("trap") != "attribution":
            continue
        f = _find_match(findings, item)
        out["attribution"].append({
            "id": item["id"],
            "status": ("ok" if (not f or (f.get("attribution") or "project") != "project")
                       else "wrong"),
            "attribution": (f or {}).get("attribution"),
        })

    # ---- 元信息
    me = gt.get("meta_expectations") or {}
    allspec = json.dumps(ledger, ensure_ascii=False) + (blob or "")

    py2 = me.get("py2_uncovered_files") or {}
    tot = len(py2.get("files", [])) or 1
    files_declared = sum(1 for f in py2.get("files", []) if f in allspec)
    # 按比例——只说中 1/9 和完整声明 9/9 是两回事，不能都给 ✅
    out["meta"].append({
        "id": "py2_uncovered",
        "status": ("ok" if files_declared >= tot * 0.9 else
                   "partial" if files_declared else "missing"),
        "detail": f"{files_declared}/{tot} 个未覆盖文件被提及"
                  + ("——**存在覆盖率假象**（列举不全等于误导读者）"
                     if 0 < files_declared < tot * 0.9 else ""),
    })

    fork = (me.get("forked_files") or {}).get("files", [])
    n_fork = sum(1 for f in fork if f in allspec)
    out["meta"].append({
        "id": "forked",
        "status": "ok" if n_fork >= len(fork) else ("partial" if n_fork else "missing"),
        "detail": f"{n_fork}/{len(fork)} 个改造版文件被提及",
    })

    # ---- 候选处置（针对 must_not_report 里带 trap 的引擎误报）
    for item in gt["must_not_report"]:
        if item.get("trap") not in ("bandit_b608", "bandit_b605"):
            continue
        c = None
        for c_ in candidates:
            f_, line = _cand_loc(c_)
            if f_ != item["file"]:
                continue
            if item["line"] <= line <= item["line"] + item.get("window", 30):
                c = c_
                break
        # 位置擦边时退到「同文件 + 同规则」
        if c is None:
            for c_ in candidates:
                f_, _ = _cand_loc(c_)
                if f_ == item["file"] and (c_.get("rule") or "") in (
                        "B608", "B605", "B603", "B607"):
                    c = c_
                    break
        st = (c or {}).get("status") or "absent"
        reason = (c or {}).get("reason") or (c or {}).get("disposition_reason") or ""
        out["candidates"].append({
            "id": item["id"], "status": st,
            "verdict": ("ok" if st in ("dismissed", "confirmed", "deferred") else "open"),
            "reason_len": len(reason),
            "reason": reason[:120],
            "candidate": (c or {}).get("id"),
        })

    return out


# ------------------------------------------------------------------ 打印

def report(gt: dict, res: dict, src: str) -> float:
    print("=" * 74)
    print(f"ground truth 评分  ·  {gt['target']}")
    print(f"被评结果：{src}")
    print("=" * 74)

    # 召回
    print("\n【一】召回 —— 必须报出的问题")
    hits = 0
    must = [r for r in res["recall"] if not r["item"].get("optional")]
    opt = [r for r in res["recall"] if r["item"].get("optional")]
    for r in res["recall"]:
        it = r["item"]
        tag = f"{it['file']}:{it['line']}"
        opt_mark = "（可选）" if it.get("optional") else ""
        if r["status"] == "hit":
            print(f"  {OK} {r['id']:4s} {tag:34s} {it['title'][:28]}{opt_mark}")
        elif r["status"] == "right_area_wrong_chain":
            print(f"  {WARN}{r['id']:4s} {tag:34s} 方向对、利用链错——报了 "
                  f"{r['finding'].get('category')}，"
                  f"{r.get('chain_note', '未说明')} basename 净化{opt_mark}")
        elif r["status"] == "misattributed":
            print(f"  {NO} {r['id']:4s} {tag:34s} 报出但归因为"
                  f"{r['finding'].get('attribution')}——应归项目{opt_mark}")
        else:
            print(f"  {NO} {r['id']:4s} {tag:34s} **漏报**：{it['title'][:30]}{opt_mark}")

    for r in must:
        if r["status"] == "hit":
            hits += 1
        elif r["status"] == "right_area_wrong_chain":
            hits += 0.5
    opt_hits = sum(1 for r in opt if r["status"] in ("hit", "right_area_wrong_chain"))
    recall = hits / len(must) if must else 1.0
    print(f"\n  召回率：{hits:g}/{len(must)} = {recall:.0%}"
          + (f"　（可选 {opt_hits}/{len(opt)}）" if opt else ""))

    # 误报
    print("\n【二】误报 —— 必须不报的样本")
    fp = 0
    for r in res["false_positive"]:
        it = r["item"]
        tag = f"{it['file']}:{it['line']}"
        if r["status"] == "clean":
            note = {"S1": "正确驳回（qn 引用 + 参数化传值）",
                    "S2": "正确驳回",
                    "S3": "报为 LOW/INFO，可接受"}.get(r["id"], "未报出")
            print(f"  {OK} {r['id']:4s} {tag:34s} {note}")
        elif r["status"] == "not_reported":
            print(f"  {OK} {r['id']:4s} {tag:34s} 未报出")
        elif r["status"] == "attributed_to_project":
            print(f"  {NO} {r['id']:4s} {tag:34s} 归因为 project——把库代码算成项目缺陷")
            fp += 1
        elif r["status"] == "reported_high":
            print(f"  {NO} {r['id']:4s} {tag:34s} 报为 "
                  f"{r['finding'].get('severity')}——把不可控来源当成用户输入")
            fp += 1
        else:
            print(f"  {NO} {r['id']:4s} {tag:34s} **误报**：{it.get('title', '')[:36]}")
            fp += 1
    print(f"\n  误报：{fp} 项")

    # 候选处置
    if res["candidates"]:
        print("\n【三】候选处置 —— 引擎误报是否被正确驳回")
        for r in res["candidates"]:
            icon = OK if r["verdict"] == "ok" else (WARN if r["status"] == "deferred" else NO)
            print(f"  {icon} {r['id']:4s} {r['status']:10s} 理由 {r['reason_len']} 字"
                  + (f"：{r['reason'][:56]}" if r["reason"] else "　**无理由**"))
        print("  说明：deferred 是「如实说没做完」，比编一个驳回理由好，"
              "但不等于审过了")

    # 元信息
    print("\n【四】元信息 —— 报告是否声明了自己的边界")
    for r in res["meta"]:
        icon = {"ok": OK, "partial": WARN, "missing": NO}[r["status"]]
        print(f"  {icon}{r['id']:16s} {r['detail']}")

    # 汇总
    meta_ok = sum(1 for r in res["meta"] if r["status"] == "ok")
    print("\n" + "=" * 74)
    print(f"  召回 {recall:.0%}　误报 {fp} 项　"
          f"归因正确 {sum(1 for r in res['attribution'] if r['status'] == 'ok')}/"
          f"{len(res['attribution'])}　边界声明 {meta_ok}/{len(res['meta'])}")
    print("=" * 74)
    print("\n  ↑ 四个数字要一起看。召回高但误报多 = 模式匹配；"
          "召回低但误报零 = 过于保守。")
    print("  ground truth 本身也是人写的判断，不是绝对真理——它衡量的是"
          "「与本项目既有认知的一致程度」。")
    return recall


def main(argv: list[str] | None = None) -> int:
    argv = argv or sys.argv[1:]
    if not argv:
        print(__doc__)
        return 2
    gt = json.loads(GT.read_text(encoding="utf-8"))
    p = Path(argv[0])
    ledger = load_ledger(p)
    md = ""
    d = p if p.is_dir() else p.parent
    for name in ("audit-report.md",):
        f = d / name
        if f.exists():
            md = f.read_text(encoding="utf-8", errors="replace")
            break
    res = score(gt, ledger, blob=md)
    report(gt, res, argv[0])

    if len(argv) > 1 and argv[1] == "--json":
        print(json.dumps(res, ensure_ascii=False, indent=1, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
