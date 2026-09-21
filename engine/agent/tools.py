# -*- coding: utf-8 -*-
"""Agent 工具集（06 §3）。

**工具是本次审计里模型唯一能改变世界的入口。** 因此所有契约都在工具边界强制：
证据契约在 `record_finding`、覆盖度契约在 `set_coverage`、归因门禁在
`check_vendored` 与 `record_finding`、收敛条件在 `conclude`。

分组（与 06 §3 对应）：
  A 侦察 —— 看代码、找入口、搜文本。只读。
  B 规则 —— 静态引擎产出的候选。
  C 推理 —— 调用图、归因、符号定位。把"模式匹配"升级为"数据流推理"的那一层。
  D 验证 —— 独立对抗验证者。
  E 记录 —— 写账本。所有写操作在此强制契约。
  F 收敛 —— 收口判定。

★ **每个工具的 description 都写"什么时候该用"，不只是"它做什么"。**
实测：只写功能的工具描述会让模型反复调用同一个工具；
写明触发条件后，模型的选择明显更准。
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from .registry import A, B, I, S, Tool, ToolRegistry, ToolResult, obj
from .ledger import Candidate, Ledger
from ..schema import CoverageClass, CoverageStatus


@dataclass
class ToolContext:
    """工具执行所需的全部外部状态。工具本身保持无状态、可单测。"""
    cfg: object
    scope: object
    ledger: Ledger
    index: object = None              # CodeIndex
    vendored: object = None           # VendoredIndex
    parsed: dict = field(default_factory=dict)
    provider: object = None           # 仅对抗验证用
    turn: int = 0
    repo: Path | None = None

    def __post_init__(self):
        if self.repo is None:
            self.repo = Path(self.scope.repo)
        self.root = Path(self.repo).resolve()

    def read_lines(self, rel: str) -> list[str]:
        """读在审文件的行。

        ★ 这是**唯一**的读盘入口，所以越界边界设在这里（A09「越界路径不能
        突破执行层」）。所有工具都经由它取代码，新增工具自动受保护。

        为什么需要这道检查：`ScopeContract.get()` 为了容错做了模糊匹配
        （`posix.endswith(k)`），于是 `"../../x/settings.py"` 也能匹配到
        `settings.py` 的 FileInfo。`get()` 返回的是**规范 FileInfo**，调用方
        理应改用 `fi.rel` 再读盘（`read_code` 就是这么做的），但只要有一处
        忘了规范化，`repo / "../../x/settings.py"` 就会真的读到仓库外，
        内容还会以"snippet"的名义写进报告。与其指望每个调用点都记得，
        不如在这里判一次：**解析后必须仍落在仓库内**。
        """
        p = self.repo / rel
        try:
            real = p.resolve()
        except OSError as e:
            raise FileNotFoundError(f"无法解析路径 {rel}：{e}") from e
        if real != self.root and self.root not in real.parents:
            raise FileNotFoundError(f"{rel!r} 解析到仓库之外（{real}），已拒绝读取")
        try:
            text = real.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            text = real.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            raise FileNotFoundError(f"无法读取 {rel}：{e}") from e
        return text.splitlines()


# ================================================================ A 侦察

def _t_list_files(ctx: ToolContext, args: dict) -> ToolResult:
    """列出在审文件。"""
    q = (args.get("filter") or "").lower()
    attr = args.get("attribution")
    limit = int(args.get("limit") or 80)

    rows = []
    for fi in ctx.scope.in_scope:
        if attr and fi.attribution != attr:
            continue
        if q and q not in fi.rel.lower():
            continue
        rows.append(fi)
    rows.sort(key=lambda f: (-f.in_critical_path, f.rel))

    if not rows:
        return ToolResult(True, f"没有匹配的文件（filter={q!r}, attribution={attr!r}）。"
                                f"共 {len(ctx.scope.in_scope)} 个在审文件。",
                          {"count": 0})

    L = [f"在审文件 {len(rows)} 个（按 关键路径 优先排序）："]
    for fi in rows[:limit]:
        flags = []
        if fi.in_critical_path:
            flags.append("★关键路径")
        if fi.is_sensitive:
            flags.append("敏感")
        if fi.attribution == "suspected":
            flags.append("待裁决")
        if fi.library:
            flags.append(f"疑似来自{fi.library}")
        L.append(f"  {fi.rel}  [{fi.py_version}语法/{fi.parse_engine}, "
                 f"{fi.lines}行]{'  ' + ' '.join(flags) if flags else ''}")
    if len(rows) > limit:
        L.append(f"  …另有 {len(rows) - limit} 个，请用 filter 缩小范围")

    return ToolResult(True, "\n".join(L),
                      {"count": len(rows), "files": [f.rel for f in rows[:limit]]})


def _t_read_code(ctx: ToolContext, args: dict) -> ToolResult:
    rel = str(args["file"]).replace("\\", "/")
    fi = ctx.scope.get(rel)
    if fi is None:
        near = [f.rel for f in ctx.scope.in_scope
                if rel.split("/")[-1].lower() in f.rel.lower()][:6]
        return ToolResult(False, f"文件 {rel!r} 不在本次审计范围内。"
                                 + (f"相近的路径：{near}" if near else
                                    "请用 list_files 查看在审文件清单。"),
                          error="out_of_scope")
    rel = fi.rel

    # ★ 只拒绝 excluded（测试/生成物/依赖目录）。
    # vendored 代码**必须可读**——C2 反序列化就藏在 vendored 的
    # `sessions/backends/base.py` 里，不让读等于放弃这一类覆盖。
    # 归因的影响体现在结论上（是否计入项目漏洞），而不是体现在能不能看。
    if rel in getattr(ctx.scope, "excluded", ()):
        return ToolResult(False, f"{rel} 被排除在审计范围外（测试桩/生成物/依赖目录）。"
                                 f"如确需查看，请说明理由；"
                                 f"但不要基于它记录 findings。", error="excluded")

    lines = ctx.read_lines(rel)
    n = len(lines)
    start = max(1, int(args.get("start") or 1))
    end = int(args.get("end") or 0)
    if end <= 0:
        end = min(n, start + int(args.get("context_lines") or 240) - 1)
    end = min(end, n)
    if start > n:
        return ToolResult(False, f"start={start} 超出 {rel} 的行数（共 {n} 行）",
                          error="bad_range")

    body = "\n".join(f"{i:>5d} | {lines[i-1]}" for i in range(start, end + 1))
    new = ctx.ledger.note_reviewed(rel, start, end)
    cov = ctx.ledger.coverage_of_file(rel)

    head = f"{rel}  L{start}-{end} / 共 {n} 行"
    if fi.py_version == "2":
        head += "  [Python 2 语法，静态引擎未覆盖]"
    if fi.forked_from:
        head += f"  ★改造版：源自 {fi.forked_from}，归因为项目代码"
    elif fi.attribution == "vendored":
        head += f"  [vendored：{fi.library}，不计入项目漏洞]"
    if not new:
        head += "  ⚠️ 这段之前已读过（如无新目的请推进到其它位置）"

    return ToolResult(True, f"{head}\n{body}",
                      {"file": rel, "start": start, "end": end, "lines": n,
                       "file_coverage": round(cov, 3), "new_information": new},
                      truncated=False)


def _t_search_code(ctx: ToolContext, args: dict) -> ToolResult:
    pat = str(args["pattern"])
    try:
        rx = re.compile(pat, re.IGNORECASE if args.get("ignore_case") else 0)
    except re.error as e:
        return ToolResult(False, f"正则表达式无效：{e}。"
                                 f"提示：特殊字符需转义（如 \\( 表示字面括号）。",
                          error="bad_regex")

    glob_pat = args.get("glob")
    only_inscope = args.get("in_scope_only", True)
    limit = int(args.get("limit") or 60)
    window = int(args.get("context_lines") or 0)

    targets = [f.rel for f in ctx.scope.in_scope] if only_inscope else \
        sorted(ctx.scope.files.keys())
    if glob_pat:
        from ..util import glob_match_posix
        targets = [t for t in targets if glob_match_posix(t, glob_pat)]

    hits: list[tuple[str, int, str]] = []
    for rel in targets:
        try:
            lines = ctx.read_lines(rel)
        except (OSError, FileNotFoundError):
            continue
        for i, ln in enumerate(lines, 1):
            if rx.search(ln):
                hits.append((rel, i, ln.rstrip()))
                if len(hits) >= limit * 3:
                    break
        if len(hits) >= limit * 3:
            break

    if not hits:
        scope_note = f"（在 {len(targets)} 个文件内搜索）"
        return ToolResult(True, f"未找到匹配 {pat!r} 的代码。{scope_note}\n"
                                f"建议：放宽正则、去掉 glob 限制、"
                                f"或把 in_scope_only 设为 false 以包含 vendored 代码。",
                          {"count": 0})

    L = [f"匹配 {len(hits)} 处（{len(set(h[0] for h in hits))} 个文件）："]
    for rel, i, ln in hits[:limit]:
        L.append(f"  {rel}:{i}")
        L.append(f"      {ln.strip()[:160]}")
        if window:
            try:
                lines = ctx.read_lines(rel)
                for j in range(i - window, i + window + 1):
                    if 1 <= j <= len(lines) and j != i:
                        L.append(f"      {j:>5d}| {lines[j-1].rstrip()[:150]}")
            except Exception:
                pass
    if len(hits) > limit:
        L.append(f"  …另有 {len(hits) - limit} 处，请加 glob 或收紧正则")
    return ToolResult(True, "\n".join(L),
                      {"count": len(hits),
                       "locations": [f"{r}:{i}" for r, i, _ in hits[:limit]]})


def _t_entry_points(ctx: ToolContext, args: dict) -> ToolResult:
    kind = args.get("kind")
    eps = list(getattr(ctx.scope, "entry_points", []) or [])
    if kind:
        eps = [e for e in eps if e.kind == kind]
    if not eps:
        return ToolResult(True, "没有提取到外部入口。" if not kind
                          else f"没有 kind={kind!r} 的入口。",
                          {"count": 0})

    # 鉴权状态是可达性推理的第一道门，按风险从高到低排序
    def risk(e):
        if e.auth == "none":
            return 0
        if e.auth == "required" and e.authz == "none":
            return 1                      # 有认证无授权 = 越权，往往更隐蔽
        return 2 if e.auth == "required" else 1.5
    eps.sort(key=risk)

    n_noauth = len([e for e in eps if e.auth == "none"])
    n_noauthz = len([e for e in eps
                     if e.auth == "required" and e.authz == "none"])
    L = [f"外部入口 {len(eps)} 个：无认证 {n_noauth} 个，"
         f"有认证但无对象级授权 {n_noauthz} 个（按风险从高到低）："]
    for e in eps[:120]:
        L.append(f"  [{e.kind}] {e.file}:{e.line}  {e.target}   {e.risk_label}")
        if e.auth_evidence and e.auth != "required":
            L.append(f"        认证依据：{e.auth_evidence}")
        if e.authz_evidence:
            L.append(f"        授权依据：{e.authz_evidence}")
        if e.note:
            L.append(f"        {e.note}")
    if len(eps) > 120:
        L.append(f"  …另有 {len(eps) - 120} 个")
    L.append("")
    L.append('★ **认证与授权是两件事**：`auth=none` 是「谁都能进」；'
             '`auth=required, authz=none` 是「登录用户能操作别人的资源」——'
             '后者更隐蔽，且修复方式不同（前者加认证，后者加对象归属校验）。'
             '判可达性时两者都算可达，但**利用前提不同**，要在 evidence 里写清楚。')
    return ToolResult(True, "\n".join(L),
                      {"count": len(eps), "no_auth": n_noauth,
                       "no_authz": n_noauthz})


def _t_outline(ctx: ToolContext, args: dict) -> ToolResult:
    rel = str(args["file"]).replace("\\", "/")
    fi = ctx.scope.get(rel)
    if fi is None:
        return ToolResult(False, f"文件 {rel!r} 不在仓库中", error="not_found")
    if ctx.index is None:
        return ToolResult(False, "符号索引不可用", error="no_index")
    text = ctx.index.outline(fi.rel, max_n=int(args.get("limit") or 120))
    return ToolResult(True, text, {"file": fi.rel})


# ================================================================ B 规则

def _candidates_grouped(cs: list[Candidate], by: str, status, source) -> ToolResult:
    """按 file / rule / source 归拢候选，**输出直接喂给 dispose_candidates**。

    ★ 存在的理由：收口前待处置的候选常有几十条（real-quota 那次 37 条），
    平铺清单要占上百行，而模型还得自己从里面数出"哪几条是同一回事"。
    它接下来要做的事恰恰是**成组处置**——视图与动作对不上，它就退回逐条
    处置，而那正是 45 个调用把输出撑爆的原因。这里按模型即将使用的分组
    维度呈现，并**显式列出 id**，让它能把 id 直接填进 dispose_candidates。
    """
    keyf = {"file": lambda c: c.file,
            "rule": lambda c: f"{c.source}/{c.rule}",
            "source": lambda c: c.source}[by]
    buckets: dict[str, list[Candidate]] = {}
    for c in cs:
        buckets.setdefault(keyf(c), []).append(c)
    order = sorted(buckets.items(), key=lambda kv: (-len(kv[1]), kv[0]))

    n_open = len([c for c in cs if c.is_open])
    L = [f"候选 {len(cs)} 条，按 {by} 归拢为 {len(order)} 组"
         + (f"（status={status}）" if status else "")
         + (f"（source={source}）" if source else "")
         + f"，其中待处置 {n_open} 条："]
    for k, grp in order:
        op = [c for c in grp if c.is_open]
        L.append(f"  · {k}　{len(grp)} 条（待处置 {len(op)}）")
        per_file: dict[str, list[int]] = {}
        for c in grp:
            per_file.setdefault(c.file, [])
            if c.line not in per_file[c.file]:
                per_file[c.file].append(c.line)
        shown = [f"{f}:{','.join(str(x) for x in ls[:6])}"
                 + ("…" if len(ls) > 6 else "")
                 for f, ls in list(per_file.items())[:4]]
        if len(per_file) > 4:
            shown.append(f"等 {len(per_file)} 个文件")
        L.append("      位置：" + "、".join(shown))
        ids = [c.id for c in (op or grp)]
        L.append("      id：" + " ".join(ids[:15])
                 + (f" …（共 {len(ids)} 条）" if len(ids) > 15 else ""))
    L.append("\n★ 归拢只是帮你把位置看清楚，**每组的判据仍要你自己给**——"
             "同一个 rule 下的候选完全可能判出不同结论（引擎按模式匹配，"
             "而「这处的值到底可不可控」得看代码）。把 id 填进 "
             "dispose_candidates 时，同组的必须是**同一个判断**。")
    return ToolResult(True, "\n".join(L), {"count": len(cs), "groups": len(order)})


def _t_list_candidates(ctx: ToolContext, args: dict) -> ToolResult:
    status = args.get("status")
    source = args.get("source")
    cs = list(ctx.ledger.candidates.values())
    if status:
        cs = [c for c in cs if c.status == status]
    if source:
        cs = [c for c in cs if c.source == source]
    if not cs:
        return ToolResult(True, "没有匹配的候选。", {"count": 0})

    by = str(args.get("group_by") or "")
    if by:
        return _candidates_grouped(cs, by, status, source)

    L = [f"候选 {len(cs)} 条"
         + (f"（status={status}）" if status else "")
         + f"，其中待处置 {len([c for c in cs if c.is_open])} 条："]
    for c in cs[:60]:
        mark = {"open": "⬜", "confirmed": "✅", "dismissed": "❌",
                "deferred": "⏭️"}.get(c.status, "?")
        L.append(f"  {mark} {c.id} [{c.source}/{c.severity}] {c.file}:{c.line} {c.rule}")
        L.append(f"      {c.message[:150]}")
        if c.snippet:
            first = c.snippet.strip().splitlines()[0] if c.snippet.strip() else ""
            L.append(f"      代码: {first[:130]}")
    if len(cs) > 60:
        L.append(f"  …另有 {len(cs) - 60} 条")
    return ToolResult(True, "\n".join(L), {"count": len(cs)})


# ================================================================ C 推理

def _t_check_vendored(ctx: ToolContext, args: dict) -> ToolResult:
    """归因门禁。**每个非平凡文件的结论都要先过这一关。**"""
    rel = str(args["file"]).replace("\\", "/")
    fi = ctx.scope.get(rel)
    if fi is None:
        return ToolResult(False, f"文件 {rel!r} 不在仓库中", error="not_found")

    L = [f"{fi.rel}",
         f"  归因      : {fi.attribution}",
         f"  判定依据  : {'; '.join(fi.attribution_reasons) or '（无记录）'}"]
    if fi.library:
        L.append(f"  疑似来源库: {fi.library}")
    if fi.forked_from:
        L.append(f"  ★改造版    : 源自 {fi.forked_from} → **归因为项目代码**")
        L.append(f"     理由：该文件 import 了仓库内的非 vendored 模块，"
                 f"说明它是被改造过的 fork 而非原样拷贝。"
                 f"库不会反向依赖宿主项目。")
    if fi.parse_engine:
        L.append(f"  解析引擎  : {fi.parse_engine}（Python {fi.py_version} 语法）")
    if fi.parse_ok is False:
        L.append(f"  ⚠️ 解析失败，静态引擎可能完全未覆盖此文件")
    if fi.in_critical_path:
        L.append(f"  ★ 位于安全关键路径")
    if fi.is_sensitive:
        L.append(f"  ⚠️ 含敏感内容（报告中外发前需脱敏）")

    L.append("")
    if fi.attribution == "project" or fi.forked_from:
        L.append("→ 该文件的缺陷**计入项目漏洞**，需要完整的数据流审查。")
    elif fi.attribution == "vendored":
        L.append("→ vendored 依赖。缺陷不计入项目，但若存在**可达且未缓解**的问题，"
                 "仍应记录（severity 降级、attribution=vendored），"
                 "因为项目需要安排升级。")
    elif fi.attribution == "suspected":
        L.append("→ 归因待定。请读代码判断：它是原样拷贝的第三方库，"
                 "还是被项目改造过的 fork？判据是**它是否 import 了仓库内的业务模块**。"
                 "判定后按实际归因继续审查。")
    else:
        L.append("→ 排除项，不参与审计。")

    return ToolResult(True, "\n".join(L), {
        "file": fi.rel, "attribution": fi.attribution,
        "forked_from": fi.forked_from, "library": fi.library,
        "in_critical_path": fi.in_critical_path,
    })


def _t_find_symbol(ctx: ToolContext, args: dict) -> ToolResult:
    if ctx.index is None:
        return ToolResult(False, "符号索引不可用", error="no_index")
    name = str(args["name"])
    hide_vendored = args.get("exclude_vendored", False)
    syms = ctx.index.find(name, limit=int(args.get("limit") or 30))
    if hide_vendored:
        syms = [s for s in syms
                if (ctx.scope.get(s.rel) or _SENTINEL).attribution != "vendored"]
    if not syms:
        return ToolResult(True, f"未找到名为 {name!r} 的符号定义。"
                                f"可能是标准库/第三方，或名字拼写不同。",
                          {"count": 0})
    L = [f"符号 {name!r} 命中 {len(syms)} 处定义："]
    for s in syms:
        fi = ctx.scope.get(s.rel)
        tag = ""
        if fi is not None and fi.attribution == "vendored":
            tag = f"  [vendored:{fi.library}]"
        elif fi is not None and fi.forked_from:
            tag = f"  [fork自{fi.forked_from}→项目代码]"
        L.append(f"  {s.rel}:{s.lineno}-{s.end_lineno}  {s.kind} {s.qualified}{tag}")
        if s.decorators:
            L.append(f"      装饰器: {' '.join(s.decorators)}")
    return ToolResult(True, "\n".join(L), {"count": len(syms)})


class _Sentinel:
    attribution = ""


_SENTINEL = _Sentinel()


def _t_find_callers(ctx: ToolContext, args: dict) -> ToolResult:
    """谁调用了这个函数 —— 可达性推理的反向搜索。"""
    if ctx.index is None:
        return ToolResult(False, "符号索引不可用", error="no_index")
    name = str(args["name"])
    rel = args.get("file")
    edges = ctx.index.callers_of(name, rel)
    if not edges:
        # ★ 索引解析不了 ≠ 不可达。动态派发（XMLRPC 方法注册表、Django 字符串视图）
        # 静态索引天然看不见，但入口提取阶段已经把它们找到了。
        # 若不在这里接上，模型会得到"没人调用它"这个**危险的错误印象**——
        # 而真相恰恰相反：它是个无鉴权的外部入口。
        eps = [e for e in (getattr(ctx.scope, "entry_points", []) or [])
               if name in (e.target or "") or name in (e.note or "")]
        if eps:
            L = [f"⚠️ 静态调用图里没有指向 {name!r} 的边，"
                 f"**但它是一个外部入口**——不可据此判定为死代码："]
            for e in eps[:10]:
                flag = {"none": "🚨无鉴权", "required": "✅已鉴权",
                        "unknown": "❓未知"}.get(e.auth, e.auth)
                L.append(f"  [{e.kind}] {e.file}:{e.line} {e.target}  {flag}")
                if e.note:
                    L.append(f"      {e.note}")
            L.append("")
            L.append("这类入口通过**注册表/字符串**被框架调用，静态调用图看不见它。"
                     "请直接把它当作可达的外部入口来评估其数据流。")
            return ToolResult(True, "\n".join(L),
                              {"count": 0, "is_entry_point": True,
                               "entry_points": [f"{e.file}:{e.line}" for e in eps]})

        syms = ctx.index.symbols.get(name, [])
        extra = ""
        if syms:
            extra = (f"\n该符号在 {len(syms)} 处有定义，但索引里没有指向它的调用边。"
                     f"可能原因：① 调用方使用 getattr/动态派发；"
                     f"② Django URL 配置以字符串引用视图；③ 是框架回调（信号/hook）。"
                     f"请用 search_code 按字符串形式再搜一次。")
        return ToolResult(True, f"没有找到对 {name!r} 的静态可解析调用。{extra}",
                          {"count": 0})

    by_file: dict[str, list] = {}
    for e in edges:
        by_file.setdefault(e.caller_rel, []).append(e)

    L = [f"{name!r} 被 {len(edges)} 处调用（分布在 {len(by_file)} 个文件）："]
    for f, es in sorted(by_file.items(),
                        key=lambda kv: -len(kv[1])):
        fi = ctx.scope.get(f)
        tag = "  [外部入口文件]" if any(
            e.file == f for e in getattr(ctx.scope, "entry_points", []) or []) else ""
        vend = f"  [vendored:{fi.library}]" if fi and fi.attribution == "vendored" else ""
        L.append(f"  {f}{tag}{vend}")
        for e in es[:12]:
            caller = e.caller_symbol or "（模块级代码）"
            L.append(f"      L{e.line:<5d} 由 {caller} 调用")
        if len(es) > 12:
            L.append(f"      …另有 {len(es) - 12} 处")
    L.append("")
    L.append("→ 继续沿调用方向上追溯，直到抵达外部入口（get_entry_points），"
             "才能确认该 sink 是否真的可达。")
    return ToolResult(True, "\n".join(L), {"count": len(edges),
                                           "files": sorted(by_file)})


def _t_trace_calls(ctx: ToolContext, args: dict) -> ToolResult:
    """某函数调用了什么 —— 正向追踪。"""
    if ctx.index is None:
        return ToolResult(False, "符号索引不可用", error="no_index")
    rel = str(args["file"]).replace("\\", "/")
    fi = ctx.scope.get(rel)
    if fi is None:
        return ToolResult(False, f"文件 {rel!r} 不在仓库中", error="not_found")
    symbol = str(args["symbol"])

    syms = [s for s in ctx.index.by_rel.get(fi.rel, []) if s.qualified == symbol
            or s.name == symbol]
    if not syms:
        return ToolResult(False,
                          f"{fi.rel} 中没有 {symbol!r}。该文件的符号有："
                          + "、".join(s.qualified for s in
                                      sorted(ctx.index.by_rel.get(fi.rel, []),
                                             key=lambda x: x.lineno)[:16]),
                          error="no_symbol")
    s = syms[0]
    edges = ctx.index.callees_of(fi.rel, s.qualified)

    L = [f"{fi.rel}:{s.lineno}-{s.end_lineno}  {s.qualified} 调用了 {len(edges)} 处："]
    resolved = [e for e in edges if e.resolved]
    unresolved = [e for e in edges if not e.resolved]
    for e in resolved:
        tgt = e.resolved
        tf = ctx.scope.get(tgt.rel)
        tag = ""
        if tf is not None and tf.attribution == "vendored":
            tag = f"  [vendored:{tf.library}]"
        L.append(f"  L{e.line:<5d} → {tgt.rel}:{tgt.lineno} {tgt.qualified}{tag}")
        L.append(f"        （{e.how}）")
    if unresolved:
        L.append(f"  以下 {len(unresolved)} 处无法静态解析（多为标准库/第三方，"
                 f"也可能因动态派发）：")
        seen = set()
        for e in unresolved:
            if e.callee_dotted in seen:
                continue
            seen.add(e.callee_dotted)
            L.append(f"  L{e.line:<5d} → {e.callee_dotted}   （{e.how}）")
    return ToolResult(True, "\n".join(L),
                      {"count": len(edges), "resolved": len(resolved)})


# ================================================================ E 记录

def _fill_snippet(ctx: ToolContext, raw: dict,
                  before: int = 3, after: int = 6, max_lines: int = 24) -> None:
    """把定位处的源码切片填进 `evidence.snippet`（带行号）。

    ★ 这件事由系统做，不由模型粘贴。三个理由：

    1. **模型粘贴的代码可能与磁盘上的不一致**（行号记错、凭记忆改写）。而报告里
       最像"证据"的那部分恰恰最不能出错——位置对、代码不对，比没有代码更糟，
       因为它看起来是可核验的。
    2. 让模型把源码抄进工具参数，是为同一段代码**付两次 token**（一次读、一次抄），
       抄完还要留进账本。系统手里本来就有这份文件。
    3. 实测：模型基本不会主动填。靶子上 7 条 finding 的 snippet **全为空**，
       于是报告里一行真实代码都没有，A06 要求的「源码快照」形同虚设。

    带行号是刻意的：报告正文写着"`lib/ylinux_xmlrpc.py:60`"，快照里就得能看见
    第 60 行是哪一句，读者才能在不打开文件的情况下核对指控。前缀是展示用的，
    不改变代码内容。

    读不到文件就静默跳过——填快照是锦上添花，不该让一条本来合格的 finding
    因此记不下来。

    ★ **无条件覆盖模型给的值**，这一条与上面第 1 条理由是同一件事，而这里曾经
    写着"evidence 里已有 snippet 时也不覆盖（模型真给了就用它的）"——**自相矛盾**。
    实测（real-quota）打出来的三条：

      · F-010/F-011 的 "snippet" 是**模型的笔记**：「# review note: 第 14 轮推理
        中标注 ydata/views.py:117 应为 Attachment 删除视图（IDOR）」。读者被告知
        "117 行有问题"，看到的却是一句自述。
      · F-008 的 "snippet" 是**拼的**：「18 | DEBUG = True」与「49 |
        DATABASE_PASSWORD = ...」之间夹着 `...`，而磁盘上这两行隔着 30 行。

    三条都带着行号格式，所以**格式检查抓不到**——核对脚本当时只验格式不验来源，
    给了 9/11 个绿勾。`snippet` 的定义就是"磁盘原文"：读者拿它核对指控，不打开
    文件也能看见第 60 行是哪一句。模型提供的东西无论多好都改变不了这个定义，
    而系统手里本来就有原文——两者不是"哪个更好"的取舍，是**权威来源**的问题。
    读不到就留空：报告里没有快照，读者知道自己要去开文件；填一段非原文，
    读者会以为已经核过了。
    """
    ev = raw.get("evidence")
    if not isinstance(ev, dict):
        return
    ev.pop("snippet", None)          # 模型给的一律作废，以磁盘为准
    rel = str(raw.get("file") or "").replace("\\", "/").lstrip("./")
    try:
        line = int(raw.get("line") or 0)
        end = int(raw.get("end_line") or line)
    except (TypeError, ValueError):
        return
    if not rel or line < 1:
        return
    try:
        lines = ctx.read_lines(rel)
    except Exception:
        return
    if line > len(lines):
        return
    end = max(line, min(end, len(lines)))
    lo = max(1, line - before)
    hi = min(len(lines), end + after)
    if hi - lo + 1 > max_lines:
        hi = lo + max_lines - 1
    ev["snippet"] = "\n".join(f"{i:>5} | {lines[i - 1]}" for i in range(lo, hi + 1))


def _t_record_finding(ctx: ToolContext, args: dict) -> ToolResult:
    raw = dict(args)
    raw.setdefault("audit_layer", "L2")
    _fill_snippet(ctx, raw)
    ok, msg = ctx.ledger.record_finding(raw, turn=ctx.turn)
    if not ok:
        return ToolResult(False, f"记录被拒绝：{msg}\n\n"
                                 f"请补齐后重新调用 record_finding。",
                          error="contract")
    fid = msg.split("已记录 ")[-1].split("（")[0] if "已记录" in msg else ""
    return ToolResult(True, msg + (
        "\n下一步：若 severity 为 HIGH/CRITICAL，必须调用 adversarial_verify "
        "对该 finding 做对抗验证（验证者会主动尝试证伪），否则无法收口。"
        if str(args.get("severity", "")).upper() in ("HIGH", "CRITICAL") else
        "\n提醒：记录完后检查是否还有引擎候选未处置。"), {"finding_id": fid})


def _t_set_coverage(ctx: ToolContext, args: dict) -> ToolResult:
    ok, msg = ctx.ledger.set_coverage(
        str(args["coverage_class"]), str(args["status"]), str(args.get("note") or ""),
        evidence_refs=args.get("evidence_refs") or [], turn=ctx.turn)
    if not ok:
        return ToolResult(False, f"设置被拒绝：{msg}", error="contract")
    pend = ctx.ledger.pending_coverage()
    tail = (f"\n仍未落终态的 C 类：{['、'.join(e.coverage_class for e in pend)]}"
            if pend else "\n✅ 七个 C 类已全部落到终态。")
    return ToolResult(True, msg + tail, {"pending": len(pend)})


def _t_dispose_candidate(ctx: ToolContext, args: dict) -> ToolResult:
    ok, msg = ctx.ledger.dispose_candidate(
        str(args["candidate_id"]), str(args["status"]), str(args.get("reason") or ""),
        finding_id=str(args.get("finding_id") or ""), turn=ctx.turn)
    if not ok:
        return ToolResult(False, f"处置被拒绝：{msg}", error="contract")
    left = len(ctx.ledger.open_candidates)
    tail = "" if left < 8 else ("　★ 待处置还有 %d 条，后面建议改用 dispose_candidates "
                                "成组处置：同一类判据的候选放一组，理由写一次。" % left)
    return ToolResult(True, f"{msg}。剩余待处置候选 {left} 条。{tail}",
                      {"remaining": left})


# 成组处置的理由下限。**这个数字不是拍脑袋**：real-quota 那次运行里模型手动
# 处置的 21 条候选全部有实质理由，最短的一条 24 字符；real-reap 全部 46 条最短
# 30 字符、中位 66。24 是「实测里确实写出来过的最短合格理由」，低于它的基本是
# 「误报」「不是问题」这类套话。逐条处置不设这个门槛（`dispose_candidate` 只要求
# 非空）——因为上一条理由就在模型眼前，「同上」在那里是合法且诚实的表达。
REASON_MIN = 24


def _t_dispose_candidates(ctx: ToolContext, args: dict) -> ToolResult:
    """成组处置。**每组一个判断，理由写一次。**

    ★ 这个工具是被一次实测失败逼出来的（real-quota）：

    模型在倒数第二轮写下了 `dispose ALL candidates (34 engine + 11 recall =
    45 calls) + set_coverage 7`，然后输出撞上长度上限被截断——**45 条一条
    都没发出去**，那次运行的 58 条候选里有 37 条停在 open，召回从 80% 掉到
    40%。但它并不是没想清楚：同一批候选在 real-reap 里的理由是

        C0001  app/admin/views.py:62   …未做同域校验 → 已并入 F-004
        C0002  app/admin/views.py:62   同上，……并入 F-004
        C0003  app/admin/views.py:134  同上，……并入 F-004
        …（同一模式共 10 条，10 遍「同上」）

    **模型早就按语义分好组了，是工具形态逼它把同一句判断写十遍。**
    批量工具省的不是"思考"，是逐条重述同一个判断的结构开销。

    两种拒绝的边界（模型需要能区分，否则会把可修复的失败当成整体失败）：

      · **调用格式错误**（组内缺字段、status 不在枚举里、理由过短、id 跨组
        重复）→ **整批拒绝，一条都不执行**。半执行会让账本状态变得说不清，
        而模型重发整个调用几乎不花额外代价。
      · **账本层面的拒绝**（候选 id 不存在、confirmed 没给 finding_id）→
        只影响那一条，同组其余照常生效，并逐条列在返回里。这类失败是数据
        问题，不该连坐。

    为什么 record_finding **没有**对应的批量版：每条 finding 的四项证据
    （sink / source / reachability / sanitizer_check）必须**单独成立**，
    批量只会鼓励复制粘贴证据——而"证据看起来像真的"正是本项目最防的一件事。
    候选处置的理由则可以共享，因为同一类候选本来就该用同一条判据。
    """
    raw_items = args.get("items")
    if not isinstance(raw_items, list) or not raw_items:
        return ToolResult(False, "items 必须是非空数组，每个元素形如 "
                                 '{"candidate_ids": ["C0001","C0002"], '
                                 '"status": "dismissed", "reason": "……"}',
                          error="contract")

    groups: list[tuple[list[str], str, str, str]] = []
    for gi, it in enumerate(raw_items, 1):
        if not isinstance(it, dict):
            return ToolResult(False, f"items[{gi}] 应为对象，收到 {type(it).__name__}",
                              error="contract")
        ids = it.get("candidate_ids")
        if ids is None:                      # 容错：模型可能写成单数键
            one = it.get("candidate_id")
            ids = [one] if one else []
        if isinstance(ids, str):
            ids = [ids]
        if not isinstance(ids, list):
            return ToolResult(False, f"items[{gi}].candidate_ids 应为数组，"
                                     f"收到 {type(ids).__name__}", error="contract")
        ids = [str(x).strip() for x in ids if str(x).strip()]
        if not ids:
            return ToolResult(False, f"items[{gi}] 没有给出任何 candidate_ids。"
                                     "若只想处置一条，用 dispose_candidate 更直接。",
                              error="contract")

        status = str(it.get("status") or "")
        if status not in ("confirmed", "dismissed", "deferred"):
            return ToolResult(False, f"items[{gi}].status 必须是 "
                                     f"confirmed/dismissed/deferred，收到 {status!r}",
                              error="contract")
        reason = str(it.get("reason") or "").strip()
        if len(reason) < REASON_MIN:
            return ToolResult(
                False,
                f"items[{gi}] 的理由只有 {len(reason)} 字符，少于 {REASON_MIN}。"
                f"这一句要盖住 {len(ids)} 条候选（{', '.join(ids[:4])}"
                f"{'…' if len(ids) > 4 else ''}），它会被原样写进报告——"
                "必须能独立读懂，且说清**这一类**的共同判据是什么。"
                "（「误报」「不是问题」这类套话不算理由。）",
                error="contract")
        fid = str(it.get("finding_id") or "")
        if status == "confirmed" and not fid:
            return ToolResult(False, f"items[{gi}] 为 confirmed，必须给出 finding_id"
                                     "——确认命中却指不到具体 finding，报告里就断了链。",
                              error="contract")
        groups.append((ids, status, reason, fid))

    # id 在同一批次里出现两次 = 模型对自己的判断不确定（先 dismissed 又
    # confirmed？）。与其猜它想表达什么，不如退回去让它重写。
    seen: dict[str, int] = {}
    for gi, (ids, *_rest) in enumerate(groups, 1):
        for cid in ids:
            if cid in seen:
                return ToolResult(
                    False, f"候选 {cid} 在同一批次里被处置了两次"
                           f"（第 {seen[cid]} 组和第 {gi} 组）。"
                           "请把每组要处置的 id 分清楚后重新提交——"
                           "同一条候选只能有一个结论。", error="contract")
            seen[cid] = gi

    rows, failures = [], []
    by_status = {"confirmed": 0, "dismissed": 0, "deferred": 0}
    n_ok = 0
    for ids, status, reason, fid in groups:
        got = []
        for cid in ids:
            ok, msg = ctx.ledger.dispose_candidate(cid, status, reason,
                                                   finding_id=fid, turn=ctx.turn)
            if ok:
                got.append(cid)
                n_ok += 1
                by_status[status] += 1
            else:
                failures.append(f"{cid}：{msg}")
        if got:
            files: list[str] = []
            for cid in got:
                f = ctx.ledger.candidates[cid].file
                if f not in files:
                    files.append(f)
            where = "、".join(files[:2]) + (f" 等 {len(files)} 个文件"
                                            if len(files) > 2 else "")
            rows.append(f"· {len(got)} 条 → {status}"
                        + (f"（{fid}）" if fid else "") + f"：{where or '（无位置）'}")

    L = [f"成组处置完成：{len(groups)} 组，{n_ok} 条候选落终态"
         f"（confirmed {by_status['confirmed']} / dismissed {by_status['dismissed']}"
         f" / deferred {by_status['deferred']}）。"]
    L += ["  " + r for r in rows]
    if failures:
        L.append(f"⚠️ {len(failures)} 条被账本拒绝（**其余已生效，不必重发本调用**）：")
        L += ["  ✗ " + f for f in failures[:10]]
        if len(failures) > 10:
            L.append(f"  …另有 {len(failures) - 10} 条未列出")
    left = len(ctx.ledger.open_candidates)
    L.append("✅ 引擎候选与对账线索**已全部处置完毕**。" if left == 0
             else f"剩余待处置候选 {left} 条（调 list_candidates 可看完整清单）。")
    return ToolResult(True, "\n".join(L),
                      {"disposed": n_ok, "failed": len(failures),
                       "remaining": left, "by_status": by_status})


# ================================================================ F 收敛

def _t_conclude(ctx: ToolContext, args: dict) -> ToolResult:
    """收口判定。**账本说不能收就不能收**——不靠模型自觉。

    ★ 收口前**无条件做一次收敛对账**（06 §5.8）——不看预算用掉多少。
    这是对账唯一不可绕过的触发点：主循环里那次有 `recall_after_ratio` 门槛，
    而一次跑得很顺、很早就想收口的运行，恰恰是从来没被问过
    "你说过的都记下了吗"的那一次。跑得越顺，越需要有人问这一句。
    """
    ctx.ledger.recall_scan(ctx.turn)
    blockers = ctx.ledger.blockers()
    if blockers and not args.get("force"):
        return ToolResult(
            False,
            "现在还不能收口，以下硬性缺口未闭合：\n"
            + "\n".join(f"  {i+1}. {b}" for i, b in enumerate(blockers))
            + "\n\n请先逐项处理。（如确有正当理由必须收口，"
              "可带 force=true 再次调用，但报告中会声明为**未完成审计**。）",
            {"blockers": blockers}, error="blocked")

    n_find = len([f for f in ctx.ledger.findings.values() if f.is_active])
    L = ["收口检查通过。", f"  有效 findings: {n_find} 条"]
    if args.get("force"):
        L.append("  ⚠️ force=true 强制收口，报告中必须声明未闭合项："
                 + "；".join(blockers))
    return ToolResult(True, "\n".join(L), {"forced": bool(args.get("force")),
                                           "blockers": blockers})


# ================================================================ 组装

def build_registry(ctx: ToolContext) -> ToolRegistry:
    # 本地后端不过脱敏：代码本来就没出域，脱敏只会让模型看不清它本该
    # 分析的东西（比如判断某个 SECRET_KEY 是不是真的生产密钥）。
    # 判据是「数据是否真的离开本机」，不是一刀切。
    local = bool(getattr(ctx.provider, "is_local", False))
    reg = ToolRegistry(ctx.cfg, sanitize=not local)
    C = ctx  # 闭包捕获

    # ---- A 侦察
    reg.register(Tool("list_files",
        "列出本次审计范围内的文件（含归因、语法版本、是否关键路径）。"
        "**开局第一步就该调用**，以及当你需要确认某个文件是否在范围内时。",
        obj({"filter": S("路径子串过滤，如 'account' 或 'views'"),
             "attribution": S("按归因过滤", enum=["project", "suspected", "vendored"]),
             "limit": I("最多返回条数，默认 80")}),
        lambda a: _t_list_files(C, a), group="A"))

    reg.register(Tool("read_code",
        "读取指定文件的代码（带行号）。**每次读的范围尽量窄**，只读你需要确认的部分。"
        "读过的区间会被记账，重复读同一段会提示你。",
        obj({"file": S("文件相对路径，如 app/account/backends.py"),
             "start": I("起始行（1 起），默认 1"),
             "end": I("结束行（含）"),
             "context_lines": I("未给 end 时读取的行数，默认 240")},
            ["file"]),
        lambda a: _t_read_code(C, a), group="A"))

    reg.register(Tool("search_code",
        "在代码里做正则搜索。用于：定位某个危险函数的全部调用点、"
        "找字符串形式的引用（Django URL / 配置项）、确认某模式在全仓库的出现情况。"
        "**搜完务必核对搜到的调用点是否就是你以为的那个符号**——同名函数在不同 app 里很常见。",
        obj({"pattern": S("Python 正则。特殊字符要转义，如 os\\.system"),
             "glob": S("限定文件范围，如 'app/**/*.py'"),
             "ignore_case": B("忽略大小写"),
             "in_scope_only": B("只搜在审文件（默认 true；设为 false 可含 vendored）"),
             "context_lines": I("每条命中附带的上下文行数"),
             "limit": I("最多命中数，默认 60")},
            ["pattern"]),
        lambda a: _t_search_code(C, a), group="A"))

    reg.register(Tool("get_entry_points",
        "列出所有外部可达入口（HTTP 路由 / XMLRPC 方法等）及其鉴权状态。"
        "**判断一个 sink 是否真的可被利用，必须从这里出发**："
        "无鉴权入口 + 可污染的数据流 = 可利用。",
        obj({"kind": S("按类型过滤", enum=["http_route", "xmlrpc", "cli", "fcgi"])}),
        lambda a: _t_entry_points(C, a), group="A"))

    reg.register(Tool("outline",
        "给出一个文件的符号骨架（函数/类 + 行号 + 装饰器），不返回函数体。"
        "**想了解一个陌生的大文件时先用它**，再针对性 read_code，可省大量 token。",
        obj({"file": S("文件相对路径"),
             "limit": I("最多返回符号数，默认 120")}, ["file"]),
        lambda a: _t_outline(C, a), group="A"))

    # ---- B 规则
    reg.register(Tool("list_candidates",
        "查看静态引擎产出的候选与收敛对账线索及其处置状态。"
        "**每个候选都必须处置到 confirmed/dismissed/deferred 并给出理由**，"
        "否则无法收口。\n"
        "★ 准备成组处置时用 group_by 归拢——它按 file/rule/source 分组并**列出"
        "每组的 id**，可以照着填 dispose_candidates。**归拢不等于判断**：同一个 "
        "rule 下的候选也可能结论不同，该分的还要分。",
        obj({"status": S("按状态过滤", enum=["open", "confirmed", "dismissed", "deferred"]),
             "source": S("按来源过滤：静态引擎，或收敛对账线索 recall",
                         enum=["semgrep", "bandit", "deps", "secret", "recall"]),
             "group_by": S("★归拢维度。给了就返回分组摘要（含每组 id），"
                           "不给则逐条平铺",
                           enum=["file", "rule", "source"])}),
        lambda a: _t_list_candidates(C, a), group="B"))

    # ---- C 推理
    reg.register(Tool("check_vendored",
        "查询文件的归因（项目代码 / vendored / 待裁决）及判定依据。"
        "**在记录任何 finding 之前必须先查**——vendored 代码的缺陷不计入项目漏洞，"
        "而这直接影响你的结论是否正确。特别注意「改造版」标记："
        "它表示这是被项目改过的 fork，**归因是项目代码**。",
        obj({"file": S("文件相对路径")}, ["file"]),
        lambda a: _t_check_vendored(C, a), group="C"))

    reg.register(Tool("find_symbol",
        "按名字查找符号定义（函数/类）。当 search_code 结果太多、"
        "或需要区分同名符号时使用。",
        obj({"name": S("符号名，如 delete_all_topic"),
             "exclude_vendored": B("排除 vendored 文件中的定义"),
             "limit": I("最多返回，默认 30")}, ["name"]),
        lambda a: _t_find_symbol(C, a), group="C"))

    reg.register(Tool("find_callers",
        "**反向**追踪：谁调用了这个函数。可达性推理的主力工具。"
        "从一个危险 sink 出发向上追溯，直到抵达外部入口，"
        "才能证明它是「真可达」还是「死代码」。索引解析不了的调用会明确告诉你原因，"
        "此时改用 search_code 按字符串搜。",
        obj({"name": S("被调用的函数名"),
             "file": S("限定在某文件内的定义上（同名函数多时必给）")}, ["name"]),
        lambda a: _t_find_callers(C, a), group="C"))

    reg.register(Tool("trace_calls",
        "**正向**追踪：这个函数调用了什么。用于快速摸清一个函数的执行路径，"
        "或确认它是否真的碰了数据库/文件系统/命令执行。",
        obj({"file": S("文件相对路径"),
             "symbol": S("函数限定名，如 ModelBackend.get_group_permissions")},
            ["file", "symbol"]),
        lambda a: _t_trace_calls(C, a), group="C"))

    # ---- D 验证（handler 在 verify.py 里注入，避免循环依赖）
    if ctx.provider is not None:
        from .verify import make_adversarial_tool
        reg.register(make_adversarial_tool(C))

    # ---- E 记录
    reg.register(Tool("record_finding",
        "记录一条确认的安全问题。**证据契约在此强制**：必须逐项给出 sink / source / "
        "reachability / sanitizer_check，缺任一项会被拒绝。这不是形式主义——"
        "四项齐备意味着你真的走完了数据流，而不是看到危险函数就报。"
        "若某路径上确实没有净化措施，就写明「无」，而不是留空。",
        obj({
            "title": S("一句话说明问题，如「XMLRPC delete_all_topic 缺少权限校验导致越权删除」"),
            "severity": S("严重度", enum=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]),
            "file": S("文件相对路径"),
            "line": I("行号（1 起）"),
            "end_line": I("结束行号"),
            "function": S("所在函数限定名"),
            "category": S("类别，如 sql_injection / os_command_injection / "
                          "missing_authorization / path_traversal / hardcoded_secret"),
            "coverage_class": S("对应覆盖类", enum=CoverageClass.all_ids()),
            "exploitability": S("可利用性（与 severity 独立判断）",
                                enum=["exploitable", "conditional",
                                      "not_exploitable", "unknown"]),
            "confidence": {"type": "number", "description": "置信度 0-1"},
            "cwe": S("如 CWE-89"),
            "audit_layer": S("结论到达的推理层", enum=["L1", "L2", "L3"]),
            "evidence": obj({
                "snippet": S("命中的代码原文"),
                "sink": S("★危险操作所在行 + 代码片段"),
                "source": S("★污点来源，以及它是否可被外部控制"),
                "reachability": S("★从哪个外部入口可达，经过哪些函数"),
                "sanitizer_check": S("★枚举路径上的净化措施，并说明为何不足/无效；"
                                     "确实没有就写「无」"),
                "attack_path": A("攻击步骤，逐条"),
                "dataflow": A("数据流，逐跳，如 'req.arg → view.x → cmd'"),
                "mitigations_found": A("已存在的缓解措施（可能降低 severity）"),
            }, ["sink", "source", "reachability", "sanitizer_check"]),
            "remediation": obj({
                "summary": S("修复建议"),
                "patch_hint": S("补丁要点"),
            }),
        }, ["title", "severity", "file", "line", "category", "evidence"]),
        lambda a: _t_record_finding(C, a), group="E", mutating=True))

    reg.register(Tool("set_coverage",
        "为一个风险类（C1-C7）声明覆盖状态。**收口前七类必须全部落到终态**。"
        "声明 no_issue 时**必须给出 evidence_refs**（审了哪个文件哪几行），"
        "否则会被强制降级为 unverified——「审过没问题」必须能指出审了哪里。"
        "switched 到 skipped 也要给理由。",
        obj({
            "coverage_class": S("覆盖类", enum=CoverageClass.all_ids()),
            "status": S("状态", enum=["covered", "no_issue", "skipped", "out_of_scope"]),
            "note": S("说明：审了什么、结论依据"),
            "evidence_refs": A("no_issue 时必填：证据引用，如 ['app/account/views.py:1-120 已逐行审查']"),
        }, ["coverage_class", "status", "note"]),
        lambda a: _t_set_coverage(C, a), group="E", mutating=True))

    reg.register(Tool("dispose_candidate",
        "处置一个引擎候选。**理由必填**——无理由关闭等同于静默忽略，不可审计。"
        "确认命中时要做两件事：先 record_finding 拿到 id，再"
        "dispose_candidate(status=confirmed, finding_id=...)。"
        "驳回时理由要具体（如「该处 % 拼接的标识符经 qn() 引用，"
        "用户输入走参数化」），而不是「误报」两个字。",
        obj({
            "candidate_id": S("候选 id，如 C0001"),
            "status": S("处置结论", enum=["confirmed", "dismissed", "deferred"]),
            "reason": S("★必填：判断依据"),
            "finding_id": S("status=confirmed 时必填：对应的 finding id"),
        }, ["candidate_id", "status", "reason"]),
        lambda a: _t_dispose_candidate(C, a), group="E", mutating=True))

    reg.register(Tool("dispose_candidates",
        "**成组处置候选——同一类判据的候选放一组，理由写一次。**"
        "待处置超过三五条时用它，比逐条 dispose_candidate 省得多。"
        "两个自然用法：审完一个文件后，把它名下的一批候选一并处置；"
        "收口前把剩余的按模式归拢，一次交清。\n"
        "一组的边界是「同一个判断」：同一类模式（如同一文件里 10 处 "
        "HTTP_REFERER → redirect）、同一条数据流的多个报告点、或引擎对同一处"
        "代码的重复告警。**不要为了让条数看着少，把无关文件塞进同一组**——"
        "组的理由会被原样写进报告，一句含糊的话会同时废掉它盖住的所有位置。\n"
        f"每条理由至少 {REASON_MIN} 字符且要能独立读懂（读报告的人不会去翻"
        "你上一条理由）。格式错误（缺字段、理由过短、id 跨组重复）会**整批"
        "拒绝、一条都不执行**；账本层面的拒绝（如 id 不存在）只影响那一条，"
        "其余照常生效——那时**不必重发本调用**。",
        obj({
            "items": A("处置分组，一组 = 一个判断", items=obj({
                "candidate_ids": A("本组的候选 id，如 ['C0001','C0002']。"
                                   "同组必须是同一个判断"),
                "status": S("本组处置结论", enum=["confirmed", "dismissed", "deferred"]),
                "reason": S(f"★必填：本组的判断依据，至少 {REASON_MIN} 字符。"
                            "说清这一类为什么成立或不成立，而不是复述已说过的"),
                "finding_id": S("status=confirmed 时必填：对应的 finding id"),
            }, ["candidate_ids", "status", "reason"])),
        }, ["items"]),
        lambda a: _t_dispose_candidates(C, a), group="E", mutating=True))

    # ---- F 收敛
    reg.register(Tool("conclude",
        "提交最终结论。只有在覆盖度七类全部落终态、所有候选已处置、"
        "且所有 HIGH/CRITICAL 已对抗验证后才会通过——**账本说了算，不是你说完成就完成**。"
        "被拒时返回的是具体缺口清单，请逐项补齐。",
        obj({"summary": S("一段话总结本次审计的发现与整体判断"),
             "limitations": A("本次审计的局限性（未覆盖的部分、不确定的结论）"),
             "force": B("确实无法闭合时强制收口（报告中会声明为未完成）")}),
        lambda a: _t_conclude(C, a), group="F", mutating=True))

    return reg


def tool_group_summary(reg: ToolRegistry) -> str:
    lines = ["可用工具："]
    for g, label in (("A", "侦察"), ("B", "规则"), ("C", "推理"),
                     ("D", "验证"), ("E", "记录"), ("F", "收敛")):
        ts = reg.by_group(g)
        if ts:
            lines.append(f"  [{g}] {label}：" + "、".join(t.name for t in ts))
    return "\n".join(lines)
