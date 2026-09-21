# -*- coding: utf-8 -*-
"""入口契约（Scope Contract）。

设计依据：06 §2.2。**在 Agent 启动之前由代码确定，模型不可协商。**

确定的内容：
    · in_scope      在审计范围内的文件（排除 vendored / 测试 / 迁移 / 生成代码）
    · vendored      判定为内嵌代码的文件 + 依据 + 置信度
    · suspected     疑似但未确认 → **不静默丢弃**，进 Agent 的待裁决清单
    · entry_points  外部入口（HTTP 路由 / XML-RPC / CLI），含鉴权状态
    · critical_paths 命中 security_critical_paths 的文件
    · budget        轮次 + token 预算

**为什么入口清单必须由代码给**：实测表明 Agent 在第 1–2 轮会花在"建图"上
（先 search 符号、再读 urls.py/settings.py）。把确定性信息直接喂给它，
省下的轮次用在真正的语义判断上。
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from . import parse as parsers
from .config import Config
from .util import match_any, read_text
from .vendored import VendoredIndex


# ---------------------------------------------------------------- 数据结构

@dataclass
class FileInfo:
    path: Path
    rel: str
    lines: int = 0
    size: int = 0
    py_version: str = "unknown"
    parse_engine: str = "none"
    parse_ok: bool = False
    parse_error: str = ""
    attribution: str = "project"          # project | vendored | suspected
    library: str | None = None
    forked_from: str | None = None        # 非 None = 改造版库代码，缺陷归项目
    attribution_reasons: list[str] = field(default_factory=list)
    is_sensitive: bool = False
    sensitive_reason: str = ""
    in_critical_path: bool = False
    critical_pattern: str = ""
    trivial: bool = False                # 空文件 / 纯注释 / 单行声明——无代码可审
    trivial_reason: str = ""

    @property
    def is_project_code(self) -> bool:
        return self.attribution == "project"


@dataclass
class EntryPoint:
    kind: str                             # http_route | xmlrpc | cli | fcgi
    file: str
    line: int
    target: str                           # 路由模式 / 方法名
    view: str = ""                        # 解析出的视图（module.func）
    auth: str = "unknown"                 # required | none | unknown —— 认证（你是谁）
    auth_evidence: str = ""
    # ★ 授权（你能做什么）与认证是两回事，必须分开记录。
    # 实测教训：本靶子 `ylinux_xmlrpc.delete_all_topic` 有 `has_auth(user, passwd)`，
    # 只做 authenticate()（认证），随后 `Topic.objects.all().delete()` 毫不校验归属。
    # 若把 auth 与 authz 混为一谈，这里会被判成"无鉴权"（错），
    # 而真相是"任意注册用户可清空全站"——**更严重**，且修复方式完全不同。
    authz: str = "unknown"                # object_level | present | none | unknown
    authz_evidence: str = ""
    note: str = ""

    def to_dict(self) -> dict:
        return {
            "kind": self.kind, "file": self.file, "line": self.line,
            "target": self.target, "view": self.view,
            "auth": self.auth, "auth_evidence": self.auth_evidence,
            "authz": self.authz, "authz_evidence": self.authz_evidence,
        }

    @property
    def risk_label(self) -> str:
        """给报告与 Agent 用的一句话标签。

        ★ 措辞刻意保持"线索"而非"结论"的口气。入口提取是**线索生成**：
        静态看到的只是"这里没有对象级授权判定"，而它是不是漏洞取决于
        这个操作该不该做对象级校验（读全局分类不需要，删他人主题需要）。
        把它写成"🚨越权"就是在替 Agent 下结论，而且会是错的。
        """
        if self.auth == "none":
            return "🚨无认证（任意人可达）"
        if self.auth == "required" and self.authz == "none":
            return "⚠️有认证、未见对象级授权（待核验）"
        if self.auth == "required" and self.authz == "unknown":
            return "❓认证有、授权未探明"
        if self.auth == "required" and self.authz in ("object_level", "present"):
            return f"✅已鉴权（{self.authz}）"
        return "❓鉴权未知"


@dataclass
class ScopeContract:
    repo: Path
    files: dict[str, FileInfo] = field(default_factory=dict)
    entry_points: list[EntryPoint] = field(default_factory=list)
    unparseable: list[str] = field(default_factory=list)
    excluded: dict[str, str] = field(default_factory=dict)   # rel -> 排除原因
    vendored_index: VendoredIndex | None = None

    # ---------------------------------------------------------- 视图

    @property
    def in_scope(self) -> list[FileInfo]:
        """★ `suspected` **必须在范围内**。

        实测踩坑：最初把 suspected 排除在 in_scope 之外，结果 `lib/ylinux_xmlrpc.py`
        （真实项目代码，含越权 `delete_all_topic` 与任意写入 `new_media`）
        被静默丢掉——正是本工具承诺绝不做的事。

        语义区分：
          · vendored  → 不在范围（不计入项目漏洞），但要报告归因
          · suspected → **在范围内照审**，同时标记待裁决；若最终确认是 vendored，
                        其 finding 通过 `attribution` 过滤，但代码**已经看过了**
        """
        return [f for f in self.files.values()
                if f.attribution in ("project", "suspected")
                and f.parse_ok and not f.trivial and f.rel not in self.excluded]

    @property
    def vendored(self) -> list[FileInfo]:
        return [f for f in self.files.values() if f.attribution == "vendored"]

    @property
    def suspected(self) -> list[FileInfo]:
        return [f for f in self.files.values() if f.attribution == "suspected"]

    def get(self, rel: str) -> FileInfo | None:
        posix = rel.replace("\\", "/")
        if posix in self.files:
            return self.files[posix]
        for k, v in self.files.items():
            if k.endswith(posix) or posix.endswith(k):
                return v
        return None

    def partition(self) -> dict[str, int]:
        """**互斥**归类，保证各桶之和 == 文件总数。

        为什么必须互斥：非互斥计数会出现 38+20+8+1+40 = 107 > 105 这种和不上账的情况。
        审计报告里数字对不上会直接损害整份报告的可信度，所以宁可多写几行保证可核。
        优先级：排除 > 解析失败 > vendored > 无代码 > 待裁决 > 项目。
        """
        b = {"excluded": 0, "unparseable": 0, "vendored": 0,
             "trivial": 0, "suspected": 0, "project": 0}
        for f in self.files.values():
            if f.rel in self.excluded:
                b["excluded"] += 1
            elif not f.parse_ok:
                b["unparseable"] += 1
            elif f.attribution == "vendored":
                b["vendored"] += 1
            elif f.trivial:
                b["trivial"] += 1
            elif f.attribution == "suspected":
                b["suspected"] += 1
            else:
                b["project"] += 1
        return b

    def summary(self) -> dict:
        by_ver: dict[str, int] = {}
        for f in self.files.values():
            by_ver[f.py_version] = by_ver.get(f.py_version, 0) + 1
        p = self.partition()
        return {
            "total_files": len(self.files),
            "partition": p,
            "in_scope": len(self.in_scope),
            "vendored": p["vendored"],
            "suspected": p["suspected"],
            "forked": sum(1 for f in self.files.values() if f.forked_from),
            "trivial": p["trivial"],
            "unparseable": p["unparseable"],
            "excluded": p["excluded"],
            "by_version": by_ver,
            "entry_points": len(self.entry_points),
            "critical_paths": sum(1 for f in self.files.values() if f.in_critical_path),
            "total_lines": sum(f.lines for f in self.files.values()),
            "in_scope_lines": sum(f.lines for f in self.in_scope),
        }

    def to_prompt(self, max_files: int = 200) -> str:
        """渲染成给 Agent 的入口摘要（不是全文——06 §2.2）。"""
        s = self.summary()
        p = s["partition"]
        L: list[str] = []
        L.append("## 审计范围（由工具确定，不可协商）")
        L.append(f"- 仓库：{self.repo.name}")
        L.append(f"- 文件：{s['total_files']} 个 / {s['total_lines']} 行；"
                 f"**在范围内 {s['in_scope']} 个 / {s['in_scope_lines']} 行**")
        L.append(f"- 语言版本：{s['by_version']}")
        L.append("")
        L.append(f"  文件归类（互斥，合计 {sum(p.values())} = 总数 {s['total_files']}）：")
        L.append(f"    · 项目代码      {p['project']:3d}  —— **本次审计对象**")
        L.append(f"    · 待裁决(继承)  {p['suspected']:3d}  —— "
                 "**在范围内必须照审**，另需 check_vendored 裁决归因")
        L.append(f"    · 纯内嵌库      {p['vendored']:3d}  —— 不计入项目漏洞，仅在报告中声明归因")
        L.append(f"    · 无代码        {p['trivial']:3d}  —— 空文件/纯注释，确认无漏洞可审")
        L.append(f"    · 已排除        {p['excluded']:3d}  —— 匹配排除规则（测试/迁移等）")
        L.append(f"    · 解析失败      {p['unparseable']:3d}  —— "
                 "**⚠️ 报告中必须声明未覆盖，不得算作已审**")
        if s["forked"]:
            L.append("")
            L.append(f"  ⚠️ 其中 **{s['forked']} 个是改造版库代码**——源自第三方库但已被项目修改，"
                     "**缺陷归项目所有**，不得因「看着像框架代码」而放过。")
        L.append("")
        L.append(f"- 敏感路径命中：{s['critical_paths']} 个")

        forked = [f for f in self.files.values() if f.forked_from]
        if forked:
            L.append("")
            L.append("## 改造版库代码（源自第三方库，但缺陷归项目）")
            for f in forked[:25]:
                L.append(f"- `{f.rel}` ← {f.forked_from}")

        if self.entry_points:
            L.append("")
            L.append(f"## 外部入口（{len(self.entry_points)} 个）")
            L.append("| 类型 | 位置 | 目标 | 鉴权 |")
            L.append("|---|---|---|---|")
            for ep in self.entry_points[:60]:
                L.append(f"| {ep.kind} | `{ep.file}:{ep.line}` | `{ep.target[:52]}` | {ep.auth} |")
            if len(self.entry_points) > 60:
                L.append(f"| … | 另有 {len(self.entry_points) - 60} 个 | | |")

        pending = [f for f in self.suspected if not f.trivial]
        if pending:
            L.append("")
            L.append("## 待裁决的内嵌嫌疑（conclude 前必须全部处理）")
            for f in pending[:40]:
                L.append(f"- `{f.rel}` — {'; '.join(f.attribution_reasons)[:70]}")

        if self.in_scope:
            L.append("")
            L.append("## 在范围文件")
            L.append("```")
            for f in sorted(self.in_scope, key=lambda x: -x.lines)[:max_files]:
                mark = " [敏感]" if f.is_sensitive else ""
                mark += " [关键路径]" if f.in_critical_path else ""
                L.append(f"{f.rel}  ({f.lines} 行, py{f.py_version}){mark}")
            if len(self.in_scope) > max_files:
                L.append(f"… 另有 {len(self.in_scope) - max_files} 个")
            L.append("```")
        return "\n".join(L)


# ---------------------------------------------------------------- 入口点提取

# Django 1.x: url(r'^x$', 'app.views.f', name=...) / (r'^x/', include(...))
_RE_DJANGO_URL = re.compile(
    r"""^\s*(?:url\s*\(\s*)?r?["']([^"']+)["']\s*,\s*"""
    r"""(?:(?P<inc>include\s*\((?P<inc_target>[^)]*)\))|"""
    r"""["'](?P<view>[\w\.]+)["']|(?P<callable>[\w\.]+))""",
    re.MULTILINE,
)
_RE_FLASK_ROUTE = re.compile(
    r"""@\s*\w+\s*\.\s*route\s*\(\s*["']([^"']+)["']""", re.MULTILINE
)
_RE_XMLRPC_METHODS = re.compile(r"XMLRPC_METHODS\s*=\s*[\(\[]", re.MULTILINE)
_RE_XMLRPC_DEF = re.compile(r"^\s*def\s+(\w+)\s*\(([^)]*)\)", re.MULTILINE)

_AUTH_DECORATORS = {
    "permission_required": "required",
    "login_required": "required",
    "user_passes_test": "required",
    "staff_member_required": "required",
    "csrf_exempt": "none",
}


def _extract_http_routes(rel: str, code: str) -> list[EntryPoint]:
    eps: list[EntryPoint] = []
    if not rel.endswith("urls.py"):
        return eps
    for i, line in enumerate(code.splitlines(), 1):
        if line.strip().startswith("#"):
            continue
        m = _RE_DJANGO_URL.match(line)
        if not m:
            continue
        pattern = m.group(1)
        if m.group("inc"):
            target = f"include({(m.group('inc_target') or '').strip()})"
            eps.append(EntryPoint("http_route", rel, i, pattern, view="",
                                  auth="unknown", note=target))
        else:
            view = m.group("view") or m.group("callable") or ""
            if view and view not in ("include",):
                eps.append(EntryPoint("http_route", rel, i, pattern, view=view))
    for m in _RE_FLASK_ROUTE.finditer(code):
        ln = code[:m.start()].count("\n") + 1
        eps.append(EntryPoint("http_route", rel, ln, m.group(1), view=""))
    return eps


_RE_XMLRPC_KEY = re.compile(r"^[ \t]*XMLRPC_METHODS\s*[:=]\s*[\(\[]", re.M)
_RE_XMLRPC_PAIR = re.compile(
    r"\(\s*['\"]([\w\.]+)['\"]\s*,\s*['\"]([\w\.\-]+)['\"]\s*\)")

# 认证（你是谁）——函数体内的检查，与装饰器等价
_AUTH_BODY_PAT = re.compile(
    r"\b(authenticate|has_auth|check_password|check_token|verify_token|"
    r"login_required)\s*\(")
# 授权（你能做什么）——对象级归属校验或权限判定
_AUTHZ_OBJECT_PAT = re.compile(
    r"\b(?:[\w\.]*\.)?(?:user|owner|author|creator|uid|username)\s*(?:==|!=|in)\s*"
    r"|\.filter\s*\([^)]*\b(?:user|owner|author)\s*="
    r"|\bhas_perm\b|\bhas_module_perms\b|\bpermission_required\b|\bis_staff\b"
    r"|\bis_superuser\b|\bget_object_or_404\s*\(")


def _xmlrpc_registry(code: str) -> list[tuple[str, str, int]]:
    """解析 `XMLRPC_METHODS = (...)` 字面量，返回 [(view, 公开名, 行号)]。

    通用解析而非针对本靶子：先定位赋值点（要求后面紧跟括号，因此可跳过
    被注释掉的旧写法），再做括号配对取出整个字面量块，最后提取字符串对。
    """
    m = _RE_XMLRPC_KEY.search(code)
    if not m:
        return []
    i = m.end() - 1                       # 指向开括号
    depth, end = 0, i
    for j in range(i, min(len(code), i + 40000)):
        if code[j] in "([":
            depth += 1
        elif code[j] in ")]":
            depth -= 1
            if depth == 0:
                end = j
                break
    block = code[i:end + 1]
    out = []
    for mm in _RE_XMLRPC_PAIR.finditer(block):
        lineno = code.count("\n", 0, i + mm.start()) + 1
        out.append((mm.group(1), mm.group(2), lineno))
    return out


def _body_auth_scan(code: str, func_name: str) -> tuple[str, str, str, str]:
    """在函数体内找认证与授权检查。返回 (auth, auth_evidence, authz, authz_evidence)。

    ★ 只看装饰器是不够的：老代码普遍把 `if not has_auth(...)` 写在函数体开头。
    本靶子 8 个 XMLRPC 方法全部如此——只扫装饰器会把它们全判成"无鉴权"（误报），
    而真相是"有认证、无对象级授权"（真问题，且修复方式完全不同）。
    """
    if not func_name:
        return ("unknown", "", "unknown", "")
    m = re.compile(r"^([ \t]*)def\s+" + re.escape(func_name) + r"\s*\(", re.M).search(code)
    if not m:
        return ("unknown", "", "unknown", "")
    indent = m.group(1)
    lines = code[m.start():].splitlines()
    body: list[str] = []
    for k, ln in enumerate(lines):
        if k > 0 and ln.strip() and not ln.startswith(indent + " ") \
                and not ln.startswith(indent + "\t"):
            break
        body.append(ln)
        if k > 400:
            break
    src = "\n".join(body)
    if len(src) < 20:
        return ("unknown", "", "unknown", "")

    am = _AUTH_BODY_PAT.search(src)
    auth = "required" if am else "none"
    aev = f"函数体内调用 {am.group(1)}()" if am else "装饰器与函数体内均未见认证检查"

    zm = _AUTHZ_OBJECT_PAT.search(src)
    if zm:
        authz = "present"
        zev = f"函数体内见授权判定：{zm.group(0).strip()[:60]}"
    elif am:
        # ★ 有认证但没有授权判定——最需要点名的组合
        authz = "none"
        zev = ("有认证（你是谁）但未见对象级授权（你能动谁）——"
               "任何通过认证的用户都可能操作他人资源")
    else:
        authz, zev = "unknown", ""
    return (auth, aev, authz, zev)


def _resolve_module_file(dotted: str, scope_files: dict[str, FileInfo]) -> str:
    """`ylinux_xmlrpc.delete_topic` → 仓库内的 rel 路径。"""
    parts = dotted.split(".")
    for cut in range(len(parts) - 1, 0, -1):
        mod = "/".join(parts[:cut])
        for cand in (f"{mod}.py", f"{mod}/__init__.py", f"app/{mod}.py",
                     f"lib/{mod}.py"):
            if cand in scope_files:
                return cand
    return ""


def _extract_xmlrpc(scope_files: dict[str, FileInfo]) -> list[EntryPoint]:
    """XML-RPC 方法逐个提取。

    ★ **每个注册方法都是一个独立的外部入口，必须逐条列出。**
    实测教训：最初把所有方法聚合成一条"XMLRPC_METHODS 注册表"，
    结果丢掉了整份报告里最关键的信息——哪个方法无鉴权、哪个有认证无授权。
    8 个方法的安全姿态各不相同，聚合成一条等于全部放弃。
    """
    eps: list[EntryPoint] = []
    for rel, fi in scope_files.items():
        code = read_text(fi.path)
        entries = _xmlrpc_registry(code)
        if not entries:
            if _RE_XMLRPC_METHODS.search(code):
                eps.append(EntryPoint("xmlrpc", rel, 1, "XMLRPC_METHODS 注册表",
                                      auth="unknown",
                                      note="检测到注册表但未能解析出具体方法，"
                                           "需人工核验认证与授权"))
            continue

        # 注册表里写的是模块名（ylinux_xmlrpc.delete_topic），
        # 真正的函数体在另一个文件里，需单独读。
        target_rel = _resolve_module_file(entries[0][0], scope_files)
        target_code = read_text(scope_files[target_rel].path) \
            if target_rel in scope_files else ""

        for view, public, lineno in entries:
            func = view.rsplit(".", 1)[-1]
            auth, aev, authz, zev = _body_auth_scan(target_code, func)
            eps.append(EntryPoint(
                "xmlrpc", rel, lineno, public, view=view,
                auth=auth, auth_evidence=aev, authz=authz, authz_evidence=zev,
                note=f"XML-RPC 公开方法，实现见 "
                     f"{target_rel or view.replace('.', '/') + '.py'}:{func}()",
            ))
    return eps


def _resolve_auth(scope: ScopeContract, parsed: dict[str, parsers.ParsedModule]) -> None:
    """把路由上的 view 映射到解析出的函数，读取其装饰器判定鉴权状态。"""
    by_qualname: dict[str, parsers.FuncInfo] = {}
    by_shortname: dict[str, list[tuple[str, parsers.FuncInfo]]] = {}
    for rel, m in parsed.items():
        if not m.ok:
            continue
        for f in m.functions:
            by_qualname[f"{rel}|{f.name}"] = f
            by_shortname.setdefault(f.name, []).append((rel, f))

    src_cache: dict[str, str] = {}

    def _src(rel: str) -> str:
        if rel not in src_cache:
            fi = scope.files.get(rel)
            src_cache[rel] = read_text(fi.path) if fi is not None else ""
        return src_cache[rel]

    for ep in scope.entry_points:
        if ep.kind != "http_route" or not ep.view:
            continue
        func_name = ep.view.rsplit(".", 1)[-1]
        cands = by_shortname.get(func_name, [])
        if not cands:
            continue
        # 优先取同模块路径的候选
        best_rel, best = cands[0]
        for rel, f in cands:
            if ep.view.replace(".", "/").split("/")[-1:][0] in rel or rel.endswith(
                ep.view.replace(".", "/") + ".py"
            ):
                best_rel, best = rel, f
                break

        # ① 装饰器
        decs = " ".join(best.decorators)
        for dec, status in _AUTH_DECORATORS.items():
            if dec in decs:
                ep.auth = status
                ep.auth_evidence = f"@{dec} @ {best.lineno}"
                break
        else:
            ep.auth = "none" if best.decorators == [] else "unknown"
            ep.auth_evidence = f"装饰器：{best.decorators or '无'}"

        # ② 函数体补充扫描。
        # ★ 不一致会误报：只认装饰器时，一个用 `if not request.user.is_authenticated`
        # 做检查的视图会被判成"无鉴权"——报告的可信度就是这样丢掉的。
        # 反过来，装饰器证明了认证之后，还必须单独看有没有**对象级授权**：
        # `@login_required` 只保证"你是某个用户"，不保证"这个资源是你的"。
        ba, bae, bz, bze = _body_auth_scan(_src(best_rel), func_name)
        if ep.auth != "required" and ba == "required":
            ep.auth = "required"
            ep.auth_evidence = (ep.auth_evidence + "；" + bae).strip("；")
        if bz != "unknown":
            ep.authz = bz
            ep.authz_evidence = bze


def _is_trivial(code: str) -> bool:
    """无代码可审？去掉空行/注释/编码声明/文档字符串后 ≤1 行即视为无实质代码。"""
    kept = []
    in_doc = False
    for raw in code.splitlines():
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        if s.startswith(('"""', "'''")):
            q = s[:3]
            if not (s.endswith(q) and len(s) > 3):
                in_doc = not in_doc
            continue
        if in_doc:
            continue
        if s.startswith(("import ", "from ")) or s.startswith("__all__"):
            continue
        kept.append(s)
        if len(kept) > 1:
            return False
    return True


# ---------------------------------------------------------------- 主流程

# 已知的生成/第三方目录（不进范围，但**要报告**，不能静默丢）
_SKIP_DIRS = {
    "__pycache__", ".git", ".svn", ".hg", "node_modules", ".venv", "venv",
    "env", ".tox", ".mypy_cache", ".pytest_cache", "htmlcov", ".idea", ".vscode",
}


def collect(cfg: Config) -> tuple[ScopeContract, parsers.ParseReport]:
    """构建入口契约。返回 (ScopeContract, ParseReport)。"""
    repo = Path(cfg.repo).resolve()
    scope = ScopeContract(repo=repo)

    # 1. 遍历
    py_files: list[Path] = []
    for p in repo.rglob("*"):
        if not p.is_file():
            continue
        if any(part in _SKIP_DIRS for part in p.parts):
            continue
        if p.suffix.lower() not in cfg.scan.include_extensions:
            continue
        py_files.append(p)

    # 2. 排除规则
    for p in py_files:
        rel = p.relative_to(repo).as_posix()
        hit = match_any(rel, cfg.scan.exclude)
        if hit:
            scope.excluded[rel] = f"匹配排除规则「{hit}」"

    # 3. 逐文件建 FileInfo + 解析
    #    ★ 解析必须在 vendored 之前：归因的第二遍「反向证据」需要 import 关系
    sources: list[tuple[str, str]] = []
    for p in py_files:
        rel = p.relative_to(repo).as_posix()
        code = read_text(p)
        sources.append((rel, code))
        scope.files[rel] = FileInfo(
            path=p, rel=rel, lines=code.count("\n") + 1,
            size=p.stat().st_size if p.exists() else 0,
        )

    report = parsers.parse_many(sources)

    # 4. vendored 识别（两遍：L1/L2/L3 内容级 + import 反向证据）
    vindex = VendoredIndex(repo, cfg)
    vindex.scan(py_files, parsed=report.modules)
    scope.vendored_index = vindex

    for rel, fi in scope.files.items():
        m = report.modules.get(rel)
        if m:
            fi.py_version = m.version
            fi.parse_engine = m.engine
            fi.parse_ok = m.ok
            fi.parse_error = m.error
        if not fi.parse_ok:
            scope.unparseable.append(rel)

        # 空文件 / 纯注释：无代码可审。必须显式标记而不是留着让 Agent 白跑一轮——
        # 实测 `lib/__init__.py` 因命中 `lib/**` 被判 suspected，进了待裁决清单，
        # 但它一行代码都没有，裁决它纯属浪费预算。
        if _is_trivial(read_text(fi.path)):
            fi.trivial = True
            fi.trivial_reason = "无实质代码（空文件/纯注释/单行声明）"

        v = vindex.get(rel)
        if v:
            fi.attribution = v.verdict
            fi.library = v.library
            fi.forked_from = v.forked_from
            fi.attribution_reasons = v.reasons

        # 敏感路径 / 关键路径
        hit = match_any(rel, cfg.sensitive_paths) or match_any(
            rel, cfg.gate.security_critical_paths
        )
        if hit:
            fi.is_sensitive = True
            fi.sensitive_reason = f"路径命中「{hit}」"
        else:
            # 内容特征
            for pat in cfg.sensitive_content_patterns:
                try:
                    if re.search(pat, read_text(fi.path)[:20000]):
                        fi.is_sensitive = True
                        fi.sensitive_reason = f"内容命中「{pat[:40]}」"
                        break
                except re.error:
                    continue

        cp = match_any(rel, cfg.gate.security_critical_paths)
        if cp:
            fi.in_critical_path = True
            fi.critical_pattern = cp

    # 5. 入口点
    for rel, fi in scope.files.items():
        if rel in scope.excluded or fi.attribution == "vendored":
            continue
        eps = _extract_http_routes(rel, read_text(fi.path))
        scope.entry_points.extend(eps)
    scope.entry_points.extend(_extract_xmlrpc(
        {r: f for r, f in scope.files.items()
         if f.attribution == "project" and r not in scope.excluded}
    ))
    _resolve_auth(scope, report.modules)

    # 6. 排序：先按类型，再按文件
    order = {"xmlrpc": 0, "http_route": 1, "fcgi": 2, "cli": 3}
    scope.entry_points.sort(key=lambda e: (order.get(e.kind, 9), e.file, e.line))

    return scope, report
