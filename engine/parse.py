# -*- coding: utf-8 -*-
"""解析层：Python 2/3 双轨。

**为什么必须双轨**（设计 01 §4.4、README §6 实测）：
    Python 3.14 内置 ast        → 靶子 105 文件中 9 个语法失败
    parso 0.8.7                 → 已移除 Py2 grammar，0/105
    parso 0.7.1                 → 105/105 ✅
    Bandit 1.9.4                → 跳过 9 个文件（含 app/sessions/backends/base.py 等核心目标）
    Semgrep 1.177.0             → 105/105 ✅

**铁律**：解析失败**不得静默跳过**。必须计入 coverage 并在报告中声明——
用户必须能区分"审过了没问题"和"根本没审"（06 §4.3）。
"""
from __future__ import annotations

import ast
import warnings
from dataclasses import dataclass, field
from pathlib import Path

from .util import read_text


# ---------------------------------------------------------------- 数据结构

@dataclass
class FuncInfo:
    name: str
    lineno: int
    end_lineno: int
    args: list[str] = field(default_factory=list)
    decorators: list[str] = field(default_factory=list)
    is_method: bool = False
    class_name: str | None = None
    docstring: str = ""

    @property
    def qualified(self) -> str:
        return f"{self.class_name}.{self.name}" if self.class_name else self.name


@dataclass
class ClassInfo:
    name: str
    lineno: int
    end_lineno: int
    bases: list[str] = field(default_factory=list)
    methods: list[str] = field(default_factory=list)


@dataclass
class ImportInfo:
    module: str
    names: list[str] = field(default_factory=list)
    lineno: int = 0
    is_from: bool = False


@dataclass
class CallInfo:
    """调用点。`dotted` 是尽力而为的限定名（如 os.system），用于 sink 匹配。"""
    dotted: str
    lineno: int
    col: int = 0


@dataclass
class ParsedModule:
    rel: str
    version: str                       # "2" | "3" | "unknown"
    engine: str                        # "ast" | "parso" | "none"
    ok: bool
    error: str = ""
    lines: int = 0
    functions: list[FuncInfo] = field(default_factory=list)
    classes: list[ClassInfo] = field(default_factory=list)
    imports: list[ImportInfo] = field(default_factory=list)
    calls: list[CallInfo] = field(default_factory=list)
    source: str = ""

    # -------------------------------------------------- 查询

    def function_at(self, line: int) -> FuncInfo | None:
        """包含指定行的最内层函数。"""
        best = None
        for f in self.functions:
            if f.lineno <= line <= f.end_lineno:
                if best is None or f.lineno >= best.lineno:
                    best = f
        return best

    def enclosing_class(self, line: int) -> ClassInfo | None:
        best = None
        for c in self.classes:
            if c.lineno <= line <= c.end_lineno:
                if best is None or c.lineno >= best.lineno:
                    best = c
        return best

    def slice(self, start: int, end: int) -> str:
        ls = self.source.splitlines()
        s = max(0, start - 1)
        e = min(len(ls), end)
        return "\n".join(f"{i + 1}: {ls[i]}" for i in range(s, e))

    def imported_modules(self) -> set[str]:
        mods: set[str] = set()
        for imp in self.imports:
            if imp.module:
                mods.add(imp.module.split(".")[0])
            for n in imp.names:
                mods.add(n.split(".")[0])
        return mods


@dataclass
class ParseReport:
    modules: dict[str, ParsedModule] = field(default_factory=dict)
    unparseable: list[str] = field(default_factory=list)
    by_version: dict[str, int] = field(default_factory=dict)

    def summary(self) -> dict:
        return {
            "total": len(self.modules),
            "parsed_ok": sum(1 for m in self.modules.values() if m.ok),
            "unparseable": len(self.unparseable),
            "unparseable_files": self.unparseable,
            "by_version": dict(self.by_version),
            "engines": {
                e: sum(1 for m in self.modules.values() if m.engine == e)
                for e in ("ast", "parso", "none")
            },
        }


# ---------------------------------------------------------------- 版本探测

_PY2_MARKERS = (
    "print ", "except ", "raise ", "exec ", "has_key(", "unicode(",
    "cPickle", "xrange", "iteritems(", "basestring", "raw_input(",
)
_PY2_SIG = (
    # `except X, e:` —— Py2 独有
    r"except\s+[\w\.\(\)\[\]\s,]+\s*,\s*\w+\s*:",
    # `print "..."` / `print x` 语句
    r"^\s*print\s+[^(=\s]",
    # `raise E, v` / `raise E, v, tb`
    r"raise\s+\w+\s*,\s*\w+",
    # `0777` 八进制字面量
    r"\b0[0-7]{2,}\b",
    # `exec "code"`
    r"\bexec\s+[\"']",
    # 反引号 repr
    r"`[^`]+`",
)


def detect_version(code: str) -> tuple[str, str]:
    """返回 (version, evidence)。version ∈ {"3", "2", "unknown"}。

    以「能否被 Py3 ast 解析」为准（确定性），正则仅用于给出可解释的证据。
    """
    try:
        ast.parse(code)
        return ("3", "Python 3 ast 解析成功")
    except SyntaxError as e:
        py3_err = f"Py3 ast 失败于第 {e.lineno} 行: {e.msg}"
    except (ValueError, RecursionError) as e:
        py3_err = f"Py3 ast 异常: {type(e).__name__}"

    try:
        import parso
        parso.parse(code, version="2.7")
        return ("2", f"{py3_err}；parso 2.7 解析成功")
    except ImportError:
        return ("unknown", f"{py3_err}；parso 未安装")
    except Exception as e:
        return ("unknown", f"{py3_err}；parso 2.7 也失败: {type(e).__name__}")


# ---------------------------------------------------------------- Py3 (ast)

class _Py3Visitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.functions: list[FuncInfo] = []
        self.classes: list[ClassInfo] = []
        self.imports: list[ImportInfo] = []
        self.calls: list[CallInfo] = []
        self._class_stack: list[str] = []

    # -- 定义
    def visit_FunctionDef(self, node):
        self._add_func(node)

    def visit_AsyncFunctionDef(self, node):
        self._add_func(node)

    def _add_func(self, node):
        args = [a.arg for a in node.args.args]
        if node.args.vararg:
            args.append("*" + node.args.vararg.arg)
        if node.args.kwarg:
            args.append("**" + node.args.kwarg.arg)
        decs = []
        for d in node.decorator_list:
            try:
                decs.append(ast.unparse(d))
            except Exception:
                decs.append("<?>")
        self.functions.append(FuncInfo(
            name=node.name, lineno=node.lineno,
            end_lineno=getattr(node, "end_lineno", node.lineno),
            args=args, decorators=decs,
            is_method=bool(self._class_stack),
            class_name=self._class_stack[-1] if self._class_stack else None,
            docstring=ast.get_docstring(node) or "",
        ))
        self.generic_visit(node)

    def visit_ClassDef(self, node):
        bases = []
        for b in node.bases:
            try:
                bases.append(ast.unparse(b))
            except Exception:
                bases.append("<?>")
        ci = ClassInfo(
            name=node.name, lineno=node.lineno,
            end_lineno=getattr(node, "end_lineno", node.lineno),
            bases=bases,
        )
        start = len(self.functions)
        self._class_stack.append(node.name)
        self.generic_visit(node)
        self._class_stack.pop()
        ci.methods = [f.name for f in self.functions[start:]]
        self.classes.append(ci)

    # -- 导入
    def visit_Import(self, node):
        for a in node.names:
            self.imports.append(ImportInfo(
                module=a.name, names=[], lineno=node.lineno, is_from=False))
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        self.imports.append(ImportInfo(
            module=node.module or "", names=[a.name for a in node.names],
            lineno=node.lineno, is_from=True))
        self.generic_visit(node)

    # -- 调用
    def visit_Call(self, node):
        dotted = _dotted_py3(node.func)
        if dotted:
            self.calls.append(CallInfo(
                dotted=dotted, lineno=node.lineno,
                col=getattr(node, "col_offset", 0)))
        self.generic_visit(node)


def _dotted_py3(node) -> str:
    try:
        return ast.unparse(node)
    except Exception:
        return ""


# ---------------------------------------------------------------- Py2 (parso)

def _parso_text(node) -> str:
    try:
        return node.get_code().strip()
    except Exception:
        try:
            return str(getattr(node, "value", "<?>"))
        except Exception:
            return "<?>"


def _parso_extract(code: str) -> tuple[list[FuncInfo], list[ClassInfo],
                                       list[ImportInfo], list[CallInfo]]:
    """从 parso 2.7 语法树提取符号。

    ★ 不要用 `tree.iter_funcdefs()` / `iter_classdefs()`——实测它们**不递归进类**。
    `app/sessions/backends/base.py` 顶层只有 2 个 classdef，37 个 funcdef 全在类内，
    `iter_funcdefs()` 返回 0，导致整个文件"解析成功但符号为空"——这种静默失效
    比解析失败更危险。因此这里全部走自写递归遍历。

    节点类型（parso 0.7.1 / Python 2.7 grammar，已实测）：
        函数 = funcdef      类 = classdef
        导入 = import_name / import_from
        调用 = power        （**不是** atom_expr，那是 Py3 grammar）
    """
    import parso

    tree = parso.parse(code, version="2.7")
    funcs: list[FuncInfo] = []
    classes: list[ClassInfo] = []
    imports: list[ImportInfo] = []
    calls: list[CallInfo] = []
    class_stack: list[str] = []

    def line_of(node) -> int:
        try:
            return node.start_pos[0]
        except Exception:
            return 0

    def end_of(node) -> int:
        try:
            return node.end_pos[0]
        except Exception:
            return line_of(node)

    def name_of(node) -> str:
        try:
            return node.name.value
        except Exception:
            return "<?>"

    def parse_import(node, is_from: bool) -> None:
        """import a.b as c / from a.b import c, d"""
        mod, names = "", []
        kids = list(node.children)
        # 跳过 'import' / 'from' 关键字，取 dotted_name
        if is_from:
            for k in kids:
                if getattr(k, "type", "") in ("dotted_name", "name"):
                    mod = _parso_text(k)
                    break
            seen_kw = False
            for k in kids:
                if getattr(k, "type", "") == "keyword" and k.value == "import":
                    seen_kw = True
                    continue
                if seen_kw:
                    t = getattr(k, "type", "")
                    if t in ("dotted_as_names", "dotted_name", "name"):
                        names.extend(_split_as(_parso_text(k)))
                    elif t == "star_expr" or _parso_text(k) == "*":
                        names.append("*")
        else:
            for k in kids:
                t = getattr(k, "type", "")
                if t in ("dotted_as_names", "dotted_name", "name"):
                    names.extend(_split_as(_parso_text(k)))
        imports.append(ImportInfo(module=mod, names=names,
                                  lineno=line_of(node), is_from=is_from))

    def visit(node, depth: int = 0) -> None:
        if depth > 250:
            return
        t = getattr(node, "type", "")

        if t == "import_name":
            parse_import(node, False)
        elif t == "import_from":
            parse_import(node, True)
        elif t == "classdef":
            bases: list[str] = []
            try:
                sup = node.get_super_arglist()
                if sup is not None:
                    bases = [_parso_text(c) for c in sup.children
                             if getattr(c, "type", "")
                             in ("name", "power", "arglist", "dotted_name")]
            except Exception:
                pass
            ci = ClassInfo(name=name_of(node), lineno=line_of(node),
                           end_lineno=end_of(node), bases=bases, methods=[])
            classes.append(ci)
            class_stack.append(ci.name)
            for ch in getattr(node, "children", []) or []:
                visit(ch, depth + 1)
            class_stack.pop()
            # 补 methods：类内直接子级的 funcdef
            ci.methods = [f.name for f in funcs
                          if f.class_name == ci.name and f.lineno >= ci.lineno]
            return
        elif t == "funcdef":
            cls = class_stack[-1] if class_stack else None
            args: list[str] = []
            try:
                args = [p.name.value for p in node.get_params()]
            except Exception:
                pass
            decs: list[str] = []
            try:
                decs = [_parso_text(d) for d in node.get_decorators()]
            except Exception:
                pass
            funcs.append(FuncInfo(
                name=name_of(node), lineno=line_of(node), end_lineno=end_of(node),
                args=args, decorators=decs,
                is_method=cls is not None, class_name=cls, docstring="",
            ))
        elif t == "power":
            # power: [base, trailer...]；有 '(' 开头的 trailer 才是调用
            code_txt = _parso_text(node)
            has_call = any(
                getattr(tr, "type", "") == "trailer" and _parso_text(tr).startswith("(")
                for tr in getattr(node, "children", []) or []
            )
            if has_call:
                dotted = code_txt.split("(")[0].strip()
                if dotted and len(dotted) < 120 and not any(
                    c in dotted for c in ("'", '"', "[", "]", "{", "}", " ", "=")
                ):
                    calls.append(CallInfo(
                        dotted=dotted, lineno=line_of(node),
                        col=node.start_pos[1] if getattr(node, "start_pos", None) else 0))

        for ch in getattr(node, "children", []) or []:
            visit(ch, depth + 1)

    visit(tree)
    return funcs, classes, imports, calls


def _split_as(text: str) -> list[str]:
    """'a.b as c, d' -> ['a.b', 'd']（去掉 as 别名，保留原名）"""
    out = []
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        out.append(part.split(" as ")[0].strip())
    return out


# ---------------------------------------------------------------- 主入口

def parse_source(rel: str, code: str) -> ParsedModule:
    lines = code.count("\n") + 1
    with warnings.catch_warnings():
        # 目标代码里的无效转义序列等会刷屏——那是被审计代码的问题，不是我们的
        warnings.simplefilter("ignore", SyntaxWarning)
        warnings.simplefilter("ignore", DeprecationWarning)
        version, evidence = detect_version(code)

        if version == "3":
            try:
                tree = ast.parse(code)
                v = _Py3Visitor()
                v.visit(tree)
                return ParsedModule(
                    rel=rel, version="3", engine="ast", ok=True, error="",
                    lines=lines, functions=v.functions, classes=v.classes,
                    imports=v.imports, calls=v.calls, source=code,
                )
            except SyntaxError as e:
                version, evidence = "unknown", f"ast 解析失败: {e.msg} (line {e.lineno})"

        if version == "2":
            try:
                f, c, i, ca = _parso_extract(code)
                return ParsedModule(
                    rel=rel, version="2", engine="parso", ok=True, error="",
                    lines=lines, functions=f, classes=c, imports=i, calls=ca,
                    source=code,
                )
            except Exception as e:
                version, evidence = "unknown", f"parso 解析失败: {type(e).__name__}: {e}"

    return ParsedModule(
        rel=rel, version="unknown", engine="none", ok=False, error=evidence,
        lines=lines, source=code,
    )


def parse_file(path: Path, rel: str | None = None) -> ParsedModule:
    rel = rel or path.name
    return parse_source(rel, read_text(path))


def parse_many(files: list[tuple[str, str]]) -> ParseReport:
    """批量解析。files = [(rel, code), ...]"""
    rep = ParseReport()
    for rel, code in files:
        m = parse_source(rel, code)
        rep.modules[rel] = m
        rep.by_version[m.version] = rep.by_version.get(m.version, 0) + 1
        if not m.ok:
            rep.unparseable.append(rel)
    return rep
