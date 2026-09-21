# -*- coding: utf-8 -*-
"""代码上下文索引：符号表 + 调用图（06 §3 C 组工具的底座）。

**为什么要有这一层**：Agent 单靠 `grep` 找调用关系会失败——
同一个函数名在多个 app 里重名（本靶子 `index` 出现在 8 个 views.py 里），
纯文本搜索分不清"谁调用了这个具体的 delete_all_topic"。

因此这里建的是**带 import 解析的符号级索引**，而不是文本索引：
    · 符号表   —— 每个函数/类定义在哪个文件哪几行
    · 别名解析 —— `from account.models import User` 之后，`User` 指向哪里
    · 调用图   —— 调用点 → 被调符号（正向）/ 被调符号 → 调用点（反向）

**能力边界要诚实**：动态派发（`getattr(mod, name)()`）、Django 的信号与
字符串形式的视图引用（`url(..., 'account.views.index')`）无法静态解析。
这些一律标为 `unresolved` 并在工具输出里说明，**绝不假装解析成功**。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from . import parse as parsers
from .vendored import _build_module_index


@dataclass
class Symbol:
    name: str
    qualified: str                 # Class.method 或 func
    rel: str
    lineno: int
    end_lineno: int
    kind: str                      # function | method | class
    class_name: str | None = None
    decorators: list[str] = field(default_factory=list)

    @property
    def loc(self) -> str:
        return f"{self.rel}:{self.lineno}"


@dataclass
class CallEdge:
    caller_rel: str
    caller_symbol: str             # 限定名；模块级代码为空串
    callee_dotted: str             # 源码里写的调用串，如 os.system / self.foo
    line: int
    resolved: Symbol | None = None
    how: str = ""                  # 解析依据（别名 / 本地 / 无法解析）


class CodeIndex:
    """全仓库符号与调用关系索引。"""

    def __init__(self, scope, report: parsers.ParseReport) -> None:
        self.scope = scope
        self.report = report
        self.repo = Path(scope.repo)

        self.symbols: dict[str, list[Symbol]] = {}       # 短名 → 定义
        self.by_rel: dict[str, list[Symbol]] = {}        # 文件 → 定义
        self.module_index: dict[str, str] = {}           # dotted → rel
        self.aliases: dict[str, dict[str, str]] = {}     # rel → {本地名: 来源 dotted}
        self.out_edges: list[CallEdge] = []
        self.in_index: dict[str, list[CallEdge]] = {}    # 被调符号 key → 调用点

        self._build()

    # -------------------------------------------------- 构建

    def _build(self) -> None:
        rels = [rel for rel, m in self.report.modules.items() if m.ok]
        self.module_index = _build_module_index(list(self.report.modules.keys()))

        for rel, m in self.report.modules.items():
            if not m.ok:
                continue
            self.aliases[rel] = _aliases_of(m)
            for f in m.functions:
                s = Symbol(f.name, f.qualified, rel, f.lineno, f.end_lineno,
                           "method" if f.is_method else "function",
                           f.class_name, list(f.decorators))
                self._add_symbol(s)
            for c in m.classes:
                s = Symbol(c.name, c.name, rel, c.lineno, c.end_lineno, "class",
                           None, [])
                self._add_symbol(s)

        # 调用边
        for rel, m in self.report.modules.items():
            if not m.ok:
                continue
            for call in m.calls:
                fn = m.function_at(call.lineno)
                caller = fn.qualified if fn else ""
                sym, how = self.resolve_call(rel, call.dotted)
                e = CallEdge(rel, caller, call.dotted, call.lineno, sym, how)
                self.out_edges.append(e)
                if sym is not None:
                    self.in_index.setdefault(self._sym_key(sym), []).append(e)

    def _add_symbol(self, s: Symbol) -> None:
        self.symbols.setdefault(s.name, []).append(s)
        self.by_rel.setdefault(s.rel, []).append(s)

    @staticmethod
    def _sym_key(s: Symbol) -> str:
        return f"{s.rel}|{s.qualified}"

    # -------------------------------------------------- 解析

    def resolve_call(self, rel: str, dotted: str) -> tuple[Symbol | None, str]:
        """把源码里的调用串解析到具体定义。解析不了就返回 (None, 原因)。

        **宁可说解析不了，也不猜。** 猜错的调用关系会直接把 Agent 引到错误结论。
        """
        if not dotted:
            return (None, "空调用串")
        parts = dotted.split(".")
        head, rest = parts[0], parts[1:]

        amap = self.aliases.get(rel, {})

        # ① self / cls —— 同类内方法
        if head in ("self", "cls") and rest:
            mine = [s for s in self.by_rel.get(rel, [])
                    if s.name == rest[0] and s.kind in ("method", "function")]
            if mine:
                return (mine[0], f"同类内方法（{head}.{rest[0]}）")
            return (None, "同类内未找到该属性（可能是基类方法，静态无法解析）")

        # ② import 别名
        if head in amap:
            origin = amap[head] + ("." + ".".join(rest) if rest else "")
            hit = self._lookup_dotted(origin)
            if hit:
                return (hit, f"经 import 别名 {head} → {origin}")
            return (None, f"{head} 来自 {amap[head]}（第三方/标准库或未收录），"
                          f"仓库内无定义")

        # ③ 本文件定义的模块级符号
        local = [s for s in self.by_rel.get(rel, []) if s.name == head]
        if local:
            if not rest:
                return (local[0], "同文件定义")
            return (None, f"{head} 是本文件定义的符号，但其属性 {'.'.join(rest)} "
                          f"静态无法解析")

        # ④ 仓库内其它文件的同名模块级符号（无 import 的跨文件调用，Py2 常见）
        cands = [s for s in self.symbols.get(head, []) if s.kind != "method"]
        if cands:
            if len(cands) == 1:
                return (cands[0], "全仓库唯一同名定义（无 import，可能为隐式可见）")
            return (None, f"全仓库有 {len(cands)} 处同名定义（{', '.join(c.loc for c in cands[:4])}），"
                          f"无 import 无法判定指向哪个")

        return (None, "标准库/第三方调用，仓库内无定义")

    def _lookup_dotted(self, origin: str) -> Symbol | None:
        # 逐级剥离：a.b.c → 找 a/b/c.py 里的定义，或 a/b.py 里的 c
        parts = origin.split(".")
        for cut in range(len(parts), 0, -1):
            mod = ".".join(parts[:cut])
            rel = self.module_index.get(mod)
            if rel and cut < len(parts):
                attr = ".".join(parts[cut:])
                for s in self.by_rel.get(rel, []):
                    if s.name == attr or s.qualified == attr:
                        return s
            if rel and cut == len(parts):
                return None      # 指向模块本身
        # 兜底：最后一段作为符号名，限定在前缀匹配的文件里
        rel = self.module_index.get(".".join(parts[:-1]))
        if rel:
            for s in self.by_rel.get(rel, []):
                if s.name == parts[-1]:
                    return s
        return None

    # -------------------------------------------------- 查询

    def callers_of(self, name: str, rel: str | None = None) -> list[CallEdge]:
        """谁调用了 name。rel 给定时限定在该文件内的定义上。"""
        syms = self.symbols.get(name, [])
        if rel:
            syms = [s for s in syms if s.rel.endswith(rel)]
        out: list[CallEdge] = []
        for s in syms:
            out.extend(self.in_index.get(self._sym_key(s), []))
        return out

    def callees_of(self, rel: str, symbol: str) -> list[CallEdge]:
        return [e for e in self.out_edges
                if e.caller_rel == rel and e.caller_symbol == symbol]

    def outline(self, rel: str, max_n: int = 120) -> str:
        """文件骨架：符号 + 行号 + 装饰器。让 Agent 不必全文读就能定位。"""
        syms = sorted(self.by_rel.get(rel, []), key=lambda s: s.lineno)
        if not syms:
            return f"{rel}：无已解析的符号定义"
        L = [f"{rel}（{len(syms)} 个符号）"]
        for s in syms[:max_n]:
            dec = ("  " + " ".join(s.decorators)) if s.decorators else ""
            L.append(f"  L{s.lineno:<5d}-{s.end_lineno:<5d} {s.kind[:4]:4s} "
                     f"{s.qualified}{dec}")
        if len(syms) > max_n:
            L.append(f"  …另有 {len(syms) - max_n} 个")
        return "\n".join(L)

    def find(self, name: str, limit: int = 30) -> list[Symbol]:
        exact = self.symbols.get(name, [])
        if exact:
            return exact[:limit]
        low = name.lower()
        out: list[Symbol] = []
        for n, syms in self.symbols.items():
            if low in n.lower():
                out.extend(syms)
                if len(out) >= limit:
                    break
        return out[:limit]

    def stats(self) -> dict:
        resolved = sum(1 for e in self.out_edges if e.resolved)
        return {
            "symbols": sum(len(v) for v in self.symbols.values()),
            "files_with_symbols": len(self.by_rel),
            "call_edges": len(self.out_edges),
            "resolved_edges": resolved,
            "resolved_ratio": round(resolved / len(self.out_edges), 3)
            if self.out_edges else 0.0,
        }


def _aliases_of(m: parsers.ParsedModule) -> dict[str, str]:
    """构建 rel 内「本地可见名 → 来源 dotted」的映射。

    `import a.b as c`      → c   → a.b
    `import a.b`           → a   → a
    `from a.b import c`    → c   → a.b.c
    `from . import c`      → c   → c
    """
    amap: dict[str, str] = {}
    for imp in m.imports:
        if imp.is_from:
            base = imp.module or ""
            for n in imp.names:
                if n == "*":
                    continue
                amap[n] = f"{base}.{n}" if base else n
        else:
            for n in imp.names:
                if not n:
                    continue
                amap[n.split(".")[0]] = n.split(".")[0]
                amap[n] = n
    return amap
