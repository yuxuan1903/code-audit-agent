# -*- coding: utf-8 -*-
"""工具注册表（06 §3）。

**为什么需要一个注册表层，而不是把函数直接塞进主循环**：

1. **契约校验点在工具边界**（06 §2.4）。证据契约、覆盖度契约、归因门禁都在
   工具处理函数里强制。模型绕过不了——它只能通过工具改变世界。
2. **失败必须是可操作的**。校验失败时返回的不是"错误"而是"差什么、怎么补"。
   实测表明模型拿到可操作反馈后能自我纠正；拿到 "invalid input" 只会重试同样的调用。
3. **绝不抛异常到主循环**。工具崩溃不能终止整次审计——包装成 ok=False 的结果，
   让模型看到"这个工具坏了"并换路子。审计工具本身绝不能因为被审计代码的
   怪异写法而中断。
"""
from __future__ import annotations

import json
import traceback
from dataclasses import dataclass, field
from typing import Callable

from ..providers.base import ToolSpec
from ..redact import scrub


# ---------------------------------------------------------------- 结果

@dataclass
class ToolResult:
    ok: bool
    content: str                      # 给模型看的文本
    data: dict = field(default_factory=dict)   # 给程序看的结构化结果
    truncated: bool = False
    error: str = ""

    def render(self, max_chars: int = 6000) -> str:
        """渲染为 tool_result 内容。**超长必须截断并明确告知**（06 §5.5）。

        截断标记不能省：模型看到"还有 N 行未显示"才会用更精确的参数重取，
        而不是把不完整的内容当作全部。
        """
        body = self.content
        if len(body) > max_chars:
            keep = max_chars - 220
            omitted = len(body) - keep
            body = (
                body[:keep]
                + f"\n\n…【输出已截断：还有约 {omitted} 字符未显示。"
                + ("请用更精确的参数（更小的行范围 / 更窄的查询）重新调用，"
                   "或直接基于已显示部分推进。】" )
            )
            self.truncated = True
        if not self.ok:
            return f"❌ {body}"
        return body


# ---------------------------------------------------------------- 工具

@dataclass
class Tool:
    name: str
    description: str
    input_schema: dict
    handler: Callable[[dict], ToolResult]
    group: str = "A"                  # A侦察 B规则 C推理 D验证 E记录 F收敛
    mutating: bool = False            # 是否改变账本状态
    requires_scope: bool = True

    def spec(self) -> ToolSpec:
        return ToolSpec(self.name, self.description, self.input_schema)


class ToolRegistry:
    def __init__(self, cfg=None, sanitize: bool = True) -> None:
        self.tools: dict[str, Tool] = {}
        self.cfg = cfg
        # 外发脱敏开关。本地模型（数据不出域）应当关掉——那里脱敏不带来
        # 任何安全收益，只会让模型看不清它本该分析的东西。
        self.sanitize = sanitize
        self.calls: dict[str, int] = {}
        self.errors: dict[str, int] = {}

    # -------------------------------------------------- 注册

    def register(self, tool: Tool) -> None:
        self.tools[tool.name] = tool

    def add(self, name: str, description: str, schema: dict,
            handler: Callable[[dict], ToolResult], **kw) -> None:
        self.register(Tool(name, description, schema, handler, **kw))

    def specs(self) -> list[ToolSpec]:
        return [t.spec() for t in self.tools.values()]

    def by_group(self, group: str) -> list[Tool]:
        return [t for t in self.tools.values() if t.group == group]

    def __contains__(self, name: str) -> bool:
        return name in self.tools

    # -------------------------------------------------- 校验

    def has_required_args(self, name: str) -> bool:
        """该工具是否声明了必填参数。

        ★ 用来区分"截断残骸"与"合法的无参调用"。
        没有必填字段的工具（`list_candidates`、`outline` 之类）空参数**永远
        合法**，无论本轮是否被截断都该照常执行——只看"参数为空"就跳过，
        会把正常调用误伤成残骸。

        未注册的工具名返回 True。理由：这里返回 True 会让它走"残骸"路径，
        可**未注册**的工具无论怎么处理都不会回一句 `bad_args`，它回的是
        `unknown_tool`——那是一句**陈述事实**的话，不会让模型以为是自己
        写错了参数，因此不存在本缺陷要修的那种误导。
        """
        tool = self.tools.get(name)
        if tool is None:
            return True
        return bool((tool.input_schema or {}).get("required") or [])

    def _validate(self, tool: Tool, args: dict) -> str:
        """返回空串表示通过，否则返回可操作的错误说明（06 §5.2）。"""
        schema = tool.input_schema or {}
        props = schema.get("properties") or {}
        required = schema.get("required") or []

        missing = [k for k in required if k not in args or args[k] is None]
        if missing:
            given = ", ".join(sorted(args.keys())) or "（无）"
            return (f"缺少必填参数 {missing}。已给出的参数：{given}。"
                    f"参数说明：" + _describe_props(props, required))

        unknown = [k for k in args if k not in props]
        if unknown:
            return (f"存在未定义的参数 {unknown}。本工具只接受："
                    f"{sorted(props.keys())}。请检查参数名拼写。")

        for k, v in args.items():
            spec = props.get(k) or {}
            t = spec.get("type")
            if t == "integer" and not isinstance(v, bool):
                if not isinstance(v, int):
                    try:
                        args[k] = int(str(v))
                    except (TypeError, ValueError):
                        return (f"参数 {k} 应为整数，收到 {v!r}。{spec.get('description','')}")
            elif t == "string" and not isinstance(v, str):
                if isinstance(v, (int, float)):
                    args[k] = str(v)
                else:
                    return f"参数 {k} 应为字符串，收到 {type(v).__name__}"
            elif t == "array" and not isinstance(v, list):
                return (f"参数 {k} 应为数组，收到 {type(v).__name__}。"
                        f"{spec.get('description','')}")
            elif t == "object" and not isinstance(v, dict):
                return f"参数 {k} 应为对象，收到 {type(v).__name__}"
            # enum 校验——模型偶尔会给出枚举外的值
            enum = spec.get("enum")
            if enum and v not in enum:
                return (f"参数 {k} 必须是 {enum} 之一，收到 {v!r}。"
                        "请选最接近的一个，不要自造取值。")
        return ""

    # -------------------------------------------------- 调用

    def call(self, name: str, args: dict | None = None) -> ToolResult:
        args = dict(args or {})
        self.calls[name] = self.calls.get(name, 0) + 1

        tool = self.tools.get(name)
        if tool is None:
            near = [n for n in self.tools if n.startswith(name[:4])][:5]
            return ToolResult(False,
                              f"未定义的工具 {name!r}。可用工具："
                              f"{sorted(self.tools.keys())}"
                              + (f"。是不是想调用 {near}？" if near else ""),
                              error="unknown_tool")

        verr = self._validate(tool, args)
        if verr:
            self.errors[name] = self.errors.get(name, 0) + 1
            return ToolResult(False, f"参数校验失败：{verr}", error="bad_args")

        try:
            r = tool.handler(args)
            if not isinstance(r, ToolResult):
                r = ToolResult(True, str(r))
            return self._sanitize(r)
        except Exception as e:
            # ★ 工具崩溃绝不能终止审计。把异常变成模型可见的事实。
            self.errors[name] = self.errors.get(name, 0) + 1
            tb = traceback.format_exc(limit=3)
            return ToolResult(
                False,
                f"工具 {name} 执行时内部错误：{type(e).__name__}: {e}\n"
                f"（这是审计工具自身的问题，不是你调用错了。"
                f"可改用其他工具达成目的，或继续分析其余部分。）\n{tb[-400:]}",
                error=f"{type(e).__name__}",
            )

    # -------------------------------------------------- 脱敏

    def _sanitize(self, r: ToolResult) -> ToolResult:
        """★ 外发前的凭据闸门（03 §5「数据不出域」）。

        这是**唯一**一条「工具结果 → 模型」的通道，所以闸门设在这里：
        所有工具的返回都经过它，将来新增工具自动受保护，不会因为漏调用
        而开出一个口子。

        脱敏的是 `content`（给模型看的）。`data` 供程序内部使用，不改动——
        它的来源（引擎候选、账本）在生成时就已经各自脱敏过了。

        为什么值得在每次工具调用上都跑一遍正则：被审代码里出现真密钥是
        常态（靶子的 `settings.py:79` 就是），而账本摘要每轮都注入模型。
        不设这道闸，"扫描出密钥"这件事本身会把密钥送出去。
        """
        if not self.sanitize or not r.content:
            return r
        r.content = scrub(r.content)
        return r

    # -------------------------------------------------- 统计

    def stats(self) -> dict:
        return {
            "calls": dict(self.calls),
            "errors": dict(self.errors),
            "total_calls": sum(self.calls.values()),
            "total_errors": sum(self.errors.values()),
        }


def _describe_props(props: dict, required: list) -> str:
    parts = []
    for k, s in props.items():
        req = "必填" if k in required else "可选"
        parts.append(f"{k}({s.get('type','?')},{req}): {s.get('description','')[:60]}")
    return "；".join(parts)


# ---------------------------------------------------------------- 构造助手

def obj(props: dict, required: list[str] | None = None, **extra) -> dict:
    """简化 JSON Schema 构造。"""
    s = {"type": "object", "properties": props,
         "required": list(required or [])}
    s.update(extra)
    return s


def S(desc: str, **kw) -> dict:
    d = {"type": "string", "description": desc}
    d.update(kw)
    return d


def I(desc: str, **kw) -> dict:
    d = {"type": "integer", "description": desc}
    d.update(kw)
    return d


def B(desc: str, **kw) -> dict:
    d = {"type": "boolean", "description": desc}
    d.update(kw)
    return d


def A(desc: str, items: dict | None = None, **kw) -> dict:
    d = {"type": "array", "description": desc, "items": items or {"type": "string"}}
    d.update(kw)
    return d
