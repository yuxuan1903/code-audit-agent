# -*- coding: utf-8 -*-
"""离线 Provider：无需网络/密钥即可跑通主循环。

存在的理由不是"占位"，而是**让主循环可被单测**——Agentic 循环的
预算、nudge、截断续写、契约校验这些逻辑必须能在 CI 里确定性验证，
不能依赖真实模型。脚本化响应让"模型下一轮会返回什么"变成输入参数。
"""
from __future__ import annotations

import json
import time

from .base import Capabilities, LLMResponse, Provider, Usage


class MockProvider(Provider):
    def __init__(self, cfg, script: list[dict] | None = None) -> None:
        super().__init__(cfg)
        self.name = "mock"
        self.caps = Capabilities(
            name="mock",
            supports_tool_calling=True,
            supports_thinking=True,
            max_context_tokens=200_000,
            max_output_tokens=8_192,
            notes=["离线脚本化 provider，用于主循环单测"],
        )
        # script 里每项描述一"轮"响应；用完后按 `default` 重复
        self.script: list[dict] = list(script or [])
        self.default: dict = {"type": "text", "text": "（mock：无更多脚本）"}
        self._i = 0
        self.trace: list[dict] = []      # 记录收到的消息，供断言

    def _next(self) -> dict:
        if self._i < len(self.script):
            r = self.script[self._i]
            self._i += 1
            return r
        return self.default

    def _build_body(self, system, messages, tools, max_tokens, temperature) -> dict:
        return {"messages": messages, "tools": tools or [], "max_tokens": max_tokens}

    @staticmethod
    def _prefix(spec: dict) -> list[dict]:
        """按真实顺序拼出工具调用之前的块：thinking 在前、text 在后。"""
        out = []
        if spec.get("thinking"):
            out.append({"type": "thinking", "thinking": spec["thinking"]})
        if spec.get("text"):
            out.append({"type": "text", "text": spec["text"]})
        return out

    def _request(self, body: dict, timeout: int) -> dict:
        self.trace.append({"messages": body["messages"], "tools": body.get("tools")})
        spec = self._next()
        kind = spec.get("type", "text")

        if kind == "tool_use":
            # 块顺序与真实响应一致：thinking → text → tool_use。
            # thinking 块是可以与工具调用同时出现的——实测两次真实运行的思考
            # 大多挂在带工具调用的轮次上。mock 若表达不了这个形状，就测不到
            # "工具轮次的推理有没有进轨迹"，而那正是轨迹里最有用的部分。
            blocks = self._prefix(spec) + [{
                "type": "tool_use",
                "id": spec.get("id", f"mock_{self._i}"),
                "name": spec["name"],
                "input": spec.get("input", {}),
            }]
            stop = "tool_use"
        elif kind == "multi_tool":
            blocks = self._prefix(spec) + [{
                "type": "tool_use", "id": f"mock_{self._i}_{n}",
                "name": t["name"], "input": t.get("input", {}),
            } for n, t in enumerate(spec.get("tools", []))]
            # ★ 允许脚本把 stop_reason 设成 "max_tokens"。真实截断的形态是
            # **有工具调用**的一轮被从尾巴上砍断（探针实测：最后那个块的
            # `input` 变成 `{}`），若 mock 只能给 "tool_use"，这条路径在 CI 里
            # 就永远测不到——而它此前正是靠"测不到"藏了十次运行。
            stop = spec.get("stop_reason", "tool_use")
        elif kind == "thinking":
            blocks = [{"type": "thinking", "thinking": spec.get("thinking", "")}]
            if spec.get("text"):
                blocks.append({"type": "text", "text": spec["text"]})
            stop = spec.get("stop_reason", "end_turn")
        else:
            blocks = [{"type": "text", "text": spec.get("text", "")}]
            stop = spec.get("stop_reason", "end_turn")

        if spec.get("delay_ms"):
            time.sleep(spec["delay_ms"] / 1000.0)

        return {
            "id": "mock", "type": "message", "role": "assistant",
            "content": blocks, "stop_reason": stop,
            "usage": {
                "input_tokens": spec.get("in_tokens", 1000),
                "output_tokens": spec.get("out_tokens", 200),
            },
        }


class RecordingProvider(Provider):
    """包装真实 provider，把每次请求/响应落到 JSONL——轨迹留档（06 §5.7）。

    数据不出域约束：轨迹落在本地 out_dir，不外发。
    """

    def __init__(self, inner: Provider, path) -> None:
        # 不调 super().__init__ 的 cfg 依赖——直接透传
        self.inner = inner
        self.cfg = inner.cfg
        self.name = f"recording({inner.name})"
        self.caps = inner.caps
        self.path = path
        self.calls = 0
        self.usage_total = Usage()

    def _build_body(self, *a, **kw):        # 不会被调用（绕过基类 complete）
        raise NotImplementedError

    def _request(self, *a, **kw):
        raise NotImplementedError

    def complete(self, messages, system="", tools=None, max_tokens=None,
                 temperature=None, max_retries=3) -> LLMResponse:
        resp = self.inner.complete(messages, system, tools, max_tokens,
                                   temperature, max_retries)
        self.calls = self.inner.calls
        self.usage_total = self.inner.usage_total
        try:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps({
                    "system": system,
                    "messages": messages,
                    "tools": [t.name if hasattr(t, "name") else t for t in (tools or [])],
                    "response_blocks": resp.blocks,
                    "stop_reason": resp.stop_reason,
                    "usage": {"in": resp.usage.input_tokens,
                              "out": resp.usage.output_tokens},
                    "latency_ms": resp.latency_ms,
                }, ensure_ascii=False) + "\n")
        except OSError:
            pass
        return resp

    def estimate(self, messages, system=""):
        return self.inner.estimate(messages, system)

    @property
    def context_ratio_value(self):
        return 0.0

    def describe(self):
        d = self.inner.describe()
        d["wrapped_by"] = "recording"
        return d
