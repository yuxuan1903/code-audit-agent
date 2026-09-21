# -*- coding: utf-8 -*-
"""OpenAI Chat Completions 兼容后端。

覆盖：DeepSeek 原生 API、本地 vLLM / Ollama、任何 OpenAI 兼容网关。
与 Anthropic 形状的差异全部在本文件内消化（system 进 messages、
tool_use/tool_result ↔ tool_calls/tool 角色、块列表 ↔ 字符串）。
"""
from __future__ import annotations

import http.client
import json
import urllib.error
import urllib.request

from .base import (
    AuthError, Capabilities, ContextOverflowError, Provider, ProviderError,
    RateLimitError, ServerError, ToolSpec, UnsupportedFeatureError,
)


class OpenAICompatProvider(Provider):
    def __init__(self, cfg) -> None:
        super().__init__(cfg)
        self.name = "openai-compat"
        base = (cfg.base_url or "").lower()
        model = (cfg.model or "").lower()

        local = any(k in base for k in ("localhost", "127.0.0.1", "11434"))
        notes = []
        max_ctx = 128_000
        if "1m" in model:
            max_ctx = 1_000_000
        elif "deepseek" in model:
            max_ctx = 64_000
        if local:
            notes.append("本地端点：**数据不出域**，可用于 L-SENSITIVE 文件")
        # 供外发脱敏判定使用（见 ToolRegistry._sanitize）
        self.is_local = local

        self.caps = Capabilities(
            name=self.name,
            # 本地小模型常常不支持 tool calling——保守声明，主循环会降级
            supports_tool_calling=not local,
            supports_thinking=False,
            max_context_tokens=max_ctx,
            max_output_tokens=cfg.max_output_tokens or 4_096,
            notes=notes,
        )
        self._url = _chat_url(cfg.base_url)

    def _build_body(self, system, messages, tools, max_tokens, temperature) -> dict:
        msgs = to_openai_messages(messages, system)
        body: dict = {"model": self.cfg.model, "messages": msgs,
                      "max_tokens": max_tokens}
        if temperature is not None:
            body["temperature"] = temperature
        if tools:
            body["tools"] = [{
                "type": "function",
                "function": {
                    "name": t.name, "description": t.description,
                    "parameters": _sanitize_schema(t.input_schema),
                },
            } for t in tools]
        return body

    def _request(self, body: dict, timeout: int) -> dict:
        if not self._url:
            raise ProviderError("未配置 base_url")
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(self._url, data=data, method="POST")
        req.add_header("content-type", "application/json")
        if self.cfg.api_key:
            req.add_header("authorization", f"Bearer {self.cfg.api_key}")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            raw = ""
            try:
                raw = e.read().decode("utf-8", errors="replace")
            except Exception:
                pass
            low = raw.lower()
            if e.code in (401, 403):
                raise AuthError(f"认证失败 {e.code}: {raw[:400]}", status=e.code) from None
            if e.code == 429:
                raise RateLimitError(f"限流: {raw[:400]}", status=429) from None
            if e.code == 400 and any(k in low for k in ("context", "too long", "exceed")):
                raise ContextOverflowError(f"上下文超限: {raw[:400]}", status=400) from None
            if e.code == 400 and "tool" in low:
                raise UnsupportedFeatureError(f"不支持 tools: {raw[:400]}", status=400) from None
            if e.code >= 500:
                raise ServerError(f"服务端错误 {e.code}: {raw[:400]}", status=e.code) from None
            raise ProviderError(f"HTTP {e.code}: {raw[:400]}", status=e.code) from None
        except urllib.error.URLError as e:
            raise ServerError(f"连接失败: {e.reason}") from None
        except TimeoutError:
            raise ServerError(f"请求超时（{timeout}s）") from None
        except http.client.HTTPException as e:
            # 与 anthropic_compat 同一处缺口，见那边的注释：`RemoteDisconnected`
            # 是 `HTTPException` 而非 `URLError`，会穿透全部 except。
            raise ServerError(f"连接被对端中断: {type(e).__name__}: {e}") from None

    def _parse(self, data: dict):
        """OpenAI 形状 → 归一化 Anthropic 形状。"""
        if data.get("error"):
            raise ProviderError(f"端点错误: {str(data['error'])[:400]}")
        choice = (data.get("choices") or [{}])[0]
        msg = choice.get("message") or {}
        blocks: list[dict] = []

        if msg.get("reasoning_content"):
            blocks.append({"type": "thinking",
                           "thinking": msg["reasoning_content"]})
        if msg.get("content"):
            blocks.append({"type": "text", "text": msg["content"]})
        for i, tc in enumerate(msg.get("tool_calls") or []):
            fn = tc.get("function") or {}
            raw_args = fn.get("arguments") or "{}"
            parse_err = ""
            try:
                args = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
            except json.JSONDecodeError as e:
                # ★ 不抛异常：让主循环看到"模型给了非法参数"这一事实并自我纠正
                args, parse_err = {}, f"JSON 解析失败: {e}"
            blocks.append({
                "type": "tool_use", "id": tc.get("id") or f"call_{i}",
                "name": fn.get("name", ""), "input": args,
                "_parse_error": parse_err,
            })

        u = data.get("usage") or {}
        from .base import LLMResponse, Usage
        return LLMResponse(
            blocks=blocks,
            stop_reason="tool_use" if msg.get("tool_calls") else
                        ("max_tokens" if choice.get("finish_reason") == "length"
                         else "end_turn"),
            usage=Usage(input_tokens=u.get("prompt_tokens", 0) or 0,
                        output_tokens=u.get("completion_tokens", 0) or 0),
            model=data.get("model", "") or self.cfg.model,
            raw=data,
        )


def _chat_url(base_url: str) -> str:
    b = (base_url or "").rstrip("/")
    if not b:
        return ""
    if b.endswith("/chat/completions"):
        return b
    if b.endswith("/v1"):
        return b + "/chat/completions"
    return b + "/v1/chat/completions"


def to_openai_messages(messages: list[dict], system: str) -> list[dict]:
    """Anthropic block 列表 → OpenAI 角色消息。"""
    out: list[dict] = []
    if system:
        out.append({"role": "system", "content": system})

    for m in messages:
        role = m.get("role", "user")
        content = m.get("content")

        if isinstance(content, str):
            out.append({"role": role, "content": content})
            continue

        texts, tool_calls, tool_results = [], [], []
        for b in content or []:
            t = b.get("type")
            if t == "text":
                texts.append(b.get("text", ""))
            elif t == "thinking":
                # OpenAI 系无 thinking 回填位；保留为普通文本以免上下文断裂
                if b.get("thinking"):
                    texts.append(b["thinking"])
            elif t == "tool_use":
                tool_calls.append({
                    "id": b.get("id", ""), "type": "function",
                    "function": {"name": b.get("name", ""),
                                 "arguments": json.dumps(b.get("input", {}),
                                                         ensure_ascii=False)},
                })
            elif t == "tool_result":
                tool_results.append({
                    "role": "tool",
                    "tool_call_id": b.get("tool_use_id", ""),
                    "content": _as_text(b.get("content")),
                })

        # tool 结果必须独立成条，且紧跟对应的 assistant tool_calls 之后
        if tool_calls:
            out.append({"role": "assistant",
                        "content": "\n".join(texts) or None,
                        "tool_calls": tool_calls})
        elif texts or role == "assistant":
            out.append({"role": role, "content": "\n".join(texts)})
        out.extend(tool_results)

    return out


def _as_text(v) -> str:
    if isinstance(v, str):
        return v
    if isinstance(v, list):
        return "\n".join(b.get("text", "") for b in v if isinstance(b, dict))
    return str(v)


def _sanitize_schema(schema: dict) -> dict:
    """部分 OpenAI 兼容端点不接受 JSON Schema 的进阶关键字，做最小化。"""
    if not isinstance(schema, dict):
        return {"type": "object", "properties": {}}

    def clean(node):
        if isinstance(node, dict):
            return {k: clean(v) for k, v in node.items()
                    if k not in ("$schema", "additionalProperties", "examples",
                                 "default", "title", "pattern")}
        if isinstance(node, list):
            return [clean(x) for x in node]
        return node

    out = clean(schema)
    out.setdefault("type", "object")
    out.setdefault("properties", {})
    return out
