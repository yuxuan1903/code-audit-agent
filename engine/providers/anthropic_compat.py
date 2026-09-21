# -*- coding: utf-8 -*-
"""Anthropic Messages API 兼容后端（含 DeepSeek 的 /anthropic 端点）。

用 stdlib urllib 而非官方 SDK：本工具要求"可插拔"，任何声称 Anthropic 兼容的
端点（DeepSeek、内网代理、LiteLLM 网关、Claude 原生）都必须能直接接上，
不被 SDK 的版本与参数校验挡住。

能力标记按端点实际情况声明，**不做乐观假设**——声明错了主循环会走错路径。
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

_ANTHROPIC_VERSION = "2023-06-01"


# 已知端点的能力表。键是 base_url 的子串（小写）。
# ★ 只写**实测确认**的项；未列出的走保守默认值。
KNOWN_ENDPOINTS: list[tuple[str, dict]] = [
    ("api.deepseek.com", dict(
        # 实测：DeepSeek 的 Anthropic 兼容端点支持 tools 与 thinking。
        supports_tool_calling=True, supports_thinking=True,
        supports_system_prompt=True, supports_prompt_cache=False,
        notes=["DeepSeek /anthropic 兼容端点；实测 tool_use 可用",
               # ★ 2026-09-19 实测（out/_probe_usage.py）：该端点**自动做
               # 前缀缓存**，无需（本工具也从不发送）cache_control 断点，
               # 并如实回报 cache_read_input_tokens；cache_creation 恒为 0。
               # 同一段提示词第二次调用：input 3405→205、cache_read 0→3200，
               # 相加仍为 3405 —— 即 Anthropic 语义（input 不含缓存）。
               # 单场 40 轮审计的缓存量在百万级，已在 7.5 节据实计入外发量。
               "自动前缀缓存（无 cache_control，cache_read 如实回报）"],
    )),
    ("api.anthropic.com", dict(
        supports_tool_calling=True, supports_thinking=True,
        supports_system_prompt=True, supports_prompt_cache=True,
        notes=["Anthropic 原生端点"],
    )),
    ("localhost", dict(notes=["本地端点，能力按保守值假设，首次调用后按实际修正"])),
    ("127.0.0.1", dict(notes=["本地端点（本地代理 / LiteLLM 网关）"])),
]


def _lookup_endpoint(base_url: str) -> dict:
    low = (base_url or "").lower()
    for needle, caps in KNOWN_ENDPOINTS:
        if needle in low:
            return dict(caps)
    return {}


class AnthropicCompatProvider(Provider):
    def __init__(self, cfg) -> None:
        super().__init__(cfg)
        self.name = "anthropic-compat"

        info = _lookup_endpoint(cfg.base_url)
        notes = list(info.pop("notes", []))
        model = (cfg.model or "").lower()

        # 上下文窗口：按模型名推断。`[1m]` 后缀是本环境 DeepSeek 1M 上下文的标记。
        max_ctx = 128_000
        if "1m" in model:
            max_ctx = 1_000_000
        elif "claude" in model:
            max_ctx = 200_000
        elif "deepseek" in model:
            max_ctx = 64_000

        self.caps = Capabilities(
            name=self.name,
            max_context_tokens=max_ctx,
            max_output_tokens=cfg.max_output_tokens or 4_096,
            **info,
        )
        self.caps.notes = notes
        if not cfg.base_url:
            self.caps.notes.append("未配置 base_url")
        if not cfg.api_key:
            self.caps.notes.append("⚠️ 未配置 api_key——调用会失败（密钥只从环境变量读）")

        # 数据是否留在本机——决定工具结果外发前要不要脱敏。
        # 判据是「数据是否真的离开这台机器」，不是一刀切。
        self.is_local = any(k in (cfg.base_url or "").lower()
                            for k in ("localhost", "127.0.0.1", "0.0.0.0", "11434"))

        self._url = _messages_url(cfg.base_url)

    # -------------------------------------------------- 请求

    def _build_body(self, system, messages, tools, max_tokens, temperature) -> dict:
        body: dict = {
            "model": self.cfg.model,
            "max_tokens": max_tokens,
            "messages": messages,
        }
        if temperature is not None:
            body["temperature"] = temperature
        if system and self.caps.supports_system_prompt:
            body["system"] = system
        if tools:
            body["tools"] = [t.to_anthropic() if isinstance(t, ToolSpec) else t
                             for t in tools]
        return body

    def _request(self, body: dict, timeout: int) -> dict:
        if not self.cfg.api_key:
            raise AuthError("未配置 API 密钥（应从 AI_AUDIT_API_KEY 或 "
                            "ANTHROPIC_AUTH_TOKEN 环境变量读取）")
        if not self._url:
            raise ProviderError("未配置 base_url")

        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(self._url, data=data, method="POST")
        req.add_header("content-type", "application/json")
        req.add_header("anthropic-version", _ANTHROPIC_VERSION)
        # 有的网关只认 x-api-key，有的只认 Bearer；两个都带上，互不冲突
        req.add_header("x-api-key", self.cfg.api_key)
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
            raise _classify_http(e.code, raw) from None
        except urllib.error.URLError as e:
            raise ServerError(f"连接失败: {e.reason}", status=0) from None
        except TimeoutError:
            raise ServerError(f"请求超时（{timeout}s）", status=0) from None
        except http.client.HTTPException as e:
            # ★ **漏出来的那一层**。`RemoteDisconnected` / `BadStatusLine` /
            # `IncompleteRead` 都属于 `http.client.HTTPException`，而它
            # **既不是 `urllib.error.URLError`**（那只覆盖 OSError 族，
            # `urlopen` 只在 `do_open` 里捕 OSError）**也不是 `ProviderError`**。
            # 实测代价（out/real-batch，2026-09-19）：第 35 轮一次
            # `RemoteDisconnected`，零重试，整场 40 轮终止，覆盖度停在 4/7。
            # 它的成因（服务端在发出响应前关连接：keep-alive 超时、网关重启、
            # 中间设备掐断）**恰恰是最该重试的一类**——重发一次通常就好。
            raise ServerError(f"连接被对端中断: {type(e).__name__}: {e}",
                              status=0) from None
        except json.JSONDecodeError as e:
            raise ServerError(f"响应不是合法 JSON: {e}", status=0) from None

    def _parse(self, data: dict):
        # 网关有时把错误塞在 200 响应体里——必须识别，否则会静默产出空结果
        if isinstance(data, dict) and data.get("type") == "error":
            err = data.get("error") or {}
            raise _classify_http(0, json.dumps(err, ensure_ascii=False))
        return super()._parse(data)


def _messages_url(base_url: str) -> str:
    """拼接 /v1/messages。容忍基址已带 /v1 或已是完整端点。"""
    b = (base_url or "").rstrip("/")
    if not b:
        return ""
    if b.endswith("/v1/messages"):
        return b
    if b.endswith("/v1"):
        return b + "/messages"
    return b + "/v1/messages"


def _classify_http(status: int, body: str) -> ProviderError:
    """把 HTTP 状态与错误体归类成可操作的异常。

    分类决定重试策略，因此必须准确：认证失败重试毫无意义（只烧配额），
    限流重试则是必须的。
    """
    low = (body or "").lower()
    snippet = (body or "")[:600]

    if status in (401, 403):
        return AuthError(f"认证/授权失败 (HTTP {status}): {snippet}", status=status, body=body)
    if status == 429 or "rate_limit" in low or "rate limit" in low:
        return RateLimitError(f"限流 (HTTP {status}): {snippet}", status=status, body=body)
    if status == 400 and any(k in low for k in (
        "context", "too long", "max_tokens", "exceed", "token limit",
    )):
        return ContextOverflowError(f"上下文超限: {snippet}", status=status, body=body)
    if status == 400 and any(k in low for k in ("tool", "tools", "unsupported", "not support")):
        return UnsupportedFeatureError(f"端点不支持该特性: {snippet}", status=status, body=body)
    if status == 413:
        return ContextOverflowError(f"请求体过大: {snippet}", status=status, body=body)
    if status >= 500:
        return ServerError(f"服务端错误 (HTTP {status}): {snippet}", status=status, body=body)
    if status == 0:
        # 200 响应体里包的错误
        if "auth" in low or "invalid api key" in low or "unauthorized" in low:
            return AuthError(f"认证失败: {snippet}", body=body)
        if "rate" in low and "limit" in low:
            return RateLimitError(f"限流: {snippet}", body=body)
        return ProviderError(f"端点返回错误: {snippet}", body=body)
    return ProviderError(f"HTTP {status}: {snippet}", status=status, body=body)
