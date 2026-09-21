# -*- coding: utf-8 -*-
"""LLM Provider 抽象。

设计依据：03 §1.3（可插拔多后端 + 能力标记）、06 §5.6（降级路径）。

三条约束决定了这里的形状：

1. **数据不出域**（治理方案铁律）：provider 只从 `LLMConfig` 读 endpoint 与密钥，
   密钥**只从环境变量来**，绝不落盘、绝不进日志。可指向内网代理或本地 Ollama/vLLM。
2. **能力是显式声明的，不是假设的**：`Capabilities` 明确标注
   `supports_tool_calling` / `supports_thinking` / `max_context_tokens`。
   不支持 tool calling 时不报错，而是由主循环降级为**结构化输出协议**（见 loop.py）。
3. **零 SDK 依赖**：只用 stdlib `urllib`。理由是"可插拔"必须真的能插——
   任何声称兼容 Anthropic/OpenAI 的端点都能接，不被 SDK 的版本与校验挡住。

消息格式采用**Anthropic 形状**（system 独立参数；content 为 block 列表）。
OpenAI 系后端在各自 provider 内做转换——因为这里是主路径，转换成本放次要路径上。
"""
from __future__ import annotations

import http.client
import json
import random
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field


# ---------------------------------------------------------------- 异常

class ProviderError(Exception):
    """所有 provider 错误的基类。带 retryable 标记，由主循环决定是否重试。"""
    retryable = False

    def __init__(self, msg: str, *, status: int = 0, body: str = "") -> None:
        super().__init__(msg)
        self.status = status
        self.body = body


class AuthError(ProviderError):
    """密钥无效 / 无权限。**不可重试**——重试只会烧配额。"""


class RateLimitError(ProviderError):
    retryable = True


class ServerError(ProviderError):
    retryable = True


class ContextOverflowError(ProviderError):
    """超出上下文窗口。**不可重试**——必须压缩后重发（06 §5.5）。"""


class UnsupportedFeatureError(ProviderError):
    """端点不支持请求的特性（如 tools）。由主循环降级，不是致命错误。"""


# ---------------------------------------------------------------- 能力

@dataclass
class Capabilities:
    """端点能力声明。**主循环据此决定用 tool calling 还是降级协议。**"""
    name: str = "unknown"
    supports_tool_calling: bool = True
    supports_thinking: bool = False
    supports_system_prompt: bool = True
    # ★ 语义澄清：本字段指**本工具是否会主动发送 cache_control 断点**，
    # 不是"该端点是否回报缓存用量"。两者无关——`api.deepseek.com/anthropic`
    # 自动缓存并如实回报 `cache_read_input_tokens`（2026-09-19 实测），
    # 而本工具从不发断点，故此处为 False，且那是**准确的**。
    # 另：目前没有任何代码消费这个字段，它只出现在 `describe()` 里。
    supports_prompt_cache: bool = False
    max_context_tokens: int = 128_000
    max_output_tokens: int = 4_096
    notes: list[str] = field(default_factory=list)

    def usable_output_tokens(self, requested: int) -> int:
        return max(256, min(requested, self.max_output_tokens))


# ---------------------------------------------------------------- 消息

@dataclass
class ToolSpec:
    """工具声明。`input_schema` 是 JSON Schema。"""
    name: str
    description: str
    input_schema: dict

    def to_anthropic(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": self.input_schema,
        }


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: dict
    parse_error: str = ""          # 模型给了非法 JSON 时记这里，不抛异常
    # ★ 截断残骸：输出被 max_tokens 砍断、参数没传完的块。它与"模型发了个
    # 空调用"在数据上**长得一模一样**（`arguments == {}`），但成因完全不同，
    # 因此给模型的反馈也必须不同——见 `Response.tool_calls` 的赋值理由。
    remnant: bool = False


@dataclass
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0

    @property
    def total(self) -> int:
        """计入预算的总量（`loop.py` 每轮用它累加 `tokens_used`）。

        ★ **缓存命中的部分也要计入。** 这里原先是 `input + output`，把
        `cache_read` / `cache_write` 排除在外。对"花了多少钱"来说那或许说得通
        （缓存命中确实更便宜），但对**预算**说不通：A10 的要求是"所有上下文
        及重试计入全局预算"，而缓存里缓的正是上下文——它同样占服务端的用量、
        同样受配额约束。把它排除，等于让"开了缓存的运行"在账面上比实际能跑的
        轮次更多，预算就不再是预算。

        与 `audit.py:_external_tokens`（数据外发量）保持一致也是刻意的：
        同一个运行里，**每一轮"发出去多少"与"预算里记了多少"用的是同量**。

        ★ 但**运行级别**的两个数并不相等，别把它们当成一个：`tokens_used`
        是**水位线**（`loop.py:201/225` 取 `max(before, before + usage.total)`），
        `data_sent_external` 是**累加值**。实测 real-group：前者 83,003、
        后者 1,387,834，差 16.7 倍。它们量的是"离预算上限还有多远"与
        "一共送出去多少"，**本就不该相等**——曾经这里写成"不该是两个数"，
        是个把两种量混为一谈的说法。

        ★ 语义前提（2026-09-19 实测确认，`out/_probe_usage.py` 可重跑）：
        这个加法**只在 Anthropic 语义下成立**——`input_tokens` 不含缓存，
        三者相加才是完整提示词。实测 `api.deepseek.com/anthropic`：
        未命中时 `input=3,405`；命中时 `input=205` + `cache_read=3,200`，
        相加恰好 `3,405`。**若换成 OpenAI 语义的端点**（`prompt_tokens`
        已含缓存命中），同样这个加法就会**重复计数**——所幸
        `openai_compat._parse` 只取 `prompt_tokens`/`completion_tokens`，
        cache_* 在那条路径上恒为 0，加法退化成"只算 input"，不重复。

        ★ 曾经这里写着"能力表里 `supports_prompt_cache=False`，因此这两次
        前后两个值相同"。**那句是错的**：该端点自动缓存（无需 cache_control）
        并如实回报缓存用量，实测缓存量在百万级。一句没人核对的注释被实测
        推翻——记在这里以免再犯。
        """
        return (self.input_tokens + self.output_tokens
                + self.cache_read_tokens + self.cache_write_tokens)

    def __add__(self, other: "Usage") -> "Usage":
        return Usage(
            self.input_tokens + other.input_tokens,
            self.output_tokens + other.output_tokens,
            self.cache_read_tokens + other.cache_read_tokens,
            self.cache_write_tokens + other.cache_write_tokens,
        )


@dataclass
class LLMResponse:
    """归一化响应。`raw` 保留原始 body 供排障与轨迹留档。"""
    blocks: list[dict] = field(default_factory=list)
    stop_reason: str = ""
    usage: Usage = field(default_factory=Usage)
    model: str = ""
    raw: dict = field(default_factory=dict)
    latency_ms: int = 0

    @property
    def text(self) -> str:
        return "\n".join(b.get("text", "") for b in self.blocks
                         if b.get("type") == "text")

    @property
    def thinking(self) -> str:
        return "\n".join(b.get("thinking", "") for b in self.blocks
                         if b.get("type") == "thinking")

    @property
    def tool_calls(self) -> list[ToolCall]:
        out = []
        for b in self.blocks:
            if b.get("type") == "tool_use":
                args = b.get("input") or {}
                out.append(ToolCall(
                    id=b.get("id", ""), name=b.get("name", ""),
                    arguments=args,
                    parse_error=b.get("_parse_error", ""),
                    # ★ 残骸判定：本轮被 max_tokens 砍断（`stop_reason`）**且**
                    # 这个块的参数是空的。两个条件缺一不可——
                    #   · 只看"参数为空"：会把合法的无参调用（`list_candidates`
                    #     之类）也误判成残骸，白白跳过。
                    #   · 只看"被截断"：截断响应里刀口**之前**的块是完整的，
                    #     它们是有效工作，必须照常执行。
                    # 受控探针实测（`out/_probe_truncation.py`）：同提示词只改
                    # max_tokens，上限 400 时 3/3 次都在**最后一个**工具调用块上
                    # 留下 `input={}`；上限 8000 时 12 个块全部完整、0 个空。
                    remnant=bool(self.truncated and not args),
                ))
        return out

    @property
    def truncated(self) -> bool:
        """★ 输出被 max_tokens 截断——主循环据此触发续写（06 §5.1）。"""
        return self.stop_reason == "max_tokens"

    @property
    def wants_tools(self) -> bool:
        return bool(self.tool_calls)

    def assistant_message(self) -> dict:
        """回填进 messages 的 assistant 轮。"""
        return {"role": "assistant", "content": list(self.blocks)}


# ---------------------------------------------------------------- 估算

def _is_cjk(ch: str) -> bool:
    o = ord(ch)
    return (0x3000 <= o <= 0x9FFF) or (0xFF00 <= o <= 0xFFEF) or (0x20000 <= o <= 0x2FA1F)


def estimate_tokens(text: str) -> int:
    """粗略 token 估算：CJK 约 1 token/字，其余约 4 字符/token。

    只用于**预算控制**（何时 nudge / 压缩），不用于计费。真实用量以 usage 为准。
    偏差方向可以接受：宁可高估（提前收敛）也不低估（撞上下文上限）。
    """
    if not text:
        return 0
    cjk = sum(1 for c in text if _is_cjk(c))
    return int(cjk + (len(text) - cjk) / 3.5) + 4


def estimate_messages_tokens(messages: list[dict], system: str = "") -> int:
    n = estimate_tokens(system)
    for m in messages:
        c = m.get("content")
        if isinstance(c, str):
            n += estimate_tokens(c)
        elif isinstance(c, list):
            for b in c:
                if b.get("type") == "text":
                    n += estimate_tokens(b.get("text", ""))
                elif b.get("type") == "tool_result":
                    n += estimate_tokens(str(b.get("content", "")))
                elif b.get("type") == "tool_use":
                    n += estimate_tokens(json.dumps(b.get("input", {}), ensure_ascii=False))
                elif b.get("type") == "thinking":
                    n += estimate_tokens(b.get("thinking", ""))
        n += 6
    return n


# ---------------------------------------------------------------- 基类

class Provider(ABC):
    """LLM 后端。子类只需实现 `_request`，重试/退避/错误归类由基类统一处理。"""

    # 数据是否留在本机。本地后端（Ollama / vLLM）子类置 True——外发脱敏
    # 对它们没有意义，反而会让模型看不清它本该分析的东西。
    # 默认 False（=按会出域处理）：安全的默认值应该是不放行的那一个。
    is_local: bool = False

    def __init__(self, cfg) -> None:
        # cfg 是 config.LLMConfig（不是顶层 Config）——见 make_provider
        self.cfg = cfg
        self.name = "base"
        self.caps = Capabilities()
        self.usage_total = Usage()
        self.calls = 0

    # -------------------------------------------------- 子类实现

    @abstractmethod
    def _request(self, body: dict, timeout: int) -> dict:
        """发一次请求，返回解析后的 JSON。异常向上抛 ProviderError。"""

    @abstractmethod
    def _build_body(self, system: str, messages: list[dict],
                    tools: list[ToolSpec] | None, max_tokens: int,
                    temperature: float) -> dict:
        ...

    # -------------------------------------------------- 公共入口

    def complete(
        self,
        messages: list[dict],
        system: str = "",
        tools: list[ToolSpec] | None = None,
        max_tokens: int | None = None,
        temperature: float | None = None,
        max_retries: int = 5,
    ) -> LLMResponse:
        if tools and not self.caps.supports_tool_calling:
            raise UnsupportedFeatureError(
                f"{self.name} 不支持 tool calling；主循环应改用结构化输出协议"
            )

        mt = self.caps.usable_output_tokens(max_tokens or self.cfg.max_output_tokens)
        temp = self.cfg.temperature if temperature is None else temperature
        body = self._build_body(system, messages, tools, mt, temp)

        last: ProviderError | None = None
        for attempt in range(max_retries + 1):
            t0 = time.time()
            try:
                data = self._request(body, self.cfg.request_timeout)
                self.calls += 1
                resp = self._parse(data)
                resp.latency_ms = int((time.time() - t0) * 1000)
                self.usage_total = self.usage_total + resp.usage
                return resp
            except ProviderError as e:
                last = e
                # 不可重试的错误立刻上抛——重试只是浪费时间和配额
                if not e.retryable or attempt >= max_retries:
                    raise
                self._backoff(attempt)
            except (OSError, http.client.HTTPException) as e:
                # ★ **兜底**：`_request` 没归类的传输层异常在这里变成可重试的
                # ServerError。判据是"异常来自传输层"而不是"具体是哪种"——
                # 因为漏映射的种类无法穷举，而漏掉一个的代价是**整场运行作废**。
                #
                # 这个兜底是被一次真实损失逼出来的（out/real-batch，2026-09-19）：
                # `RemoteDisconnected` 属于 `http.client.HTTPException`，既不是
                # `urllib.error.URLError`（那只覆盖 OSError 族）也不是
                # `ProviderError`，于是**从 `_request` 与 `complete` 两层 except
                # 中间穿过去**，一路穿到主循环，那里没有重试、只有"停止"。
                # 第 35 轮一次断连，零重试，整场 40 轮就此终止。
                last = ServerError(f"传输层异常 {type(e).__name__}: {e}")
                if attempt >= max_retries:
                    raise last from e
                self._backoff(attempt)
        raise last or ProviderError("unreachable")

    @staticmethod
    def _backoff(attempt: int) -> None:
        """退避：1、2、4、8、16 秒（各加 0–0.5s 抖动），总窗口约 **31 秒**。

        ★ 参数是被"作废一场运行"的代价推上去的，不是拍脑袋：上限从 8 提到 20、
        次数从 3 提到 5，因为一次端点抖动会让**整场 40 轮**（约 7 分钟、27 万
        输入 token）前功尽弃——多等 20 秒与丢掉一整场，不成比例。
        抖动是为了避免多个实例的重试在同一时刻撞回去（本项目跑单进程，
        但同一份 CI 并发跑多份是常态）。
        """
        time.sleep(min(2 ** attempt, 20) + random.uniform(0, 0.5))

    # -------------------------------------------------- 响应解析

    def _parse(self, data: dict) -> LLMResponse:
        u = data.get("usage") or {}
        return LLMResponse(
            blocks=list(data.get("content") or []),
            stop_reason=data.get("stop_reason") or "",
            usage=Usage(
                input_tokens=u.get("input_tokens", 0) or 0,
                output_tokens=u.get("output_tokens", 0) or 0,
                cache_read_tokens=u.get("cache_read_input_tokens", 0) or 0,
                cache_write_tokens=u.get("cache_creation_input_tokens", 0) or 0,
            ),
            model=data.get("model", "") or self.cfg.model,
            raw=data,
        )

    # -------------------------------------------------- 预算辅助

    def estimate(self, messages: list[dict], system: str = "") -> int:
        return estimate_messages_tokens(messages, system)

    def context_ratio(self, messages: list[dict], system: str = "") -> float:
        if self.caps.max_context_tokens <= 0:
            return 0.0
        return self.estimate(messages, system) / self.caps.max_context_tokens

    def describe(self) -> dict:
        return {
            "provider": self.name,
            "model": self.cfg.model,
            "base_url": _mask_url(self.cfg.base_url),
            "capabilities": {
                "tool_calling": self.caps.supports_tool_calling,
                "thinking": self.caps.supports_thinking,
                "system_prompt": self.caps.supports_system_prompt,
                "prompt_cache": self.caps.supports_prompt_cache,
                "max_context_tokens": self.caps.max_context_tokens,
                "max_output_tokens": self.caps.max_output_tokens,
            },
            "calls": self.calls,
            "usage": {
                "input": self.usage_total.input_tokens,
                "output": self.usage_total.output_tokens,
                "total": self.usage_total.total,
            },
            "notes": self.caps.notes,
        }


def _mask_url(url: str) -> str:
    """URL 里可能带密钥（?key=...）；外发审计日志里必须打码（03 §5）。"""
    if not url:
        return ""
    for sep in ("key=", "token=", "api_key=", "apikey="):
        i = url.lower().find(sep)
        if i >= 0:
            j = i + len(sep)
            k = url.find("&", j)
            k = len(url) if k < 0 else k
            url = url[:j] + "***" + url[k:]
    return url


# ---------------------------------------------------------------- 工厂

def make_provider(config, force: str | None = None) -> Provider:
    """按配置构造 provider。`provider=auto` 时按 endpoint 特征推断。

    接受**顶层 Config 或 LLMConfig**（容忍两者，因为调用方很容易混）。
    延迟导入——避免为一个不用的后端付出导入成本，也避免循环依赖。
    """
    llm = getattr(config, "llm", config)
    name = (force or llm.provider or "auto").lower()
    base = (llm.base_url or "").lower()

    if name == "auto":
        if "anthropic" in base or base.endswith("/v1/messages"):
            name = "anthropic"
        elif any(k in base for k in ("openai", "deepseek", "vllm", "ollama",
                                     "localhost", "127.0.0.1", "11434")):
            name = "openai"
        else:
            name = "anthropic" if llm.api_key else "mock"

    if name == "mock":
        from .mock import MockProvider
        return MockProvider(llm)
    if name == "openai":
        from .openai_compat import OpenAICompatProvider
        return OpenAICompatProvider(llm)
    from .anthropic_compat import AnthropicCompatProvider
    return AnthropicCompatProvider(llm)
