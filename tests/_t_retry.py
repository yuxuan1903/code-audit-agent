#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Provider 重试与传输层异常分类 —— **一次真实运行就是被这个毁掉的**。

★ 现场（`out/real-batch`，2026-09-19，第 35 轮）：

    llm_error  RemoteDisconnected: Remote end closed connection without response

一条，只有一条，**从中读到写出没有任何重试**。整场 40 轮的 Agentic 分析就此
终止：覆盖度停在 4/7、40 条候选未处置、input token 停在 22.5 万（正常 26–28 万）。

根因不在退避参数，在**异常分类漏了一层**：

  · `RemoteDisconnected` 属于 `http.client.HTTPException`；
  · 它**不是 `urllib.error.URLError`**——`urlopen` 只在 `do_open` 里捕 OSError
    并转成 URLError，而 `HTTPException` 不是 `OSError`；
  · 它**也不是 `ProviderError`**；
  · 于是它从 `_request`（只捕 HTTPError / URLError / TimeoutError /
    JSONDecodeError）与 `complete`（只捕 ProviderError）**两层中间穿了过去**，
    一路穿到主循环的 `except Exception`——那里没有重试，只有"停止 Agentic 分析"。

而它的成因（服务端在发出响应前关掉连接：keep-alive 超时、网关重启、中间设备
掐断）**恰恰是最该重试的那一类**。重发一次通常就好了。

所以本文件钉三件事，缺一不可：
  1. 这一类异常**被归类**（而不是穿透）；
  2. 归类后**真的会重试**，且**退避窗口足够跨过一次抖动**——把"为什么把参数
     从 3 次/8 秒提到 5 次/20 秒"变成一条可测的断言，而不是注释里的一句话；
  3. **兜底**：将来新增 provider 时忘了映射某个异常，也只退化成"多等几秒"，
     而不是"丢掉一整场运行"。判据放宽到"异常来自传输层"，因为漏映射的种类
     无法穷举，而漏掉一个的代价是整场作废。
"""
import http.client
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from engine.util import force_utf8
force_utf8()

from engine.config import LLMConfig
from engine.providers.base import (AuthError, ProviderError,
                                   make_provider)

bad = 0


def check(label: str, cond: bool, detail: str = "") -> None:
    global bad
    if not cond:
        bad += 1
    print(f"  {'✅' if cond else '❌'} {label}" + (f"  {detail}" if detail else ""))


def _prov():
    """一个只会指向 example.invalid 的 provider。真实请求永远不会发出去——
    下面每个用例都会先替换掉 `urlopen`。"""
    llm = LLMConfig(provider="anthropic", model="test-model",
                    base_url="https://example.invalid/v1/messages",
                    api_key="test-key", request_timeout=5)
    return make_provider(llm, force="anthropic")


class _Resp:
    """够用的 urlopen 返回值：context manager + read()。"""
    def __init__(self, payload: bytes) -> None:
        self._b = payload

    def read(self) -> bytes:
        return self._b

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


_OK = json.dumps({
    "content": [{"type": "text", "text": "ok"}],
    "stop_reason": "end_turn", "model": "test-model",
    "usage": {"input_tokens": 3, "output_tokens": 2},
}).encode("utf-8")

_real_urlopen = urllib.request.urlopen
_real_sleep = time.sleep
_sleeps: list[float] = []

print("=" * 74)
print("① 异常分类：RemoteDisconnected 必须被归类，而不是穿透")
print("=" * 74)


def _boom(*a, **kw):
    raise http.client.RemoteDisconnected(
        "Remote end closed connection without response")


urllib.request.urlopen = _boom
try:
    try:
        _prov()._request({}, timeout=5)
        check("RemoteDisconnected 被归类为 ProviderError", False, "没有抛异常？")
    except ProviderError as e:
        check("RemoteDisconnected 被归类为 ProviderError（不再穿透）", True,
              f"{type(e).__name__}: {str(e)[:52]}")
        check("且标记为可重试——服务端提前断连，重发通常就好",
              bool(e.retryable), f"retryable={e.retryable}")
    except Exception as e:
        check("RemoteDisconnected 被归类为 ProviderError（不再穿透）", False,
              f"仍然穿透成 {type(e).__name__}——它会一路穿到主循环，那里只有「停止」")
finally:
    urllib.request.urlopen = _real_urlopen

print()
print("=" * 74)
print("② 重试真的发生：连续两次抖动作不掉整场")
print("=" * 74)

_calls = {"n": 0}


def _flaky(*a, **kw):
    _calls["n"] += 1
    if _calls["n"] <= 2:
        raise http.client.RemoteDisconnected("Remote end closed connection")
    return _Resp(_OK)


urllib.request.urlopen = _flaky
_sleeps.clear()
time.sleep = lambda s: _sleeps.append(s)
try:
    # 不写 `except ProviderError` 而写宽口径：修复前的实现抛的是裸
    # `RemoteDisconnected`，若在这里逃逸，脚本会中途崩掉、后面几条断言
    # 一条都跑不到——那正是反向验证时最需要看清的地方。
    r = _prov().complete([{"role": "user", "content": "hi"}])
    _text = r.text
except Exception as e:
    _text = f"<{type(e).__name__}: {e}>"
finally:
    time.sleep = _real_sleep
    urllib.request.urlopen = _real_urlopen

check("前两次断连后第 3 次成功（重试确实发生了）",
      _text == "ok" and _calls["n"] == 3,
      f"共尝试 {_calls['n']} 次，等待 {sum(_sleeps):.1f}s")

print()
print("=" * 74)
print("③ 退避窗口：把「参数为什么是这个数」变成可测的断言")
print("=" * 74)

_calls["n"] = 0


def _always(*a, **kw):
    _calls["n"] += 1
    raise http.client.RemoteDisconnected("Remote end closed connection")


urllib.request.urlopen = _always
_sleeps.clear()
time.sleep = lambda s: _sleeps.append(s)
try:
    try:
        _prov().complete([{"role": "user", "content": "hi"}])
        _exhausted, _exname = False, "（没抛）"
    except ProviderError:
        _exhausted, _exname = True, "ProviderError"
    except Exception as e:
        _exhausted, _exname = False, type(e).__name__
finally:
    time.sleep = _real_sleep
    urllib.request.urlopen = _real_urlopen

check("重试用尽后如实抛出 ProviderError（不是无限重试、也不是裸异常）",
      _exhausted and _calls["n"] == 6,
      f"尝试 {_calls['n']} 次、抛出 {_exname}")
check("★ 退避总窗口 ≥ 30 秒——一次抖动不该作废一场 7 分钟、27 万 token 的运行",
      sum(_sleeps) >= 30,
      f"{len(_sleeps)} 次退避共 {sum(_sleeps):.1f}s（旧参数 3 次/上限 8s 只有 7.6s）")

print()
print("=" * 74)
print("④ 兜底：将来新增 provider 忘了映射异常，也不该丢一整场")
print("=" * 74)

p3 = _prov()


def _unmapped(body, timeout):
    """模拟「provider 没映射这个异常」——它既不是 URLError 也不是 ProviderError。"""
    raise http.client.IncompleteRead(b"torn response")


p3._request = _unmapped
time.sleep = lambda s: None
try:
    try:
        p3.complete([{"role": "user", "content": "hi"}], max_retries=2)
        _fb, _fb_detail = False, "没有抛异常？"
    except ProviderError as e:
        _fb = bool(e.retryable) and "IncompleteRead" in str(e)
        _fb_detail = f"{type(e).__name__}: {str(e)[:52]}"
    except Exception as e:
        _fb, _fb_detail = False, f"{type(e).__name__} 穿透——主循环只会「停止」"
finally:
    time.sleep = _real_sleep

check("★ 未归类的传输层异常也被重试（兜底按「来自传输层」判，不枚举具体类型）",
      _fb, _fb_detail)

print()
print("=" * 74)
print("⑤ 不可重试的错误不能浪费重试次数")
print("=" * 74)

_calls["n"] = 0


def _401(*a, **kw):
    _calls["n"] += 1
    raise urllib.error.HTTPError("https://example.invalid/", 401, "Unauthorized",
                                 {}, None)


urllib.request.urlopen = _401
_sleeps.clear()
time.sleep = lambda s: _sleeps.append(s)
try:
    try:
        _prov().complete([{"role": "user", "content": "hi"}])
        _auth = False
    except AuthError:
        _auth = True
    except Exception as e:
        _auth = False
        print(f"    （抛的是 {type(e).__name__}）")
finally:
    time.sleep = _real_sleep
    urllib.request.urlopen = _real_urlopen

check("401 认证失败立刻上抛，一次都不重试（重试只会烧配额）",
      _auth and _calls["n"] == 1 and not _sleeps,
      f"尝试 {_calls['n']} 次，等待 {len(_sleeps)} 次")

print()
print(f"  {'✅ 四类传输层行为全部符合预期' if not bad else f'❌ {bad} 项不成立'}")
raise SystemExit(1 if bad else 0)
