# -*- coding: utf-8 -*-
"""1.11 Provider 抽象 实测：能力标记 + 真实端点 tool calling + 消息形状转换。"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from engine.util import force_utf8
force_utf8()

from engine.config import Config
from engine.providers.base import (ToolSpec, Usage, estimate_tokens,
                                   make_provider)
from engine.providers.openai_compat import to_openai_messages

sys.path.insert(0, str(Path(__file__).resolve().parent))   # -I 隐含 -P：脚本自身目录不在 sys.path
from _target import require_target

TARGET = require_target()
cfg = Config.load(TARGET)

print("=" * 74)
print("① 端点配置与能力标记")
print("=" * 74)
print(f"  provider={cfg.llm.provider}  model={cfg.llm.model}")
print(f"  base_url={cfg.llm.base_url}")
print(f"  api_key={'已设置(' + str(len(cfg.llm.api_key)) + ' 字符)' if cfg.llm.api_key else '未设置'}")

prov = make_provider(cfg)
d = prov.describe()
for k, v in d["capabilities"].items():
    print(f"    {k:22s} {v}")

print()
print("=" * 74)
print("② 真实端点 tool calling")
print("=" * 74)

TOOLS = [
    ToolSpec(
        name="read_code",
        description="读取仓库中某个文件的指定行范围。相对路径，如 app/admin/views.py。",
        input_schema={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "仓库内相对路径"},
                "start_line": {"type": "integer", "description": "起始行(含)"},
                "end_line": {"type": "integer", "description": "结束行(含)"},
            },
            "required": ["path", "start_line", "end_line"],
        },
    ),
    ToolSpec(
        name="record_finding",
        description="记录一条已确认的安全问题。必须给出完整证据链才允许记录。",
        input_schema={
            "type": "object",
            "properties": {
                "title": {"type": "string"},
                "severity": {"type": "string",
                             "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]},
                "file": {"type": "string"},
                "line": {"type": "integer"},
            },
            "required": ["title", "severity", "file", "line"],
        },
    ),
]

SYS = ("你是代码安全审计 Agent。你可以调用工具来读取代码。"
       "先用 read_code 确认，再决定是否 record_finding。不要凭猜测记录问题。")

MSGS = [{"role": "user", "content": (
    "已知线索：app/admin/views.py 第 358-365 行附近有一个 reboot 视图，"
    "据说用 os.popen('whoami') 的结果拼进 os.system 调用。\n"
    "请读取该处代码确认，然后判断是否应记录为问题。"
)}]

try:
    r1 = prov.complete(MSGS, system=SYS, tools=TOOLS, max_tokens=2048)
    print(f"  ✅ 调用成功  {r1.latency_ms} ms  stop_reason={r1.stop_reason}")
    print(f"  usage: in={r1.usage.input_tokens} out={r1.usage.output_tokens}")
    if r1.thinking:
        print(f"\n  [thinking] {r1.thinking[:300]}")
    if r1.text:
        print(f"\n  [text] {r1.text[:300]}")
    print(f"\n  tool_calls ({len(r1.tool_calls)}):")
    for tc in r1.tool_calls:
        print(f"    · {tc.name}({tc.arguments})  id={tc.id}"
              + (f"  ⚠️{tc.parse_error}" if tc.parse_error else ""))

    # 回填 tool_result，验证多轮形状正确（这是循环能否跑通的关键）
    if r1.tool_calls:
        print()
        print("=" * 74)
        print("③ 回填 tool_result 后的第二轮（验证消息形状）")
        print("=" * 74)
        msgs2 = list(MSGS) + [r1.assistant_message()]
        results = []
        for tc in r1.tool_calls:
            if tc.name == "read_code":
                results.append({
                    "type": "tool_result", "tool_use_id": tc.id,
                    "content": ("358: @permission_required('ydata.delete_catalog')\n"
                                "359: def reboot(request):\n"
                                "360:     user = os.popen('whoami').read().strip()\n"
                                "361:     if not user:\n"
                                "362:         return HttpResponse('无法获取当前用户')\n"
                                "363:     os.system('killall -u %s' % user)\n"
                                "364:     return HttpResponse('已重启')"),
                })
            else:
                results.append({
                    "type": "tool_result", "tool_use_id": tc.id,
                    "content": "ok",
                })
        msgs2.append({"role": "user", "content": results})

        r2 = prov.complete(msgs2, system=SYS, tools=TOOLS, max_tokens=2048)
        print(f"  ✅ 第二轮成功  stop_reason={r2.stop_reason}")
        if r2.thinking:
            print(f"\n  [thinking] {r2.thinking[:400]}")
        if r2.text:
            print(f"\n  [text] {r2.text[:500]}")
        for tc in r2.tool_calls:
            print(f"    · tool: {tc.name}({tc.arguments})")
except Exception as e:
    print(f"  ❌ {type(e).__name__}: {e}")
    import traceback
    traceback.print_exc()

print()
print("=" * 74)
print("④ 消息形状转换（Anthropic blocks → OpenAI messages）")
print("=" * 74)
sample = [
    {"role": "user", "content": "读代码"},
    {"role": "assistant", "content": [
        {"type": "thinking", "thinking": "先读文件"},
        {"type": "text", "text": "我来读一下"},
        {"type": "tool_use", "id": "t1", "name": "read_code",
         "input": {"path": "a.py", "start_line": 1, "end_line": 10}},
    ]},
    {"role": "user", "content": [
        {"type": "tool_result", "tool_use_id": "t1", "content": "1: import os"},
    ]},
]
conv = to_openai_messages(sample, "你是审计员")
for m in conv:
    keys = {k: (v if k != "content" else str(v)[:44]) for k, v in m.items()}
    print(f"    {keys}")
print(f"  转换后 {len(conv)} 条 ← 原始 {len(sample)} 条")

print()
print("=" * 74)
print("⑤ token 估算")
print("=" * 74)
for s in ["import os", "def reboot(request):",
          "这是一个中文注释，描述配置投毒风险"] * 3:
    print(f"    {estimate_tokens(s):5d} tk  | {s[:44]}")
u = Usage(100, 20) + Usage(50, 10)
print(f"    Usage 相加: in={u.input_tokens} out={u.output_tokens} total={u.total}")

print()
print("=" * 74)
print("⑥ 离线 mock provider（主循环单测用）")
print("=" * 74)
from engine.providers.mock import MockProvider
mock = MockProvider(cfg.llm, script=[
    {"type": "tool_use", "name": "read_code",
     "input": {"path": "app/admin/views.py", "start_line": 358, "end_line": 365}},
    {"type": "text", "text": "确认存在命令注入。"},
])
mr1 = mock.complete(MSGS, system=SYS, tools=TOOLS)
mr2 = mock.complete(MSGS, system=SYS, tools=TOOLS)
mr3 = mock.complete(MSGS, system=SYS, tools=TOOLS)
print(f"  轮1 stop={mr1.stop_reason} tools={[t.name for t in mr1.tool_calls]}")
print(f"  轮2 stop={mr2.stop_reason} text={mr2.text[:30]}")
print(f"  轮3 stop={mr3.stop_reason} text={mr3.text[:30]}（脚本耗尽走 default）")
print(f"  记录到 {len(mock.trace)} 次请求")
