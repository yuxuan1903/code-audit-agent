# -*- coding: utf-8 -*-
"""探查 semgrep / bandit 的可用性与输出形状（决定 runner 的解析逻辑）。"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from engine.util import find_tool, force_utf8, run_tool, run_tool_json
force_utf8()

sys.path.insert(0, str(Path(__file__).resolve().parent))   # -I 隐含 -P：脚本自身目录不在 sys.path
from _target import require_target

TARGET = require_target()

print("=" * 74)
print("① 工具可用性")
print("=" * 74)
for name in ("semgrep", "bandit", "pip-audit", "safety", "pip"):
    p = find_tool(name)
    print(f"  {name:12s} {'✅ ' + p if p else '❌ 未找到'}")

print()
print("=" * 74)
print("② semgrep")
print("=" * 74)
code, out, err = run_tool(
    ["semgrep", "--config", "p/python", "--json", "--quiet",
     "--max-target-bytes", "2000000", str(TARGET)],
    cwd=TARGET, timeout=900,
)
print(f"  exit={code}  stdout={len(out)} 字节  stderr={len(err)} 字节")
if err.strip():
    print("  stderr 首行:", err.strip().splitlines()[0][:160])
data, jerr = run_tool_json([])  # placeholder
try:
    d = json.loads(out)
    results = d.get("results") or []
    print(f"  findings: {len(results)}")
    if results:
        print("  首条原始结构:")
        print("   ", json.dumps(results[0], ensure_ascii=False)[:900])
    print("  keys:", list(d.keys()))
    print("  errors:", json.dumps(d.get("errors") or [])[:200])
    # 规则分布
    from collections import Counter
    print("  规则分布:", Counter(r["check_id"].split(".")[-1] for r in results).most_common(12))
except Exception as e:
    print(f"  JSON 解析失败: {e}")
    print("  out head:", out[:400])

print()
print("=" * 74)
print("③ bandit")
print("=" * 74)
code, out, err = run_tool(
    ["bandit", "-r", "-f", "json", "-q", "--exit-zero", str(TARGET)],
    cwd=TARGET, timeout=900,
)
print(f"  exit={code}  stdout={len(out)} 字节  stderr={len(err)} 字节")
if err.strip():
    for ln in err.strip().splitlines()[:6]:
        print("  stderr:", ln[:170])
try:
    d = json.loads(out[out.find("{"):])
    res = d.get("results") or []
    print(f"  findings: {len(res)}")
    if res:
        print("  首条原始结构:")
        print("   ", json.dumps(res[0], ensure_ascii=False)[:900])
    print("  metrics keys:", list((d.get("metrics") or {}).keys())[:14])
    print("  skipped:", (d.get("metrics") or {}).get("_totals", {}).get("skipped") if isinstance((d.get("metrics") or {}).get("_totals"), dict) else "n/a")
    from collections import Counter
    print("  规则分布:", Counter(r["test_id"] for r in res).most_common(14))
    print("  严重度分布:", Counter(r["issue_severity"] for r in res).most_common())
except Exception as e:
    print(f"  JSON 解析失败: {e}")
    print("  out head:", out[:400])
