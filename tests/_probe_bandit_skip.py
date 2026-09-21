# -*- coding: utf-8 -*-
"""查清 Bandit 如何表示"没能解析的文件"——决定跳过项对账的正确做法。"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from engine.util import force_utf8, run_tool
force_utf8()

sys.path.insert(0, str(Path(__file__).resolve().parent))   # -I 隐含 -P：脚本自身目录不在 sys.path
from _target import require_target

T = str(require_target())
code, out, err = run_tool(["bandit", "-r", "-f", "json", "-q", "--exit-zero", T],
                          timeout=600)
d = json.loads(out[out.find("{"):])
m = d.get("metrics") or {}
norm = {k.replace("\\", "/"): v for k, v in m.items()}

print("metrics 条目数:", len(m))
print()
print("--- _totals ---")
print(" ", json.dumps(norm.get("_totals"), ensure_ascii=False)[:500])
print()

for key in ("sessions/backends/base.py", "ydata/views.py", "markdown/__init__.py",
            "admin/views.py", "account/backends.py", "ylab/views.py"):
    found = [(k, v) for k, v in norm.items() if k.endswith(key)]
    print(f"--- {key} ---")
    if not found:
        print("   ❌ metrics 中不存在")
        continue
    for k, v in found:
        print("   ", json.dumps(v, ensure_ascii=False)[:300])

print()
print("--- Py2 文件在 metrics 中的 loc ---")
py2 = ["app/account/__init__.py", "app/sessions/backends/base.py",
       "app/sessions/models.py", "app/ydata/views.py", "app/ylab/views.py",
       "lib/django_xmlrpc/views.py", "lib/markdown/__init__.py",
       "lib/markdown/commandline.py", "scripts/ylinux-client.py"]
for p in py2:
    hit = [k for k in norm if k.endswith(p)]
    v = norm[hit[0]] if hit else None
    loc = (v or {}).get("loc") if isinstance(v, dict) else None
    print(f"   {'在' if hit else '不在'} metrics: {p:38s} loc={loc}")

print()
print("--- results 里出现过的文件 ---")
res = {r["filename"].replace("\\", "/") for r in (d.get("results") or [])}
for r in sorted(res):
    print("   ", r.split("ylinux_old-master/")[-1])

print()
print("--- stderr 全文（前 30 行）---")
for l in err.splitlines()[:30]:
    print("   ", l[:180])
