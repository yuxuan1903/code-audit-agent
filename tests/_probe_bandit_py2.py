# -*- coding: utf-8 -*-
"""决定性实验：Bandit 到底能不能解析 Python 2 语法？

对照组设计（唯一变量 = 语法版本，危险调用完全相同）：
    py2 版：含 `print "x"` —— Py3 语法错误，Py2 合法
    py3 版：同样的 pickle.loads，但 print 用函数形式

若两者命中数相同 → Bandit 支持 Py2，先前的「跳过 9 个文件」假设**错误**。
若 py2 版命中 0 而 py3 版命中 1 → 确实跳过。
"""
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from engine.util import force_utf8, run_tool
force_utf8()

BODY_COMMON = '''
import pickle

def load_it(data):
    return pickle.loads(data)

def cmd(name):
    import os
    return os.system("killall -u %s" % name)

def sq(cur, uid):
    qn = cur.ops.quote_name
    sql = """SELECT %s FROM %s WHERE id = %%s""" % (qn("a"), qn("b"))
    cur.execute(sql, [uid])
'''

PY2 = 'print "hello python 2"\n' + BODY_COMMON
PY3 = 'print("hello python 3")\n' + BODY_COMMON

tmp = Path(tempfile.mkdtemp(prefix="bandit_probe_"))
(tmp / "t_py2.py").write_text(PY2, encoding="utf-8")
(tmp / "t_py3.py").write_text(PY3, encoding="utf-8")

print("=" * 74)
print(f"临时目录: {tmp}")
print("=" * 74)

for name in ("t_py2.py", "t_py3.py"):
    f = tmp / name
    code, out, err = run_tool(
        ["bandit", "-f", "json", "-q", "--exit-zero", "-l", str(f)], timeout=180)
    try:
        d = json.loads(out[out.find("{"):])
        res = d.get("results") or []
        ids = [(r["test_id"], r["line_number"]) for r in res]
        m = {k.replace("\\", "/"): v for k, v in (d.get("metrics") or {}).items()}
        loc = next((v.get("loc") for k, v in m.items()
                    if k.endswith(name)), None)
        print(f"\n{name}")
        print(f"  语法版本: {'Python 2 (print 语句)' if name == 't_py2.py' else 'Python 3'}")
        print(f"  metrics loc = {loc}")
        print(f"  命中 {len(res)} 条: {ids}")
        for r in res:
            print(f"    · {r['test_id']} L{r['line_number']}: {r['issue_text'][:80]}")
    except Exception as e:
        print(f"\n{name}: 解析失败 {e}\n  out={out[:300]}\n  err={err[:300]}")

print()
print("=" * 74)
print("结论判定")
print("=" * 74)
print("  若 py2 版命中数 == py3 版 → Bandit **支持 Py2 语法**")
print("  若 py2 版命中 0 而 py3 版有命中 → Bandit **跳过 Py2 文件**")
print()
print("  注：本实验同时检验 B301(pickle) / B605(os.system) / B608(裸 SQL)")
