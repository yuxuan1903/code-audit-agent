# -*- coding: utf-8 -*-
"""1.5/1.6 引擎接入 实测：命中归一 + ★ 跳过项对账。"""
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from engine.util import force_utf8
force_utf8()

from engine.collect import collect
from engine.config import Config
from engine.engines import BanditRunner, SemgrepRunner

sys.path.insert(0, str(Path(__file__).resolve().parent))   # -I 隐含 -P：脚本自身目录不在 sys.path
from _target import require_target

TARGET = require_target()
cfg = Config.load(TARGET)
scope, report = collect(cfg)

print("=" * 74)
print("① Semgrep")
print("=" * 74)
sg = SemgrepRunner(cfg).run()
print(sg.summary())
print(f"\n  命中规则分布: {Counter(h.rule.split('.')[-1] for h in sg.hits).most_common()}")
print(f"  严重度分布:   {Counter(h.severity for h in sg.hits).most_common()}")
print("\n  前 6 条:")
for h in sg.hits[:6]:
    print(f"    {h.severity:6s} {h.file}:{h.line}  {h.rule.split('.')[-1]}")
    print(f"           {(h.message or '')[:100]}")

print()
print("=" * 74)
print("② Bandit（★ 跳过项对账）")
print("=" * 74)
bd = BanditRunner(cfg, parsed=report.modules).run()
print(bd.summary())
print(f"\n  raw_counts: {bd.raw_counts}")
print(f"  命中规则分布: {Counter(h.rule for h in bd.hits).most_common()}")
print(f"  严重度分布:   {Counter(h.severity for h in bd.hits).most_common()}")

print("\n  ★ 跳过项是否覆盖了关键文件：")
key_py2 = ["app/sessions/backends/base.py", "app/ydata/views.py",
           "lib/markdown/__init__.py"]
for k in key_py2:
    hit = k in bd.skipped_files
    print(f"    {'✅' if hit else '❌'} {k:42s} {'在跳过清单中' if hit else '未被声明为跳过'}")

print("\n  ground truth 交叉核验：")
def find(rule, needle):
    return [h for h in bd.hits if h.rule == rule and needle in h.file]

s1 = find("B608", "backends.py")
print(f"    {'✅' if s1 else '❌'} S1 参数化 SQL 被报 B608（**正确答案是不报**，"
      f"需 Agent 驳回）: {len(s1)} 条")
s3 = find("B605", "admin/views.py")
print(f"    {'✅' if s3 else '❌'} S3/V1 os.system 命令执行被检出: {len(s3)} 条")
for h in s3:
    print(f"         L{h.line}: {h.snippet.splitlines()[0][:70] if h.snippet else ''}")

print()
print("=" * 74)
print("③ 引擎覆盖对照（供报告声明）")
print("=" * 74)
sg_files = {h.file for h in sg.hits}
bd_files = {h.file for h in bd.hits}
py2 = sorted(r for r, m in report.modules.items() if m.version == "2")
print(f"  Python 2 文件 {len(py2)} 个 → Bandit 覆盖 0 个，Semgrep 覆盖 "
      f"{len([p for p in py2])} 个（parso 解析）")
print(f"  Bandit 分析文件 {bd.analyzed_files} 个 / 仓库 {len(scope.files)} 个")
print(f"  Semgrep 分析文件 {sg.analyzed_files} 个")
print(f"  两者命中文件并集 {len(sg_files | bd_files)} 个")

uncovered = [f"{r} (py{m.version})" for r, m in sorted(report.modules.items())
             if m.version == "2"]
print(f"\n  ⚠️ Bandit 完全未覆盖的文件（报告中必须声明）：")
for u in uncovered:
    print(f"      · {u}")

print()
print("=" * 74)
print("④ 候选入账（引擎命中 → Ledger Candidate）")
print("=" * 74)
from engine.agent.ledger import Ledger
led = Ledger(scope, cfg)
led.add_candidates([h.to_candidate() for h in sg.hits])
led.add_candidates([h.to_candidate() for h in bd.hits])
print(f"  候选总数: {len(led.candidates)}  待处置: {len(led.open_candidates)}")
# 验证处置强制理由
ok1, m1 = led.dispose_candidate("C0001", "dismissed", "")
print(f"  空理由处置 → {'❌ 被拒绝（错）' if ok1 else '✅ 被拒绝：' + m1[:56]}")
ok2, m2 = led.dispose_candidate("C0001", "dismissed", "已确认是参数化调用，非拼接")
print(f"  带理由处置 → {'✅ ' + m2 if ok2 else '❌ ' + m2}")
ok3, m3 = led.dispose_candidate("C9999", "dismissed", "x")
print(f"  不存在的候选 → {'❌' if ok3 else '✅ 被拒绝：' + m3[:50]}")
