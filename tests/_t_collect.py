# -*- coding: utf-8 -*-
"""1.4 入口契约 实测。"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from engine.util import force_utf8, read_text
force_utf8()

from engine.config import Config
from engine.collect import collect

sys.path.insert(0, str(Path(__file__).resolve().parent))   # -I 隐含 -P：脚本自身目录不在 sys.path
from _target import require_target

TARGET = require_target()

cfg = Config.load(TARGET)
cfg.gate.security_critical_paths = [
    "**/settings.py", "**/urls.py", "**/views.py", "**/backends.py",
    "**/middleware.py", "**/models.py", "lib/ylinux_xmlrpc.py",
    "scripts/*.py",
]

scope, report = collect(cfg)

print("=" * 74)
print("入口契约汇总")
print("=" * 74)
s = scope.summary()
for k, v in s.items():
    print(f"  {k:20s} {v}")

print()
print("排除的文件（前 20）:")
for rel, why in list(scope.excluded.items())[:20]:
    print(f"  {rel:55s} {why}")

print()
print("vendored 判定明细:")
vi = scope.vendored_index
for rel, v in sorted(vi.verdicts.items()):
    if v.verdict != "project":
        print(f"  [{v.verdict:9s}] {rel:50s} {v.library or '-':10s} "
              f"conf={v.confidence:.2f} layers={v.layers_hit}")

print()
print("=" * 74)
print("入口点")
print("=" * 74)
kinds = {}
for ep in scope.entry_points:
    kinds[ep.kind] = kinds.get(ep.kind, 0) + 1
print(f"  类型分布: {kinds}")
print()
for ep in scope.entry_points[:70]:
    print(f"  [{ep.kind:10s}] {ep.file}:{ep.line:<4d} "
          f"{(ep.view or ep.target)[:44]:46s} auth={ep.auth:8s} {ep.auth_evidence[:40]}")

print()
print("=" * 74)
print("ground truth 核验")
print("=" * 74)

# 1. 关键文件必须在范围内
must_in = [
    "app/admin/views.py",              # os.system 命令注入（真漏洞）
    "app/account/backends.py",         # ★ Django 改造版：参数化 SQL（安全，Bandit 必报 B608）
    "lib/ylinux_xmlrpc.py",            # 越权 + 路径遍历（L1 命中 lib/** 但实为项目代码）
    "app/settings.py",                 # DEBUG / SECRET_KEY
    "app/account/models.py",           # 自定义 User 模型（曾误判 vendored）
]
print("\n① 关键文件在范围内:")
ok = 0
for rel in must_in:
    fi = scope.get(rel)
    if fi is None:
        print(f"  ❌ {rel}  未收录")
        continue
    in_scope = fi in scope.in_scope
    print(f"  {'✅' if in_scope else '❌'} {rel:34s} "
          f"attr={fi.attribution:9s} py{fi.py_version} lines={fi.lines} "
          f"critical={fi.in_critical_path}")
    ok += int(in_scope)
print(f"  → {ok}/{len(must_in)}")

# 2. Django 框架代码必须被归为 vendored（不计入项目漏洞）
print("\n② 框架拷贝必须归为 vendored（归因陷阱 A1-A4）:")
must_vendored = [
    "app/sessions/backends/base.py",   # Django SessionBase（pickle.loads）
    "app/sessions/models.py",          # Django Session
    "lib/django_xmlrpc/views.py",      # django-xmlrpc
    "lib/markdown/__init__.py",        # python-markdown
]
ok2 = 0
for rel in must_vendored:
    v = vi.get(rel)
    if not v:
        print(f"  ❌ {rel}  未收录")
        continue
    good = v.verdict in ("vendored", "suspected")
    print(f"  {'✅' if good else '❌'} {rel:34s} {v.verdict:9s} "
          f"{v.library or '-':10s} {v.reasons[0][:44] if v.reasons else ''}")
    ok2 += int(good)
print(f"  → {ok2}/{len(must_vendored)}")

# 3. 项目代码绝不能被误判为 vendored（否则静默丢 finding）
print("\n③ 项目代码不得被误判 vendored（★ 最危险错误）:")
must_project = [
    "app/admin/views.py", "app/account/backends.py", "app/account/models.py",
    "lib/ylinux_xmlrpc.py", "app/ydata/views.py", "app/ylab/views.py",
    "app/account/__init__.py",
]
ok3 = 0
for rel in must_project:
    v = vi.get(rel)
    if not v:
        print(f"  ❌ {rel}  未收录")
        continue
    good = v.verdict == "project"
    fork = f"  ← fork自 {v.forked_from}" if v.forked_from else ""
    print(f"  {'✅' if good else '❌'} {rel:34s} {v.verdict:9s}{fork}")
    ok3 += int(good)
print(f"  → {ok3}/{len(must_project)}")

# 3b. 反向证据：改造版库代码必须被识别
print("\n③b 反向证据（改造版库代码 → 缺陷归项目）:")
must_fork = {"app/account/backends.py": "django", "app/account/middleware.py": "django"}
ok3b = 0
for rel, lib in must_fork.items():
    v = vi.get(rel)
    good = bool(v and v.verdict == "project" and v.forked_from == lib)
    print(f"  {'✅' if good else '❌'} {rel:34s} forked_from={v.forked_from if v else '-'}")
    ok3b += int(good)
print(f"  → {ok3b}/{len(must_fork)}")
# 纯拷贝不得被误判为 fork
for rel in ("app/account/tokens.py", "app/sessions/backends/base.py"):
    v = vi.get(rel)
    good = bool(v and v.forked_from is None and v.verdict == "vendored")
    print(f"  {'✅' if good else '❌'} {rel:34s} 纯拷贝保持 vendored（forked_from={v.forked_from if v else '-'}）")
    ok3b += int(good)
print(f"  → 含纯拷贝反例 {ok3b}/{len(must_fork) + 2}")

# 4. 入口点抽取
print("\n④ 入口点抽取:")
has_xmlrpc = any(e.kind == "xmlrpc" for e in scope.entry_points)
print(f"  {'✅' if has_xmlrpc else '❌'} XML-RPC 注册入口被发现")

urls = [e for e in scope.entry_points if e.file.endswith("urls.py")]
print(f"  {'✅' if urls else '❌'} HTTP 路由 {len(urls)} 条")
authed = [e for e in urls if e.auth == "required"]
unauthed = [e for e in urls if e.auth == "none"]
print(f"     auth=required {len(authed)} / auth=none {len(unauthed)} / "
      f"unknown {len(urls) - len(authed) - len(unauthed)}")

print()
print("=" * 74)
print("★ 渲染给 Agent 的入口摘要（前 60 行）")
print("=" * 74)
print("\n".join(scope.to_prompt().splitlines()[:60]))

total = ok + ok2 + ok3 + ok3b + int(has_xmlrpc) + int(bool(urls))
mx = (len(must_in) + len(must_vendored) + len(must_project)
      + len(must_fork) + 2 + 2)
print()
print(f">>> 入口契约核验：{total}/{mx} 通过")
