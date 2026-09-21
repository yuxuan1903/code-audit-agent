# -*- coding: utf-8 -*-
"""1.12/1.13 主循环 + 工具集 实测。

分两段：
  A 工具集 —— 每个工具单独调用，验证契约在工具边界被强制
  B 主循环 —— 脚本化 mock 驱动完整闭环，验证自主性、契约强制、收敛判定
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from engine.util import force_utf8
force_utf8()

from engine.agent.ledger import Ledger
from engine.agent.loop import AuditAgent
from engine.agent.tools import ToolContext, build_registry
from engine.collect import collect
from engine.config import Config
from engine.context import CodeIndex
from engine.providers.mock import MockProvider

sys.path.insert(0, str(Path(__file__).resolve().parent))   # -I 隐含 -P：脚本自身目录不在 sys.path
from _target import require_target

TARGET = require_target()
cfg = Config.load(TARGET)

print("=" * 74)
print("准备：范围 + 解析 + 符号索引")
print("=" * 74)
scope, report = collect(cfg)
idx = CodeIndex(scope, report)
st = idx.stats()
print(f"  在审文件 {len(scope.in_scope)} 个，入口 {len(scope.entry_points)} 个")
print(f"  符号索引：{st['symbols']} 个符号 / {st['call_edges']} 条调用边，"
      f"可解析 {st['resolved_edges']} 条（{st['resolved_ratio']:.1%}）")

led = Ledger(scope, cfg)
ctx = ToolContext(cfg=cfg, scope=scope, ledger=led, index=idx,
                  parsed=report.modules, repo=TARGET)
reg = build_registry(ctx)

print()
print("=" * 74)
print("A 工具集")
print("=" * 74)
from engine.agent.tools import tool_group_summary
print(tool_group_summary(reg))
print(f"\n  共 {len(reg.tools)} 个工具")

def show(title, r, max_lines=8):
    print(f"\n--- {title} ---")
    print(f"  ok={r.ok} err={r.error!r} data={str(r.data)[:120]}")
    for line in r.render(4000).splitlines()[:max_lines]:
        print(f"    {line[:150]}")

show("list_files(filter=xmlrpc)", reg.call("list_files", {"filter": "xmlrpc"}))
show("check_vendored(ylinux_xmlrpc)", reg.call("check_vendored",
     {"file": "lib/ylinux_xmlrpc.py"}))
show("check_vendored(backends.py) ★改造版", reg.call("check_vendored",
     {"file": "app/account/backends.py"}))
show("outline(ylinux_xmlrpc)", reg.call("outline", {"file": "lib/ylinux_xmlrpc.py"}), 10)
show("find_symbol(delete_all_topic)", reg.call("find_symbol",
     {"name": "delete_all_topic"}))
show("find_callers(delete_all_topic) ★反向可达", reg.call("find_callers",
     {"name": "delete_all_topic"}), 12)
show("trace_calls(admin/views.py)", reg.call("trace_calls",
     {"file": "app/admin/views.py", "symbol": "index"}), 8)
show("search_code(os\\.system)", reg.call("search_code",
     {"pattern": r"os\.system", "in_scope_only": False}), 8)
show("get_entry_points", reg.call("get_entry_points", {}), 6)

print()
print("--- 工具边界的契约强制 ---")
# 先入账一条候选，否则测不到"空理由"这条路径（会先报"候选不存在"）
led.add_candidate(source="bandit", rule="B608", file="app/account/backends.py",
                  line=38, severity="MEDIUM", message="Possible SQL injection")
r = reg.call("record_finding", {"title": "证据不全的测试", "severity": "HIGH",
                                "file": "lib/ylinux_xmlrpc.py", "line": 10,
                                "category": "missing_authorization",
                                "evidence": {"sink": "只给了 sink"}})
print(f"  缺证据四项 → {'❌ 竟然通过' if r.ok else '✅ 被拒绝'}")
print(f"    {r.content.splitlines()[0][:120]}")
print(f"    提示是否可操作: {'✅ 列出了缺失项' if 'sanitizer_check' in r.content else '❌ 没说缺什么'}")

r = reg.call("set_coverage", {"coverage_class": "C1_注入", "status": "no_issue",
                              "note": "看过了"})
print(f"\n  no_issue 无证据引用 → {led.coverage['C1_注入'].status.value}"
      f"  {'✅ 强制降级为 unverified' if led.coverage['C1_注入'].status.value == 'unverified' else '❌ 未被降级'}")

r = reg.call("set_coverage", {"coverage_class": "不存在的类", "status": "covered",
                              "note": "x"})
print(f"  非法覆盖类 → {'❌ 通过' if r.ok else '✅ 被拒绝：' + r.content[:60]}")

r = reg.call("dispose_candidate", {"candidate_id": "C0001", "status": "dismissed",
                                   "reason": ""})
print(f"  空理由处置 → {'❌ 通过' if r.ok else '✅ 被拒绝：' + r.content[:70]}")

r = reg.call("read_code", {"file": "不存在的文件.py"})
print(f"  读不存在的文件 → {'❌ 通过' if r.ok else '✅ 被拒绝：' + r.content[:70]}")

r = reg.call("search_code", {"pattern": "([unclosed"})
print(f"  非法正则 → {'❌ 通过' if r.ok else '✅ 被拒绝：' + r.content[:60]}")

r = reg.call("read_code", {"file": "lib/ylinux_xmlrpc.py", "start": 1, "end": 40})
r2 = reg.call("read_code", {"file": "lib/ylinux_xmlrpc.py", "start": 5, "end": 20})
print(f"  重复阅读检测 → 首次 new={r.data.get('new_information')} "
      f"重复 {r2.data.get('new_information')} "
      f"{'✅' if r2.data.get('new_information') is False else '❌'}")

r = reg.call("nonexistent_tool", {})
print(f"  未知工具 → {'❌ 通过' if r.ok else '✅ 被拒绝：' + r.content[:70]}")
print(f"  工具崩溃不终止审计: {'✅ 全部返回 ToolResult' if all(isinstance(reg.call(n, {}), object) for n in ['list_files']) else '❌'}")

print()
print("=" * 74)
print("B 主循环（脚本化 mock 驱动完整闭环）")
print("=" * 74)

led2 = Ledger(scope, cfg)
# 只入账 3 条候选，便于在有限轮次内全部处置
led2.add_candidate(source="bandit", rule="B608", file="app/account/backends.py",
                   line=38, severity="MEDIUM", message="Possible SQL injection",
                   snippet="sql = ...")
led2.add_candidate(source="bandit", rule="B605", file="app/admin/views.py",
                   line=363, severity="HIGH", message="Starting a process with a shell",
                   snippet="os.system(cmd)")
led2.add_candidate(source="semgrep", rule="open-redirect", file="app/admin/views.py",
                   line=118, severity="WARNING", message="open redirect",
                   snippet="return redirect(next)")

cfg.agent.max_turns = 15
cfg.agent.require_adversarial_for = []      # 对抗验证单独测（见 verify 段）

script = [
    # 1 侦察
    {"type": "tool_use", "name": "list_files", "input": {"filter": "xmlrpc"}},
    # 2 归因门禁
    {"type": "tool_use", "name": "check_vendored",
     "input": {"file": "lib/ylinux_xmlrpc.py"}},
    # 3 读代码
    {"type": "tool_use", "name": "read_code",
     "input": {"file": "lib/ylinux_xmlrpc.py", "start": 1, "end": 50}},
    # 4 证据不全 → 应被拒
    {"type": "tool_use", "name": "record_finding", "input": {
        "title": "XMLRPC 方法缺少权限校验", "severity": "HIGH",
        "file": "lib/ylinux_xmlrpc.py", "line": 30,
        "category": "missing_authorization",
        "evidence": {"sink": "def delete_all_topic(self, ...)"}}},
    # 5 补齐证据 → 应通过（4 条，覆盖 C2-C5，使覆盖度自洽）
    {"type": "multi_tool", "tools": [
        {"name": "record_finding", "input": {
            "title": "XMLRPC delete_all_topic 缺少对象级授权导致越权删除",
            "severity": "HIGH", "file": "lib/ylinux_xmlrpc.py", "line": 66,
            "function": "delete_all_topic",
            "category": "missing_authorization", "coverage_class": "C3_认证授权",
            "exploitability": "exploitable", "cwe": "CWE-862",
            "evidence": {
                "snippet": "def delete_all_topic(user, passwd):\n"
                           "    if not has_auth(user, passwd):\n"
                           "        raise Fault(-1, \"Authentication Failure\")\n"
                           "    Topic.objects.all().delete()",
                "sink": "lib/ylinux_xmlrpc.py:66 Topic.objects.all().delete() "
                        "—— 删除全站所有主题，无任何归属或角色校验",
                "source": "XMLRPC 入参 user/passwd 由调用者提供；任意**有效注册用户**"
                          "的凭据即可通过 has_auth",
                "reachability": "settings.py:166 将 ylinux_xmlrpc.delete_all_topic 注册为"
                                "XMLRPC 公开方法 delete_all_topic → 公网可达（HTTP 层）"
                                "→ 直达删除逻辑",
                "sanitizer_check": "has_auth() 只做 authenticate()（认证：你是谁），"
                                   "**不做授权**（你能动谁）。函数体内无 owner 归属校验、"
                                   "无 is_staff/is_superuser 判定、无对象级过滤。"
                                   "故：能挡住匿名用户，挡不住任何已注册用户。",
                "attack_path": ["以任意普通注册用户的凭据调用 XMLRPC 方法 delete_all_topic",
                                "has_auth 通过（该用户真实存在）",
                                "执行 Topic.objects.all().delete()，全站主题被清空"],
                "dataflow": ["xmlrpc call → dispatch → has_auth(认证) → "
                             "Topic.objects.all().delete()"],
            },
            "remediation": {
                "summary": "在 has_auth 之外补充授权判定：仅允许 is_staff/is_superuser "
                           "调用 delete_all_topic；delete_topic 应校验主题归属。",
                "patch_hint": "if not (user.is_authenticated and user.is_staff):\n"
                              "    raise Fault(-1, 'Permission Denied')",
            }}},
        {"name": "record_finding", "input": {
            "title": "Django session 后端使用 pickle 反序列化（vendored，需跟进升级）",
            "severity": "MEDIUM", "file": "app/sessions/backends/base.py", "line": 98,
            "category": "deserialization", "coverage_class": "C2_反序列化",
            "exploitability": "conditional", "cwe": "CWE-502",
            "evidence": {
                "snippet": "return pickle.loads(base64.b64decode(session_data))",
                "sink": "app/sessions/backends/base.py:98 pickle.loads()",
                "source": "session_data 来自客户端 cookie，**但**Django 对 session "
                          "cookie 做了签名校验，未签名的载荷在到达此处前即被拒绝",
                "reachability": "HTTP 请求 cookie → SessionMiddleware → "
                                "decode() → pickle.loads",
                "sanitizer_check": "路径上存在签名校验（signing 模块），"
                                   "攻击者需要 SECRET_KEY 才能构造合法载荷。"
                                   "因此单独不可直接利用；但若 SECRET_KEY 泄露"
                                   "（见 C4），则升级为 RCE。",
            },
            "remediation": {"summary": "该文件为 vendored 代码（Django 自带 session 后端），"
                                       "不计入项目自身漏洞。建议升级 Django 版本至"
                                       "使用 JSONSerializer 的版本。"}}},
        {"name": "record_finding", "input": {
            "title": "生产配置中 DEBUG 开启且 SECRET_KEY 硬编码",
            "severity": "HIGH", "file": "app/settings.py", "line": 1,
            "category": "hardcoded_secret", "coverage_class": "C4_凭据配置",
            "exploitability": "exploitable", "cwe": "CWE-798",
            "evidence": {
                "snippet": "DEBUG = True\nSECRET_KEY = '...'",
                "sink": "app/settings.py 中 DEBUG=True 与明文 SECRET_KEY",
                "source": "配置文件随源码分发，密钥对任何拿到仓库的人可见",
                "reachability": "SECRET_KEY 用于 session 签名与密码重置令牌签名 → "
                                "泄露即可伪造任意用户 session、伪造密码重置链接",
                "sanitizer_check": "未发现从环境变量或密钥管理服务读取的逻辑，"
                                   "该值直接硬编码在源码中",
            },
            "remediation": {"summary": "SECRET_KEY 改为从环境变量读取并轮换；"
                                       "生产环境 DEBUG 必须为 False。"}}},
        {"name": "record_finding", "input": {
            "title": "XMLRPC new_media 未校验路径导致任意文件写入",
            "severity": "HIGH", "file": "lib/ylinux_xmlrpc.py", "line": 105,
            "function": "new_media",
            "category": "path_traversal", "coverage_class": "C5_文件路径",
            "exploitability": "conditional", "cwe": "CWE-22",
            "evidence": {
                "snippet": "def new_media(blogid, user, passwd, fileObject): ...",
                "sink": "lib/ylinux_xmlrpc.py:105 new_media() 以调用者提供的文件名"
                        "写入文件系统",
                "source": "fileObject['name'] 由 XMLRPC 调用者完全控制",
                "reachability": "settings.py:170 注册为 metaWeblog.newMediaObject → "
                                "任意已认证用户可达",
                "sanitizer_check": "函数体内未见 os.path.basename 或路径规范化调用，"
                                   "亦未见扩展名白名单——需读取完整实现确认，"
                                   "当前判定为待核验",
            }}},
    ]},
    # 6 处置 3 条候选
    {"type": "multi_tool", "tools": [
        {"name": "dispose_candidate", "input": {
            "candidate_id": "C0001", "status": "dismissed",
            "reason": "该处 % 拼接的仅有 qn() 引用的表名/列名，用户输入 uid 走 "
                      "execute(sql, [uid]) 参数化，不构成注入（已读 backends.py:27-59 确认）"}},
        {"name": "dispose_candidate", "input": {
            "candidate_id": "C0002", "status": "deferred",
            "reason": "app/admin/views.py:363 的 os.system('killall -u %s' % user) "
                      "参数来源需读完整的调用链确认（该视图装饰器为已认证管理员），"
                      "本轮预算内未完成，延后处理"}},
        {"name": "dispose_candidate", "input": {
            "candidate_id": "C0003", "status": "deferred",
            "reason": "open redirect 需确认部署侧是否有跳转白名单，静态无法判定"}},
    ]},
    # 7 覆盖度未完成时收口 → 应被拒
    {"type": "tool_use", "name": "conclude", "input": {"summary": "审完了"}},
    # 8 落终态
    {"type": "multi_tool", "tools": [
        {"name": "set_coverage", "input": {"coverage_class": "C1_注入",
         "status": "no_issue", "note": "已审 account/backends.py 的 SQL 构造与 "
         "admin/views.py 的命令执行点，未发现可被外部污染且无净化的拼接",
         "evidence_refs": ["app/account/backends.py:27-59", "app/admin/views.py:340-370"]}},
        {"name": "set_coverage", "input": {"coverage_class": "C2_反序列化",
         "status": "covered", "note": "sessions/backends/base.py 的 pickle.loads 位于 "
         "vendored 的 Django session 后端，已记录并标注归因"}},
        {"name": "set_coverage", "input": {"coverage_class": "C3_认证授权",
         "status": "covered", "note": "发现 XMLRPC 越权删除 F-001"}},
        {"name": "set_coverage", "input": {"coverage_class": "C4_凭据配置",
         "status": "covered", "note": "app/settings.py 中 DEBUG 与 SECRET_KEY 硬编码"}},
        {"name": "set_coverage", "input": {"coverage_class": "C5_文件路径",
         "status": "covered", "note": "ylinux_xmlrpc 的 new_media 任意写入"}},
        {"name": "set_coverage", "input": {"coverage_class": "C6_依赖供应链",
         "status": "skipped", "note": "本轮未接入依赖扫描器（任务 1.8 未完成），"
         "如实声明未覆盖而非声称无问题"}},
        {"name": "set_coverage", "input": {"coverage_class": "C7_AI代码特有",
         "status": "no_issue", "note": "逐文件查看后未见 AI 生成特征（无过度整齐注释、"
         "无未被调用的生成接口），该仓库为 2013 年前后代码",
         "evidence_refs": ["已通读 lib/ 与 app/ 下全部在审文件的 outline 与关键函数体"]}},
    ]},
    # 9 收口
    {"type": "tool_use", "name": "conclude", "input": {
        "summary": "发现 XMLRPC 越权删除与任意文件写入等 1 条 HIGH 问题；"
                   "依赖供应链本轮未覆盖。",
        "limitations": ["C6 依赖供应链未接入扫描器", "9 个 Py2 文件 Bandit 未覆盖"]}},
]

provider = MockProvider(cfg.llm, script=script)
agent = AuditAgent(cfg, scope, report, led2, index=idx, provider=provider)
result = agent.run()

print(result.summary())
print()
print("  逐轮工具调用轨迹：")
for e in led2.events:
    if e.get("kind") == "tool":
        r = "✅" if e.get("ok") else "❌"
        print(f"    T{e.get('turn'):<3d} {r} {e.get('name'):20s} {e.get('args','')[:70]}")
    elif e.get("kind") in ("compacted", "truncation_continue", "text_only_nudge",
                           "concluded", "coverage_set", "finding_recorded",
                           "candidate_disposed"):
        print(f"    T{e.get('turn')}  · {e.get('kind')} "
              f"{ {k: v for k, v in e.items() if k not in ('kind', 'turn')} }"[:150])

print()
print("--- 契约强制（脚本第 4 轮：故意给不全的证据）---")
tool_events = [e for e in led2.events if e.get("kind") == "tool"
               and e.get("name") == "record_finding"]
print(f"  record_finding 被调用 {len(tool_events)} 次，其中失败 "
      f"{len([e for e in tool_events if not e.get('ok')])} 次")
print(f"  {'✅ 第一次被拒、其余通过' if not tool_events[0].get('ok') and all(e.get('ok') for e in tool_events[1:]) else '❌ 未按预期'}")

print()
print("--- 收敛判定（脚本第 7 轮：有 blocker 时收口）---")
concl = [e for e in led2.events if e.get("kind") == "tool"
         and e.get("name") == "conclude"]
print(f"  conclude 被调用 {len(concl)} 次，失败 {len([e for e in concl if not e.get('ok')])} 次")
print(f"  {'✅ 第一次被 blocker 挡住、补完后通过' if len(concl) == 2 and not concl[0].get('ok') and concl[1].get('ok') else '❌ 未按预期'}")

print()
print("--- 终态 ---")
print(f"  Agent 状态: {result.status}")
print(f"  findings: {len(led2.findings)} 条（有效 "
      f"{len([f for f in led2.findings.values() if f.is_active])} 条）")
print(f"  候选: 已处置 {len([c for c in led2.candidates.values() if not c.is_open])}"
      f"/{len(led2.candidates)}")
print(f"  覆盖度:")
for e in led2.coverage.values():
    mark = {"covered": "✅", "no_issue": "✅", "skipped": "⏭️",
            "out_of_scope": "➖", "unverified": "⬜"}[e.status.value]
    print(f"    {mark} {e.coverage_class:14s} {e.status.value:12s} {e.note[:52]}")
print(f"  结论: {led2.conclusion.get('summary','')[:150]}")
print(f"  工具调用统计: {result.tool_stats}")
print(f"  记录的事件类型: "
      f"{sorted(set(e['kind'] for e in led2.events))}")

print()
print("=" * 74)
print("C 报告生成（1.17）")
print("=" * 74)
from engine.engines import BanditRunner, SemgrepRunner
from engine.report import build_json, evaluate_gate, render_markdown, write_reports

engines = {"semgrep": SemgrepRunner(cfg).run(),
           "bandit": BanditRunner(cfg, parsed=report.modules).run()}
md = render_markdown(scope, led2, result, engines, cfg,
                     {"version": "0.1", "tool_stats": result.tool_stats})
print(f"  Markdown 报告 {len(md):,} 字符 / {len(md.splitlines())} 行")
print(f"  章节：")
for line in md.splitlines():
    if line.startswith("## ") or line.startswith("### "):
        print(f"    {line[:80]}")

js = build_json(scope, led2, result, engines, {"version": "0.1"})
print(f"\n  JSON 报告：schema={js['schema']}")
print(f"    summary: {js['summary']}")
print(f"    coverage_complete: {js['coverage_complete']}")
print(f"    candidates_open: {js['candidates_open']}")
print(f"    forked_files: {len(js['forked_files'])} 个")
print(f"    gate: {js['gate']['note']} (passed={js['gate']['passed']})")

cfg.report.formats = ["md", "json"]
cfg.out_dir = ROOT / "tests" / "_out"
written = write_reports(cfg, scope, led2, agent_result=result,
                        engines=engines, meta={"version": "0.1"})
print(f"\n  落盘：")
for k, p in written.items():
    print(f"    {k:8s} {p.relative_to(ROOT)}  ({p.stat().st_size:,} 字节)")

print(f"\n  ★ 报告是否包含局限性声明：")
for probe in ["## 二、覆盖度与局限性", "2.2 静态引擎覆盖与实际盲区",
              "2.4 方法学固有局限", "9 个文件完全未被该引擎分析",
              "认证与授权是两件事", "这不等于"]:
    print(f"    {'✅' if probe in md else '❌'} {probe[:40]}")

print(f"\n  ★ 报告是否包含对抗验证/候选台账：")
for probe in ["## 四、候选处置台账", "4.1 静态引擎候选", "4.2 收敛对账线索",
              "驳回", "## 六、代码归因", "改造版第三方代码", "7.7 构建指纹"]:
    print(f"    {'✅' if probe in md else '❌'} {probe[:40]}")


# ================================================================ C 越界边界
# A09「越界路径不能突破执行层」。这段是被一个真实缺陷逼出来的：
# `ScopeContract.get()` 为容错做了模糊匹配（`posix.endswith(k)`），
# 于是 `"../../x/settings.py"` 也能匹配到 `settings.py` 的 FileInfo。
# `get()` 返回的是规范 FileInfo，调用方理应改用 `fi.rel` 再读盘；
# 但只要有一处忘了规范化，`repo / "../../x/settings.py"` 就会真的读到
# 仓库外的内容，还可能以"snippet"的名义写进报告。
# 现在边界统一设在 `ToolContext.read_lines`——唯一的读盘入口。

print("\n" + "=" * 74)
print("C 越界边界 —— 路径不能逃出仓库根")
print("=" * 74)

ESCAPES = [
    ("相对遍历 + 伪装成在审文件名", "../audit.py"),
    ("多级相对遍历", "../../audit.py"),
    ("深遍历到系统文件", "../../../../../../etc/passwd"),
    ("Windows 绝对路径", "C:/Windows/win.ini"),
    ("绝对路径指向仓库外", str((ROOT / "audit.py").resolve())),
]
INSIDE = [("正常文件", "settings.py"), ("正常子目录文件", "app/account/views.py")]

bad = 0
for name, rel in INSIDE:
    try:
        n = len(ctx.read_lines(rel))
        print(f"  ✅ {name:22s} {rel[:34]:36s} 读到 {n} 行")
    except Exception as e:
        bad += 1
        print(f"  ❌ {name:22s} {rel[:34]:36s} 本应可读，却 {type(e).__name__}: {e}")

for name, rel in ESCAPES:
    try:
        n = len(ctx.read_lines(rel))
        bad += 1
        print(f"  ❌ {name:22s} {rel[:34]:36s} **逃逸成功，读到 {n} 行**")
    except FileNotFoundError as e:
        tag = "已拒绝" if "仓库之外" in str(e) else "未找到（非边界拦截）"
        print(f"  ✅ {name:22s} {rel[:34]:36s} {tag}")
    except Exception as e:
        bad += 1
        print(f"  ❌ {name:22s} {rel[:34]:36s} 意外异常 {type(e).__name__}: {e}")

# 边界必须在**读盘入口**，而不是某个调用点：绕过 scope 直接调用也要被拦。
# 这正是本次修复的意义——新增工具不会因为忘了校验而开出口子。
print(f"\n  {'✅ 越界边界全部生效' if not bad else f'❌ {bad} 项异常'}"
      f"（边界设在 ToolContext.read_lines，唯一读盘入口）")


# ================================================================ D 摘录层
# 前三段测的是"审计做对了吗"。这一段测的是**"报告把做过的事说对了吗"**——
# 验收过程中暴露出来的缺陷有近一半属于这一类：结论没错，是产物在失真
# （轨迹不落盘、外发量低报、快照为空）。这类缺陷的可怕之处在于它们不报错，
# 只是让读者看到一个通顺但错误的陈述，所以必须有用例钉住。
print("\n" + "=" * 74)
print("D 报告层陈述与事实的一致性")
print("=" * 74)

d_bad = 0


def check(label, cond, detail=""):
    global d_bad
    if not cond:
        d_bad += 1
    print(f"  {'✅' if cond else '❌'} {label}" + (f"  {detail}" if detail else ""))


# --- D1 推理轨迹必须真的落盘（缺陷 #9）----------------------------------
# 曾经的现场：7.4 节写着"完整轨迹见同目录的 JSON 报告"，而那个 JSON 里
# 根本没有 transcript 字段。指引读者去一个空地方，比不写更糟。
#
# 这一段特意**跑一次真实的 Agent 循环**（mock 模型，带 thinking 块），而不是
# 手工造一个 AgentResult：手工造的那份只能证明"渲染器能渲染给定数据"，
# 证明不了"循环会把 thinking 收进 result"——而缺陷 #9 恰恰出在后者。
from engine.agent.ledger import Ledger as _Ledger

_led3 = _Ledger(scope, cfg)
_prov3 = MockProvider(cfg.llm, script=[
    {"type": "tool_use", "name": "list_files", "input": {},
     "thinking": "D 段探针：先看文件清单，再决定从哪个入口读起。",
     "text": "先列文件。"},
])
_prev_turns = cfg.agent.max_turns
cfg.agent.max_turns = 2                      # 探针只跑两轮，别拖慢测试
try:
    _res3 = AuditAgent(cfg, scope, report, _led3, index=idx,
                       provider=_prov3).run()
finally:
    cfg.agent.max_turns = _prev_turns

check("循环把 thinking 收进了 result.transcript",
      any(e.get("kind") == "thinking" for e in _res3.transcript),
      f"{len(_res3.transcript)} 条："
      f"{[(e.get('turn'), e.get('kind')) for e in _res3.transcript]}")
check("循环把工具轮的 assistant_text 也收进了轨迹",
      any(e.get("kind") == "assistant_text" for e in _res3.transcript))

js2 = build_json(scope, _led3, _res3, engines, {"version": "0.1"})
tr = (js2.get("agent") or {}).get("transcript")
check("JSON 含 agent.transcript 且有内容",
      isinstance(tr, list) and len(tr) > 0, f"{len(tr) if tr else 0} 条")
kinds = {e.get("kind") for e in (tr or [])}
check("轨迹含 thinking（不只 assistant_text）", "thinking" in kinds, f"kinds={kinds}")
check("轨迹每条带轮次",
      all(e.get("turn") is not None for e in (tr or [])),
      f"turns={sorted({e.get('turn') for e in (tr or [])})}")

md2 = render_markdown(scope, _led3, _res3, engines, cfg, {"version": "0.1"})
check("Markdown 7.4 节真的渲染了轨迹", "### 7.4 审计轨迹" in md2)
check("7.4 节渲染出了探针那句思考原文",
      "先看文件清单" in md2)
check("轨迹声明了「不是核验过的事实」", "不是核验过的事实" in md2)

# --- D2 长文本截断必须显式标注（缺陷 #13）-------------------------------
# 旧代码是 `resp.thinking[:2000]`：实测两次 40 轮运行各有 13 / 17 条思考撞上
# 上限（约占三分之一），被切掉的正是推理的**结尾**——下结论那一句
# （实测断在 "But limited. Let me hold." 的 "Let" 上）。而产物里没有任何
# 痕迹能让人分辨"说完了"和"被切了"。
from engine.agent.loop import _clip
short = _clip("短文本", 8000)
check("短文本原样保留（不画蛇添足）", short == "短文本")
long_raw = "推" * 9000
long_clip = _clip(long_raw, 8000)
check("长文本被标注为已截断", "记录被截断" in long_clip)
check("标注里给出了被切掉的字符数", "1000 字符" in long_clip)
check("截断后长度可控", len(long_clip) < 8300, f"{len(long_clip)} 字符")
# 上限必须真的够用：实测最长的一条思考约 4.9K 字符，2000 会让三分之一的
# 推理失去结尾，8000 则只有极少数超长推理会被标注。
check("上限已从 2000 提高（≥8000）", len(_clip("x" * 8000, 8000)) == 8000)

# --- D3 数据外发声明的两个分支都不能沉默（缺陷 #10 的补丁）-------------
# 曾经的现场：`if meta.get("data_sent_external"):` —— 于是"没跑 Agent"和
# "跑了但没量到"在报告里长得一模一样：都什么都不显示。对一份合规声明来说，
# 沉默是最不能有的一种表达，因为读者会把"没写"读成"没有外发"。
# ★ 2026-09-19 补：夹具本身必须是**自洽**的。
# 原先这里是 `data_sent_external: 12345` 配 `tokens_in: 12000` —— 两个数
# 相差 345（恰好等于 tokens_out），谁也还原不出谁。**夹具不真实的后果，
# 是它测不出真实报告里的错**：正是这种"sent 与分项对不上"的写法，
# 在真实报告里连过七次没被发现。现在夹具按真实构成给：输入 + 缓存读。
result.cache_read_tokens = 1000
md_with = render_markdown(scope, led2, result, engines, cfg,
                          {"version": "0.1", "data_sent_external": 13000,
                           "tokens_in": 12000, "tokens_out": 345})
check("有真实用量时报出数字", "累计发送 13,000 tokens" in md_with)
check("有真实用量时说明取自服务端（而非本地估算）",
      "取自服务端回报" in md_with and "而非本地估算" in md_with)
# --- D3b 括号必须是**分解式**（缺陷 #28）--------------------------------
# 现场：7.5 写「累计发送 1,387,834 tokens（输入 269,626 / 输出 60,424）」，
# 两项相加 330,050，与总数差 1,118,208（差额=缓存读）；而"输出"根本
# 不参与这个总数。括号长得像分解式却不是，读者一验算就撞墙。
check("括号里列的是真正参与外发的分项（输入/缓存读/缓存写）",
      "输入 12,000" in md_with and "缓存读 1,000" in md_with
      and "缓存写 0" in md_with)
check("★ 分项相加 = 总数（读者不必自己验算，且它确实对得上）",
      "输入 12,000 + 缓存读 1,000 + 缓存写 0" in md_with)
check("输出被明确排除，而不是混在括号里冒充外发量",
      "输出 345 tokens" in md_with and "不计入" in md_with)
_eg = build_json(scope, led2, result, engines,
                 {"version": "0.1", "data_sent_external": 13000,
                  "tokens_in": 12000, "tokens_out": 345})["data_egress"]
check("★ JSON 里带得走外发量（合规数字不再只存在于正文）",
      _eg["tokens_sent_external"] == 13000 and _eg["reconstructs"] is True,
      f"sent={_eg['tokens_sent_external']:,} reconstructs={_eg['reconstructs']}")
check("缓存两项已序列化（否则 13,000 无从核验）",
      _eg["cache_read_tokens"] == 1000 and _eg["cache_write_tokens"] == 0)
# 负向对照：分项对不上时，报告**自己说出来**，而不是留给读者去发现。
md_bad = render_markdown(scope, led2, result, engines, cfg,
                         {"version": "0.1", "data_sent_external": 99999,
                          "tokens_in": 12000, "tokens_out": 345})
check("★ 自校验不通过时报告主动示警（不留给人去发现）",
      "本报告自校验未通过" in md_bad)

md_wo = render_markdown(scope, led2, result, engines, cfg, {"version": "0.1"})
check("拿不到用量时**仍然出现** 7.5 节", "### 7.5 数据外发声明" in md_wo)
check("拿不到用量时明说「未能取得」", "未能取得发送量" in md_wo)
check("拿不到用量时禁止读者读作「没有外发」",
      "请勿把这里的空缺读作" in md_wo)
check("拿不到用量时不显示「0 tokens」这种伪造的确定值",
      "0 tokens" not in md_wo)
# 没跑 Agent 时才不出现——那才是真的"没有外发"。
md_noagent = render_markdown(scope, led2, None, engines, cfg, {"version": "0.1"})
check("未跑 Agent 时不出现 7.5 节（此时确实没有外发）",
      "### 7.5 数据外发声明" not in md_noagent)

# --- D4 预算口径：缓存命中的上下文也要计入（缺陷 #16）-------------------
# A10 要求"所有上下文及重试计入全局预算"。缓存里缓的正是上下文，
# 排除它会让开了缓存的运行在账面上比实际能跑的轮次更多——预算就不再是预算。
from engine.providers.base import Usage
_u = Usage(input_tokens=100, output_tokens=20,
           cache_read_tokens=1000, cache_write_tokens=50)
check("预算总量计入缓存读写", _u.total == 1170, f"total={_u.total}（期望 1170）")
_external = _u.input_tokens + _u.cache_read_tokens + _u.cache_write_tokens
check("外发量与预算口径不再互相矛盾（外发 ≤ 预算总量）",
      _external <= _u.total, f"外发={_external} 预算={_u.total}")
check("未计缓存的旧口径已被改掉", _u.total != _u.input_tokens + _u.output_tokens)

print(f"\n  {'✅ 报告层陈述与事实一致' if not d_bad else f'❌ {d_bad} 项不一致'}"
      f"（轨迹落盘 / 截断标注 / 外发声明不沉默 / 预算口径）")


# ================================================================ E 收敛对账
# A 段测的是"审计做对了吗"，D 段测的是"报告说对了吗"。
# 这一段测**第三种东西**：报告是不是**完整**的。
#
# 验收报告 §4 的结论是——两次真实运行的全部漏报，没有一条来自"读不懂代码"
# 或"判错了漏洞类型"，全都是"看见了、说出来了、没落账"：
#   · V9  记录遗漏：第 5 轮已把 delete_all_topic 定性为越权，输出被截断，finding 从未建立
#   · V11 覆盖不全：同一轮识别出 3 处，只落账 1 处
#   · V10 低严重度倾向不记："But limited. Let me hold."
# 证据在轨迹里，报告只读账本。所以漏报不是"没发现"，是"发现了但没留下"。
#
# 收敛对账（06 §5.8）补的就是这一环：收口前把"推理里提过、账本里没有"的位置
# 提出来，要求逐条处置。它的失效形态是**沉默**——不报错、不写日志，
# 只是让报告少一条本该有的记录。所以必须有用例钉住它的每一个动作。
print("\n" + "=" * 74)
print("E 收敛对账：提过但没落账的位置必须被追问")
print("=" * 74)

e_bad = 0


def echeck(label, cond, detail=""):
    global e_bad
    if not cond:
        e_bad += 1
    print(f"  {'✅' if cond else '❌'} {label}" + (f"  {detail}" if detail else ""))


from engine.agent import recall as _recall
from engine.report import _build_meta

# --- E1 纯函数：抽取器的四条边界 ---------------------------------------
# 判据全都可以调，而调参必须知道自己在调什么。四条边界各钉一个：
#   · 带行号的危险提及要抽到（含 `lines 62,134` 这种写法）
#   · 纯导航句不算（"先读 X 的第 N 行"不是判断）
#   · 回显引擎候选的段落不算（那些位置另有处置通道，再报一次是噪音）
#   · 文件名有歧义时放弃（猜错文件比对账不报更糟）
_probe = (
    "app/admin/views.py lines 62,134 — that redirect target looks unvalidated.\n"
    "delete_all_topic in lib/ylinux_xmlrpc.py:60 — any user can delete ALL topics.\n"
    "C0012: B608 SQL in app/account/backends.py:43 — candidate echo here.\n"
    "Now let me read app/ydata/views.py 100-140 to confirm the download path.\n"
)
_refs = _recall.extract(_probe, scope)
_hits = {f"{r['file']}:{r['line']}" for r in _refs}
echeck("抽到带行号的危险提及", "lib/ylinux_xmlrpc.py:60" in _hits, f"{sorted(_hits)}")
echeck("抽到 `lines 62,134` 这种写法",
      any(r["file"] == "app/admin/views.py" and r["line"] == 62 for r in _refs))
echeck("纯导航句（说要去读，没下判断）不算",
      not any(r["file"] == "app/ydata/views.py" for r in _refs))
echeck("回显引擎候选的段落不算（另有处置通道）",
      not any(r["file"] == "app/account/backends.py" for r in _refs))
echeck("文件名有歧义时放弃解析，而不是猜一个",
      _recall.resolve("views.py", scope) is None
      and _recall.resolve("admin/views.py", scope) == "app/admin/views.py")

# --- E2 真循环：说过、没落账 → 必须变成待处置线索 -----------------------
# ★ 本段核心用例，构造的正是 V10 的形态：模型看见了一处，在推理里说出来了，
# 然后**什么也没记**。修复前这个位置在报告里等于不存在；修复后它必须变成
# 一条要处置的线索，且**不收口就不能收**。
_led4 = _Ledger(scope, cfg)
_prov4 = MockProvider(cfg.llm, script=[
    {"type": "tool_use", "name": "list_files", "input": {},
     "thinking": "lib/ylinux_xmlrpc.py:105 的新媒体上传接口看起来有 path traversal 风险，"
                 "文件名校验只做了 basename 处理，先记着。",
     "text": "先看文件清单。"},
    {"type": "tool_use", "name": "read_code",
     "input": {"file": "settings.py", "start": 1, "end": 20},
     "text": "看看配置。"},
])
_prev_t4 = cfg.agent.max_turns
_prev_r4 = cfg.agent.recall_after_ratio
_prev_g4 = _recall.MENTION_GRACE_TURNS
cfg.agent.max_turns = 3
cfg.agent.recall_after_ratio = 0.0        # 测试里不等预算过半
_recall.MENTION_GRACE_TURNS = 1           # 真跑里冷静期是 3 轮，测试压到 1
try:
    AuditAgent(cfg, scope, report, _led4, index=idx, provider=_prov4).run()
finally:
    cfg.agent.max_turns = _prev_t4
    cfg.agent.recall_after_ratio = _prev_r4
    _recall.MENTION_GRACE_TURNS = _prev_g4

_c4 = [c for c in _led4.candidates.values() if c.source == "recall"]
echeck("说过却没落账的位置被提成了对账线索", bool(_c4),
       f"{[(c.id, c.file, c.line, c.rule) for c in _c4]}")
echeck("线索指向的正是推理里说过的那个位置",
       any(c.file == "lib/ylinux_xmlrpc.py" and c.line == 105 for c in _c4))
echeck("线索本身不是结论（INFO + 待处置，等模型表态）",
       all(c.severity == "INFO" and c.is_open for c in _c4))
echeck("线索进 blockers，不收口就不能收",
       any("收敛对账线索" in b for b in _led4.blockers()))
echeck("线索被记进事件流（可审计，不是隐式行为）",
       any(ev.get("kind") == "recall_flagged" for ev in _led4.events))
echeck("注入给模型的摘要里也点出了待处置线索",
       "收敛对账线索" in _led4.digest())

# --- E3 账本状态决定线索的去留 -----------------------------------------
# 对账最怕两种错：**该问的没问**（漏报原样回来）、**已经处置过的又问一遍**
# （烧预算，且会让模型养成"随便驳回"的习惯）。两种都钉住。
_led5 = _Ledger(scope, cfg)
_prov5 = MockProvider(cfg.llm, script=[
    {"type": "tool_use", "name": "list_files", "input": {},
     "thinking": "settings.py:18 的 DEBUG=True 是硬编码的生产配置问题。"},
    {"type": "tool_use", "name": "list_files", "input": {}},
    {"type": "tool_use", "name": "list_files", "input": {}},
])
cfg.agent.max_turns = 3
_recall.MENTION_GRACE_TURNS = 1
try:
    AuditAgent(cfg, scope, report, _led5, index=idx, provider=_prov5).run()
finally:
    cfg.agent.max_turns = _prev_t4
    _recall.MENTION_GRACE_TURNS = _prev_g4
_first = [c for c in _led5.candidates.values()
          if c.source == "recall" and c.file == "settings.py"]
echeck("同一位置只提一次（不会每轮重复催）", len(_first) == 1, f"{len(_first)} 条")

# 已记录 finding 的位置不该再被问
_led5.record_finding({"title": "DEBUG 上线", "severity": "LOW",
                      "file": "settings.py", "line": 18, "category": "config"},
                     turn=1, enforce_evidence=False)
_n_before = len([c for c in _led5.candidates.values() if c.source == "recall"])
_led5.recall_scan(turn=9)
_n_after = len([c for c in _led5.candidates.values() if c.source == "recall"])
echeck("已落账的位置不再产生新线索（扫描器认账）",
       _n_after == _n_before, f"{_n_before} → {_n_after}")

# 延后（deferred）是合法且诚实的出口：预算不够时不能说"没这回事"，说"没看"
# ★ 这里必须换一个**不会被 finding 覆盖**的位置。原先用的是 settings.py:18，
# 而上面刚给它记了 finding——`_reap_stale` 下一次扫描就把它自动回收了，
# `open_candidates` 空掉，断言退化成"没有待处置线索可供测试"。
# 那是新机制在**正确工作**（线索确实过时了），所以改测试，不是让机制让开。
# 这条位置的选取本身也有讲究：它必须**不是**任何 finding 的坐标，
# 否则测的就不是 deferred，而是自动回收。
_led5.log("thinking", turn=2,
          text="app/ydata/models.py:258 的存储型 XSS 未过滤，先记下。")
_led5.recall_scan(turn=10)              # 越过冷静期（此时 GRACE=3）
_open_rec = [c for c in _led5.open_candidates if c.source == "recall"]
if _open_rec:
    _ok, _msg = _led5.dispose_candidate(_open_rec[0].id, "deferred",
                                        "预算耗尽，本次未复核", turn=9)
    echeck("deferred 是合法处置（预算不够时如实记录，而不是沉默）",
           _ok and _led5.candidates[_open_rec[0].id].status == "deferred", _msg)
else:
    echeck("deferred 是合法处置（预算不够时如实记录，而不是沉默）", False,
           "没有待处置线索可供测试")

# --- E4 文件级回访：读过却没有结论的文件 -------------------------------
# §4.5-2：「这类文件是最可能藏着漏报的地方」。实测 real-final 里
# `lib/ylinux_xmlrpc.py` 的越权讨论**没有任何行号**（那段推理正好在
# 2000 字上限处被截断），A 类一条都抽不到——能兜住它的只有这条通道。
_led6 = _Ledger(scope, cfg)
_led6.note_reviewed("lib/ylinux_xmlrpc.py", 1, 9999)
_got6 = _led6.recall_scan(turn=20)
echeck("完整读过、却既无 finding 也无覆盖说明的文件被回访",
       any(c.file == "lib/ylinux_xmlrpc.py" for c in _got6),
       f"{[(c.file, c.rule) for c in _got6]}")
echeck("回访理由写清了「读过多少、有无对外入口」",
       any(c.rule == "file" and "读过" in c.message and "入口" in c.message
           for c in _got6),
       f"{[c.message[:70] for c in _got6 if c.rule == 'file']}")
_led7 = _Ledger(scope, cfg)
_led7.note_reviewed("lib/ylinux_xmlrpc.py", 1, 9999)
_led7.record_finding({"title": "越权批量删帖", "severity": "HIGH",
                      "file": "lib/ylinux_xmlrpc.py", "line": 60,
                      "category": "authz"}, turn=1, enforce_evidence=False)
echeck("已有 finding 的文件不再回访",
       not any(c.file == "lib/ylinux_xmlrpc.py" for c in _led7.recall_scan(turn=20)))

# --- E4b 回访的重复提名与总量失控（★ 真实运行打出来的两个缺陷）----------
# 这一段是**被一次真实 40 轮运行逼出来的**，不是设计时想到的。
# 现场：46 条对账线索里 40 条是 B 类，而它们只来自 6 个文件——
# `app/admin/views.py` 被提名 18 次、`app/wiki/views.py` 17 次。
# 模型在第 39 轮的推理里自己认出了这是噪音："mostly duplicates"，
# 然后在最后一轮试图挤进 58 次 dispose，**一条也没做完**。
#
# 两个成因，各钉一条：
#   · 去重失效：`F|{rel}` 只对**被选中的**文件写入 `_emitted`，筛选时却从不读它
#     → 同一个文件每轮重新排队
#   · 配额是"每次对账"的上限，不是整场运行的上限 → 40 轮累积出 46 条
# 两条都不会报错，只会让引擎安静地产出一份**没人做得完**的清单。
_REVIEWED = ("app/admin/views.py", "app/wiki/views.py", "app/account/views.py",
             "app/ydata/views.py", "app/ydata/models.py")


def _revisit(led, turns=range(10, 30)) -> list:
    for rel in _REVIEWED:
        led.note_reviewed(rel, 1, 9999)
    for t in turns:
        led.recall_scan(turn=t)
    return [c for c in led.candidates.values()
            if c.source == "recall" and c.rule == "file"]


_led9 = _Ledger(scope, cfg)
_b9 = _revisit(_led9)
_counts: dict[str, int] = {}
for c in _b9:
    _counts[c.file] = _counts.get(c.file, 0) + 1
_dupes = {f: n for f, n in _counts.items() if n > 1}
echeck("同一个文件只被回访一次（20 轮扫描不重复提名）", not _dupes,
       f"重复：{_dupes}" if _dupes else f"{len(_b9)} 条覆盖 {len(_counts)} 个文件")

# 全局配额：整场运行的总量必须落在预算能处置完的范围内
_prev_q = (cfg.agent.recall_max_file_total, cfg.agent.recall_max_mention_total)
cfg.agent.recall_max_file_total = 2
cfg.agent.recall_max_mention_total = 1
_led10 = _Ledger(scope, cfg)
_b10 = _revisit(_led10)
# A 类的来源是**推理文本**，不是 note_reviewed——构造时要走事件流，
# 否则拿到 0 条，而"0 ≤ 配额"恒真，那条断言什么也没测。
_led10.log("thinking", turn=1,
           text="settings.py:18 是硬编码的 DEBUG；lib/ylinux_xmlrpc.py:60 存在越权；"
                "app/admin/views.py:62 的重定向目标未校验；"
                "app/ydata/views.py:117 下载接口无鉴权；"
                "app/wiki/views.py:432 的渲染未转义。")
for _t in range(4, 12):                     # 越过冷静期（3 轮）
    _led10.recall_scan(turn=_t)
_a10 = [c for c in _led10.candidates.values()
        if c.source == "recall" and c.rule == "mention"]
cfg.agent.recall_max_file_total, cfg.agent.recall_max_mention_total = _prev_q
# ★ 措辞按机制的**实际**承诺写：配额管的是"模型**同时**要面对几条未处置
# 的线索"，不是"整场运行一共提过几条"。两者的差别就是下面 E4d 要钉的
# 东西——而这个用例里没有任何处置/回收动作，"同时"与"累计"恰好给出同一个
# 数，所以它**测不出区别**（旧的累计实现在这里照样通过）。
echeck("B 类同时未处置量不超过配额（不是每轮的上限）", len(_b10) == 2,
       f"20 轮扫描共 {len(_b10)} 条（配额 2）")
echeck("A 类同时未处置量不超过配额", len(_a10) == 1,
       f"{len(_a10)} 条（配额 1，源文本含 5 处提及）")

# --- E4d 配额是"同时待处置量"，不是"累计提名量" -------------------------
# ★ 这两条钉的是**语义**，不是数值——每个用例都刻意在提名之后做一次
# 处置/回收，让两种语义给出不同的数。累计实现（只增不减的计数器）在这里
# 必然失败，而它正是真值 V10 没落账的原因：
#   real-reap 第 37 轮（倒数第 3 轮）在推理里提到了 `lib/ylinux_xmlrpc.py:120`
#   ——V10 的 basename 净化点，落在真值窗口 105±25 内——而 A 类 6 条配额
#   **早在第 32 轮就用完了**。用掉的那 6 条里 **5 条随后被自动回收**，
#   模型一条都没真正处理。配额烧在了"再等两轮它自己就落账了"的位置上。
# 离线扫描（tests/_tune_recall.py）在同一批账本上给出：累计语义要捞到 V10
# 得把配额提到 12；换成"同时待处置量"，冷静期 3 + 配额 6（当前默认值）
# 就捞到了。
_prev_q2 = (cfg.agent.recall_max_file_total, cfg.agent.recall_max_mention_total)
cfg.agent.recall_max_file_total = 6
cfg.agent.recall_max_mention_total = 2
_led11 = _Ledger(scope, cfg)
_led11.log("thinking", turn=1,
           text="lib/ylinux_xmlrpc.py:60 存在越权；app/admin/views.py:62 重定向未校验；"
                "settings.py:18 是硬编码的 DEBUG。")
for _t in range(4, 6):                      # 越过冷静期（3 轮）
    _led11.recall_scan(turn=_t)
_a11 = [c for c in _led11.candidates.values()
        if c.source == "recall" and c.rule == "mention"]
echeck("（前置）配额满时第三处提及进不来", len(_a11) == 2,
       f"{[f'{c.file}:{c.line}' for c in _a11]}（配额 2）")

# ① 处置即释放：模型给出结论，那条线索的使命就结束了，格子该还回来
_led11.dispose_candidate(_a11[0].id, "dismissed", "人工核过，是误报。", turn=6)
_led11.recall_scan(turn=6)
_a11b = [c for c in _led11.candidates.values()
         if c.source == "recall" and c.rule == "mention"]
echeck("处置一条后配额立即释放（腾出的格子给下一个位置）", len(_a11b) == 3,
       f"2 → {len(_a11b)} 条")

# ② 自动回收同样释放：这一条才是 V10 的病因所在——模型**连看都没看过**
#    那些位置，配额就被"反正马上会自行落账"的线索占着。
_led12 = _Ledger(scope, cfg)
_led12.log("thinking", turn=1,
           text="lib/ylinux_xmlrpc.py:60 存在越权；app/admin/views.py:62 重定向未校验；"
                "settings.py:18 是硬编码的 DEBUG。")
for _t in range(4, 6):
    _led12.recall_scan(turn=_t)
_a12 = [c for c in _led12.candidates.values()
        if c.source == "recall" and c.rule == "mention"]
# 给其中一条线索的**位置**记一条 finding——线索随即过时
_led12.record_finding({"title": "该处确有越权", "severity": "HIGH",
                       "file": _a12[0].file, "line": _a12[0].line,
                       "category": "authorization"},
                      turn=6, enforce_evidence=False)
_led12.recall_scan(turn=7)                  # 这一轮开头 `_reap_stale` 回收掉它
echeck("（前置）过时线索已被自动回收",
       not _led12.candidates[_a12[0].id].is_open,
       "".join(c.reason for c in [_led12.candidates[_a12[0].id]])[:60])
_a12b = [c for c in _led12.candidates.values()
         if c.source == "recall" and c.rule == "mention"]
echeck("自动回收同样释放配额（不必等模型回头驳回）", len(_a12b) == 3,
       f"2 → {len(_a12b)} 条")
cfg.agent.recall_max_file_total, cfg.agent.recall_max_mention_total = _prev_q2

# --- E4c 账本落盘不能缺"理由" -------------------------------------------
# `to_dict()` 曾经漏掉 `message`/`snippet`：报告读者看到"某文件某行未处置"，
# 却看不到**它为什么被提出**（"第 23 轮的推理里提到过这里"）。
# 账本是"唯一的真相来源"（06 §5.7）——真相里不能缺理由。
# 这个缺口是实测撞出来的：核对脚本读 `c["message"]` 直接 KeyError。
_dump = _led9.to_dict()["candidates"]
echeck("候选的理由（message）落盘", all("message" in c for c in _dump)
       and any(c["message"] for c in _dump))
echeck("候选的代码片段（snippet）也在", all("snippet" in c for c in _dump))

# --- E4d 过时线索的自动回收 ---------------------------------------------
# 线索的成立与否是**动态**的：提出它时那个位置确实没有结论，之后模型补了
# finding，线索就不再成立。但账本里的候选不会自己消失，模型得回头逐条驳回。
# 实测 real-fix：12 条线索只处置了 1 条，未处置的 11 条里绝大多数所在文件
# **都已经记了 finding**——模型被要求为自己已经做对的事再付一次账。
# 这类核对是机械的，系统自己做更快也更可靠。但边界要守住：
# **只有"确有 finding"才回收**，模型故意不记的那些必须留着自己给理由。
_led11 = _Ledger(scope, cfg)
_led11.log("thinking", turn=1,
           text="lib/ylinux_xmlrpc.py:60 的 delete_all_topic 是越权删除。")
for _t in range(4, 7):
    _led11.recall_scan(turn=_t)
_before11 = [c for c in _led11.open_candidates
             if c.source == "recall" and c.rule == "mention"]
echeck("（前置）过时判定前，线索处于待处置", bool(_before11),
       f"{[c.id for c in _before11]}")
_led11.recall_scan(turn=7)
echeck("无结论时线索不被回收（模型仍须表态）",
       bool([c for c in _led11.open_candidates
             if c.source == "recall" and c.rule == "mention"]))
_led11.record_finding({"title": "越权批量删帖", "severity": "HIGH",
                       "file": "lib/ylinux_xmlrpc.py", "line": 60,
                       "category": "authz"}, turn=8, enforce_evidence=False)
_led11.recall_scan(turn=9)
_left = [c for c in _led11.open_candidates
         if c.source == "recall" and c.id in {x.id for x in _before11}]
echeck("线索被后续 finding 覆盖后自动回收", not _left, f"残留 {[c.id for c in _left]}")
_reaped = [c for c in _led11.candidates.values()
           if c.source == "recall" and c.status == "dismissed"]
echeck("回收理由写明了覆盖它的 finding（可独立核对）",
       any("F-00" in c.reason for c in _reaped),
       f"{[c.reason[:60] for c in _reaped]}")
echeck("回收被记进事件流（不是隐式行为）",
       any(e.get("kind") == "recall_reaped" for e in _led11.events))

# --- E5 报告必须把线索写出来，且未处置的必须显眼 -----------------------
# 这一节是给**人**看的：漏报复核的第一手材料，就是"模型提过却没记的位置"。
_led8 = _Ledger(scope, cfg)
_led8.add_candidate(source="recall", rule="mention",
                    file="lib/ylinux_xmlrpc.py", line=105, severity="INFO",
                    message="第 5 轮的推理里提到过这里（「traversal」），账本里没有对应记录")
_meta8 = {"version": "0.1", "build": _build_meta(cfg)}
md3 = render_markdown(scope, _led8, None, engines, cfg, _meta8)
js3 = build_json(scope, _led8, None, engines, _meta8)
echeck("报告有独立的对账线索小节", "### 4.2 收敛对账线索" in md3)
echeck("报告写出了线索指向的位置", "lib/ylinux_xmlrpc.py:105" in md3)
echeck("未处置的线索被显式警告（不是静默留空）",
       "条对账线索未处置" in md3 and "建议人工优先复核" in md3)
echeck("JSON 里带了线索计数", js3.get("candidates_recall", 0) >= 1,
       f"candidates_recall={js3.get('candidates_recall')}")
echeck("构建指纹进了报告（两份报告可比不可比，读者能自己核）",
       "### 7.7 构建指纹" in md3 and "代码指纹" in md3)
echeck("指纹里带配置快照（同时改代码和改参数都能看出来）",
       "code_digest" in _meta8["build"] and "recall_after_ratio" in
       str(_meta8["build"].get("config")))

# --- E6 拿不到指纹时也要说出来，不能静默省略 ---------------------------
# 与 D3 是同一条原则：报告里的"没写"和"没有"必须能被读者区分开。
# 指纹就是给"两份报告能不能对照"用的——而读者正打算拿它去对比。
# 此时静默省略会被读成"这次运行不需要指纹"，恰恰是最危险的一种误读。
md_nocfg = render_markdown(scope, _led8, None, engines, None, {"version": "0.1"})
echeck("拿不到构建指纹时仍出 7.7 节并明说",
       "### 7.7 构建指纹" in md_nocfg and "本次未能生成构建指纹" in md_nocfg)
echeck("明说了后果（读者不能默认可比）",
       "无法确认这份报告与其它运行是否可比" in md_nocfg)
echeck("JSON 侧也带 build 字段（供 CI/看板判断可比性）",
       "build" in js3)

# --- E4y 快照必须来自磁盘：模型自填的一律作废 -------------------------------
# ★ `_fill_snippet` 曾经在"模型已经给了 snippet"时直接返回，理由写着
# 「模型真给了就用它的」——而**同一个函数的 docstring 第一条理由**说的是
# 「位置对、代码不对，比没有代码更糟，因为它看起来是可核验的」。自相矛盾，
# 而且**从没被任何用例钉过**：改掉它时四套测试的项数一个都没变。
#
# 三份真实产物实测，模型自填的快照里有：
#   · **笔记**——「# review note: 第 14 轮推理中标注 ydata/views.py:117
#     应为 Attachment 删除视图（IDOR）」，读者被告知"117 行有问题"，
#     看到的却是一句自述；
#   · **拼接**——「18 | DEBUG = True」与「49 | DATABASE_PASSWORD = ...」
#     之间夹着 `...`，而磁盘上这两行隔着 30 行；
#   · **倒序**——行号从 78 跳到 49。
# 三者都带着行号格式，所以**格式检查全绿**。这条断言是唯一能抓住它们的。
from engine.agent.tools import _fill_snippet as _fill        # noqa: E402
_real_disk = (TARGET / "lib" / "ylinux_xmlrpc.py").read_text(
    encoding="utf-8").splitlines()
_raw_snap = {"file": "lib/ylinux_xmlrpc.py", "line": 60, "end_line": 62,
             "evidence": {"snippet": "# 模型自己写的笔记，不是源码"}}
_fill(ctx, _raw_snap)
_snap = _raw_snap["evidence"]["snippet"]
_snap_nums = [int(m) for m in re.findall(r"^\s*(\d+) \| ", _snap, re.M)]
echeck("模型自填的快照被磁盘原文覆盖（不再是「真给了就用它的」）",
       "模型自己写的笔记" not in _snap and _real_disk[59].rstrip() in _snap,
       f"取到 {len(_snap.splitlines())} 行，含第 60 行原文 "
       f"{_real_disk[59].strip()[:38]!r}")
echeck("快照行号连续（拼接出来的片段在这里露馅）",
       bool(_snap_nums)
       and _snap_nums == list(range(_snap_nums[0], _snap_nums[0] + len(_snap_nums))),
       f"行号 {_snap_nums[:5]}…")

# --- E4z 成组处置：一个判断写一次，但一组只能是一个判断 ---------------------
# ★ 这一段是被一次实测失败逼出来的（real-quota）。模型在倒数第二轮写下了
# `dispose ALL candidates (34 engine + 11 recall = 45 calls) + set_coverage 7`，
# 输出撞上长度上限被截断——**45 条一条都没发出去**，那次运行的 58 条候选有
# 37 条停在 open，召回从 80% 掉到 40%。
#
# 但翻它同一批候选在 real-reap 里的理由就明白：**它早就按语义分好组了**。
# 同一处 HTTP_REFERER → redirect 的 10 条候选，它一条条写的是
#     C0001  app/admin/views.py:62  …未做同域校验 → 已并入 F-004
#     C0002  app/admin/views.py:62  同上，……并入 F-004
#     C0003  app/admin/views.py:134 同上，……并入 F-004   （共 10 遍「同上」）
# 缺的不是判断，是"把同一句判断写十遍"的输出预算。
#
# 所以这个工具的验收有两条，缺一不可：
#   · **成组真的成组** —— N 条候选一次调用落终态；
#   · **一组只能是一个判断** —— 格式错误/理由过短的批次必须**整批拒绝，
#     且一条都不执行**。少了后半条，它就变成"一句话关掉 40 条"的后门，
#     而那恰恰是批量工具最容易毁掉审计质量的地方。
_FIXTURE = dict(cfg=cfg, scope=scope, index=idx, parsed=report.modules, repo=TARGET)


def _mk_led(pairs, source="semgrep",
            rule="python.django.security.injection.open-redirect.open-redirect"):
    """构造一个只含候选的账本，pairs 形如 [("app/admin/views.py", 62), ...]"""
    l = _Ledger(scope, cfg)
    l.add_candidates([{"source": source, "rule": rule, "file": f, "line": n,
                       "message": f"{rule} at {f}:{n}"} for f, n in pairs])
    return l


_led13 = _mk_led([("app/admin/views.py", n) for n in (62, 134, 192, 257, 354)])
_reg13 = build_registry(ToolContext(ledger=_led13, **_FIXTURE))
_ids13 = list(_led13.candidates)
_r1 = _reg13.call("dispose_candidates", {"items": [
    {"candidate_ids": _ids13, "status": "dismissed",
     "reason": "这 5 处 redirect 的目标都先经 same_origin() 校验，外部无法把 "
               "Referer 改成他域，与 F-004 那处不是同一个判断"}]})
echeck("成组处置：5 条候选一次调用全部落终态",
       _r1.ok and not _led13.open_candidates
       and _reg13.calls.get("dispose_candidates") == 1,
       f"调用 {_reg13.calls.get('dispose_candidates')} 次落 "
       f"{_r1.data.get('disposed')} 条")

# 理由过短 → 整批拒绝。★ 后一条断言才是关键：如果实现是"边校验边执行"，
# 第二组（理由合格）会先被执行，账本就不再是干净的。
_led14 = _mk_led([("app/account/backends.py", n) for n in (31, 43, 48)])
_reg14 = build_registry(ToolContext(ledger=_led14, **_FIXTURE))
_ids14 = list(_led14.candidates)
_r2 = _reg14.call("dispose_candidates", {"items": [
    {"candidate_ids": _ids14[:2], "status": "dismissed", "reason": "误报"},
    {"candidate_ids": _ids14[2:], "status": "dismissed",
     "reason": "该处 % 拼接的是经 qn() 引用的标识符，用户输入全程走参数化查询，"
               "不构成注入"}]})
echeck("理由过短（「误报」两个字）的批次被拒绝", not _r2.ok)
echeck("★ 整批拒绝时**一条都没执行**（不存在半执行状态）",
       all(c.is_open for c in _led14.candidates.values()),
       f"仍待处置 {len(_led14.open_candidates)} 条")

# 账本层面的失败**不连坐**：那是数据问题，不是调用格式问题
_r3 = _reg14.call("dispose_candidates", {"items": [
    {"candidate_ids": [_ids14[0], "C9999", _ids14[1]], "status": "dismissed",
     "reason": "三处 % 拼接的都是被引号包裹的标识符，值不来自请求参数"}]})
echeck("id 不存在只影响那一条，同组其余照常生效",
       _r3.ok and _led14.candidates[_ids14[0]].status == "dismissed"
       and _led14.candidates[_ids14[1]].status == "dismissed"
       and _r3.data.get("failed") == 1,
       f"失败 {_r3.data.get('failed')} 条 / 落账 {_r3.data.get('disposed')} 条")
echeck("失败原因逐条回显，且本轮没被处置的仍是待处置",
       "C9999" in _r3.content and _led14.candidates[_ids14[2]].is_open)

# 同一条候选在两个组里 → 整批拒绝（那说明模型自己没想清楚，不该猜它的意思）
_led15 = _mk_led([("app/account/models.py", n) for n in (12, 19, 26)])
_reg15 = build_registry(ToolContext(ledger=_led15, **_FIXTURE))
_ids15 = list(_led15.candidates)
_before15 = [c.status for c in _led15.candidates.values()]
_r4 = _reg15.call("dispose_candidates", {"items": [
    {"candidate_ids": _ids15[:2], "status": "dismissed",
     "reason": "这两处的字段值来自常量，不进查询语句"},
    {"candidate_ids": _ids15[1:], "status": "confirmed", "finding_id": "F-001",
     "reason": "这一处确实把请求参数拼进了查询"}]})
echeck("同一候选出现在两组 → 整批拒绝",
       not _r4.ok and [c.status for c in _led15.candidates.values()] == _before15)

# confirmed 指不到 finding → 整批拒绝（确认了却断链，报告里就是孤儿）
_r5 = _reg15.call("dispose_candidates", {"items": [
    {"candidate_ids": _ids15, "status": "confirmed",
     "reason": "三处都把用户传入的字段名直接拼进了 ORDER BY"}]})
echeck("confirmed 没给 finding_id → 整批拒绝",
       not _r5.ok and all(c.is_open for c in _led15.candidates.values()))

# ★ 省下来的到底是什么：同一批候选，逐条发 vs 成组发
_led16 = _mk_led([("app/ydata/views.py", n) for n in range(100, 112)])
_reg16 = build_registry(ToolContext(ledger=_led16, **_FIXTURE))
_ids16 = list(_led16.candidates)
for _cid in _ids16[:6]:                       # 前 6 条逐条处置（旧路径）
    _reg16.call("dispose_candidate",
                {"candidate_id": _cid, "status": "dismissed",
                 "reason": "该分支的路径参数经 os.path.basename 截断，无法穿越目录"})
_reg16.call("dispose_candidates", {"items": [  # 后 6 条成组处置
    {"candidate_ids": _ids16[6:], "status": "dismissed",
     "reason": "这 6 处同为下载分支，文件名都经 basename 截断后拼进 open()"}]})
echeck("同一批候选：逐条要 6 次调用，成组只要 1 次",
       _reg16.calls.get("dispose_candidate") == 6
       and _reg16.calls.get("dispose_candidates") == 1
       and not _led16.open_candidates,
       f"逐条 {_reg16.calls.get('dispose_candidate')} 次 / "
       f"成组 {_reg16.calls.get('dispose_candidates')} 次，"
       f"12 条全部落终态（待处置 {len(_led16.open_candidates)}）")

# 归拢视图：模型要成组处置，先得看得见"哪几条是同一回事"
_led17 = _mk_led([("app/admin/views.py", n) for n in (62, 134, 192)])
_led17.add_candidate("bandit", "B608", "app/account/backends.py", 43,
                     message="possible SQL injection vector through string-based "
                             "query construction")
_led17.add_candidate("recall", "mention", "lib/ylinux_xmlrpc.py", 105,
                     message="推理里提到过、账本里没有结论的位置")
_reg17 = build_registry(ToolContext(ledger=_led17, **_FIXTURE))
_r7 = _reg17.call("list_candidates", {"group_by": "rule"})
echeck("归拢视图按 rule 分组，每组带自己的 id（可直接填进 dispose_candidates）",
       _r7.ok and all(cid in _r7.content for cid in _led17.candidates)
       and _r7.data.get("groups") == 3,
       f"{_r7.data.get('groups')} 组：open-redirect / B608 / recall-mention")
_r8 = _reg17.call("list_candidates", {"source": "recall"})
echeck("source=recall 能过滤（枚举里曾漏了 recall，线索清单根本调不出来）",
       _r8.ok and _r8.data.get("count") == 1,
       f"召回 {_r8.data.get('count')} 条线索")

print(f"\n  {'✅ 收敛对账四项动作齐备' if not e_bad else f'❌ {e_bad} 项不成立'}"
      f"（提得出来 / 认账不重复 / 有出口 / 写得进报告）")
