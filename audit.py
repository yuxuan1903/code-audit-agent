#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""ai-audit CLI 入口。

用法：
    python audit.py <仓库路径> [选项]

    python audit.py ../审计对象/ylinux_old-master
    python audit.py . --max-turns 60 --out ./out
    python audit.py . --engines-only          # 只跑静态引擎，不起 Agent
    python audit.py . --gate                  # 启用门禁判定，退出码反映结果

退出码：
    0  审计完成且门禁通过（或未启用门禁）
    1  门禁未通过（存在达到阈值的已验证问题）
    2  审计本身失败（范围解析失败、无可用引擎等）

**关于退出码的一个刻意选择**：门禁只由**经过对抗验证的** finding 触发。
静态引擎的原始命中不会拦门——它们只是候选，未经判断。
若不做这个区分，开发团队会在被误报拦下第三次之后关掉这个门禁。
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from engine.util import force_utf8
force_utf8()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ai-audit",
        description="AI Agent 代码安全审计（静态引擎 + 数据流推理 + 对抗验证）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    p.add_argument("repo", nargs="?", default=".",
                   help="被审计的仓库路径（默认当前目录）")
    p.add_argument("--out", "-o", default=None, help="输出目录")
    p.add_argument("--config", "-c", default=None, help="配置文件路径")
    p.add_argument("--max-turns", type=int, default=None, help="Agent 最大轮次")
    p.add_argument("--max-tokens", type=int, default=None, help="Agent token 预算")
    p.add_argument("--provider", default=None,
                   choices=["auto", "deepseek", "anthropic", "local", "mock"])
    p.add_argument("--model", default=None, help="模型名")
    p.add_argument("--base-url", default=None, help="LLM API 基址")
    p.add_argument("--engines-only", action="store_true",
                   help="只跑静态引擎，不启动 Agent")
    p.add_argument("--no-engines", action="store_true", help="跳过静态引擎")
    p.add_argument("--gate", action="store_true", help="启用门禁判定")
    p.add_argument("--fail-on", default=None,
                   choices=["critical", "high", "medium", "low"],
                   help="门禁阈值（默认 high）")
    p.add_argument("--exclude", action="append", default=None,
                   help="追加排除模式（可多次）")
    p.add_argument("--quiet", "-q", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    t0 = time.time()

    repo = Path(args.repo).resolve()
    if not repo.is_dir():
        print(f"❌ 路径不存在或不是目录：{repo}", file=sys.stderr)
        return 2

    from engine.config import Config
    overrides: dict = {}
    if args.max_turns or args.max_tokens:
        overrides["agent"] = {}
        if args.max_turns:
            overrides["agent"]["max_turns"] = args.max_turns
        if args.max_tokens:
            overrides["agent"]["max_tokens"] = args.max_tokens
    if args.provider or args.model or args.base_url:
        overrides.setdefault("llm", {})
        if args.provider:
            overrides["llm"]["provider"] = args.provider
        if args.model:
            overrides["llm"]["model"] = args.model
        if args.base_url:
            overrides["llm"]["base_url"] = args.base_url
    if args.exclude:
        overrides.setdefault("scan", {})["exclude"] = args.exclude
    if args.out:
        overrides["out_dir"] = args.out

    cfg = Config.load(repo, args.config, overrides)
    if args.gate:
        cfg.gate.enabled = True
    if args.fail_on:
        cfg.gate.fail_on = args.fail_on

    if not args.quiet:
        _banner(repo, cfg)

    # ---------------------------------------------------------- 1 范围
    from engine.collect import collect
    try:
        scope, report = collect(cfg)
    except Exception as e:
        print(f"❌ 范围解析失败：{type(e).__name__}: {e}", file=sys.stderr)
        return 2
    if not args.quiet:
        print(f"  范围契约：{len(scope.files)} 个文件 → 在审 {len(scope.in_scope)} 个；"
              f"外部入口 {len(scope.entry_points)} 个")
        vend = [f for f in scope.files.values() if f.attribution == "vendored"]
        fork = [f for f in scope.files.values() if f.forked_from]
        print(f"  归因：vendored {len(vend)} 个"
              + (f"，**改造版 {len(fork)} 个（缺陷归项目）**" if fork else ""))

    # ---------------------------------------------------------- 2 引擎
    engines: dict = {}
    candidates: list[dict] = []
    if not args.no_engines:
        from engine.engines import BanditRunner, SemgrepRunner
        if cfg.engines.semgrep_enabled:
            if not args.quiet:
                print("  运行 semgrep …", end="", flush=True)
            engines["semgrep"] = SemgrepRunner(cfg).run()
            if not args.quiet:
                print(f" {len(engines['semgrep'].hits)} 条命中")
            candidates += [h.to_candidate() for h in engines["semgrep"].hits]
        if cfg.engines.bandit_enabled:
            if not args.quiet:
                print("  运行 bandit  …", end="", flush=True)
            engines["bandit"] = BanditRunner(cfg, parsed=report.modules).run()
            if not args.quiet:
                print(f" {len(engines['bandit'].hits)} 条命中"
                      + (f"，**跳过 {len(engines['bandit'].skipped_files)} 个文件**"
                         if engines["bandit"].skipped_files else ""))
            candidates += [h.to_candidate() for h in engines["bandit"].hits]
        if cfg.engines.secret_enabled:
            # 凭据扫描。★ 它的候选是**唯一一类在生成时就已经脱敏的候选**——
            # 命中值在 SecretRunner 内部就被换成指纹，账本与报告里不会出现明文。
            from engine.engines.secret_runner import SecretRunner
            if not args.quiet:
                print("  运行 secret  …", end="", flush=True)
            engines["secret"] = SecretRunner(cfg, scope=scope).run()
            if not args.quiet:
                n = len(engines["secret"].hits)
                print(f" {n} 条命中" + ("（已脱敏）" if n else ""))
            candidates += [h.to_candidate() for h in engines["secret"].hits]

    # ---------------------------------------------------------- 3 索引
    from engine.agent.ledger import Ledger
    from engine.context import CodeIndex
    index = CodeIndex(scope, report)
    ledger = Ledger(scope, cfg)
    ledger.add_candidates(candidates)
    if not args.quiet:
        st = index.stats()
        print(f"  符号索引：{st['symbols']} 个符号 / {st['call_edges']} 条调用边"
              f"（可解析 {st['resolved_ratio']:.0%}）")
        print(f"  候选入账：{len(candidates)} 条待处置")

    # ---------------------------------------------------------- 4 Agent
    result = None
    if not args.engines_only and cfg.agent.enabled:
        from engine.agent.loop import AuditAgent
        from engine.providers.base import make_provider
        provider, perr = _make_provider(cfg, args, quiet=args.quiet)
        if provider is None and not cfg.llm.fallback_to_engines_only:
            print(f"❌ 无法初始化 LLM：{perr}", file=sys.stderr)
            return 2
        agent = AuditAgent(cfg, scope, report, ledger, index=index,
                           provider=provider, candidates=candidates)
        if not args.quiet:
            print(f"\n  启动 Agentic 分析（模型 {getattr(provider, 'name', '无')}，"
                  f"预算 {cfg.agent.max_turns} 轮 / {cfg.agent.max_tokens:,} tokens）")
        result = agent.run()
        if not args.quiet:
            print(f"  {result.summary()}")
    elif args.engines_only and not args.quiet:
        print("\n  （--engines-only：跳过 Agentic 分析）")

    # ---------------------------------------------------------- 5 报告
    from engine.report import evaluate_gate, render_markdown, write_reports
    meta = {"version": "0.1",
            "tool_stats": getattr(result, "tool_stats", {}) if result else {},
            "gate_fail_on": cfg.gate.fail_on,
            "data_sent_external": _external_tokens(result),
            "tokens_in": getattr(result, "input_tokens", 0) if result else 0,
            "tokens_out": getattr(result, "output_tokens", 0) if result else 0}
    written = write_reports(cfg, scope, ledger, result, engines, meta)

    if not args.quiet:
        print(f"\n  报告已生成：")
        for k, p in written.items():
            print(f"    {k:8s} {p}")

    gate = evaluate_gate(ledger, cfg.gate.fail_on)
    if not args.quiet:
        _summary(ledger, gate, time.time() - t0, cfg)

    if cfg.gate.enabled and not gate["passed"]:
        return 1
    return 0


# ---------------------------------------------------------------- 辅助

def _make_provider(cfg, args, quiet: bool):
    from engine.providers.base import ProviderError, make_provider
    if args.provider == "mock":
        from engine.providers.mock import MockProvider
        return MockProvider(cfg.llm), ""
    try:
        p = make_provider(cfg)
        if not quiet:
            print(f"  LLM 后端：{p.name}（模型 {cfg.llm.model or '默认'}）")
            if not p.caps.supports_tool_calling:
                print("  ⚠️ 该后端不支持 tool calling，Agent 将无法自主选择工具")
        return p, ""
    except Exception as e:
        if not quiet:
            print(f"  ⚠️ LLM 不可用（{type(e).__name__}: {e}）——"
                  f"降级为仅静态引擎模式")
        return None, str(e)


def _external_tokens(result) -> int:
    """★ 数据外发量（03 §5）。

    被审代码的内容会随工具结果发给 LLM。这个数字让"数据不出域"的要求
    从一句口号变成可核对的事实——如果策略要求敏感代码不外发，
    至少要能知道实际发了多少。

    **取服务端回报的 input_tokens，不取本地估算。** 曾经这里按账本事件
    的文本长度 //4 估算，实测报出 3,006，而 provider 回报的输入量是
    十万量级——**低估了 36 倍**。原因是账本记的是"每个事件自己的文本"，
    而真正的发送量是"每一轮把整个对话历史重新发一遍"的累加：轮次越多，
    低估越严重。一个用于合规声明的数字低估 36 倍，比没有这个数字更糟。

    输入侧才是"外发"的量（输出是模型自己生成的，不涉及把代码送出去）；
    缓存命中的部分也计在内——它们此刻存在于对方服务端。
    """
    if result is None:
        return 0                      # 没跑 Agent，就没有内容离开本机
    return (getattr(result, "input_tokens", 0)
            + getattr(result, "cache_read_tokens", 0)
            + getattr(result, "cache_write_tokens", 0))


def _banner(repo: Path, cfg) -> None:
    print("=" * 74)
    print(f"ai-audit  ·  {repo}")
    print("=" * 74)
    print(f"  配置：模式 {cfg.mode}，输出到 {cfg.out_dir}")


def _summary(ledger, gate: dict, seconds: float, cfg) -> None:
    from engine.schema import Attribution, CoverageStatus
    print()
    print("=" * 74)
    print("审计结果")
    print("=" * 74)

    n = len(ledger.coverage)
    done = [e for e in ledger.coverage.values()
            if e.status not in (CoverageStatus.UNVERIFIED,)]
    print(f"覆盖度：{len(done)}/{n} 类已落终态")
    for e in ledger.coverage.values():
        mark = {"covered": "✅", "no_issue": "✅", "skipped": "⏭️",
                "out_of_scope": "➖", "unverified": "⬜"}[e.status.value]
        if e.status.value in ("unverified", "skipped"):
            print(f"  {mark} {e.coverage_class:14s} {e.status.value}"
                  f"  {e.note[:60]}")

    active = [f for f in ledger.findings.values() if f.is_active]
    vend = [f for f in ledger.findings.values()
            if f.attribution != Attribution.PROJECT]
    print(f"\n问题：{len(active)} 条有效"
          + (f"（另有 {len(vend)} 条归因为非项目代码，不计入）" if vend else ""))
    for f in sorted(active, key=lambda x: -x.severity.rank):
        icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡",
                "LOW": "🔵", "INFO": "⚪"}[f.severity.value]
        v = f.verification.verdict.value
        vt = "" if v == "UNVERIFIED" else f" [{v}]"
        print(f"  {icon} {f.id} {f.location['file']}:{f.location['line']}"
              f"  {f.title[:56]}{vt}")

    op = ledger.open_candidates
    if op:
        n_rec = len([c for c in op if c.source == "recall"])
        tail = (f"（其中 {n_rec} 条是收敛对账线索——模型推理里提过、账本里没记的位置）"
                if n_rec else "")
        print(f"\n⚠️  {len(op)} 条候选未处置——它们既不算漏洞也不算误报{tail}")

    if gate["coverage_complete"] is False:
        print("\n⚠️  覆盖度未完成：本次结论的适用范围见报告第二节")

    print(f"\n总耗时 {seconds:.0f}s")
    if cfg.gate.enabled:
        icon = "✅" if gate["passed"] else "❌"
        print(f"{icon} 门禁（阈值 {gate['fail_on']}）：{gate['note']}")


if __name__ == "__main__":
    sys.exit(main())
