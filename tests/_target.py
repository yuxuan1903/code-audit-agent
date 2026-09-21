# -*- coding: utf-8 -*-
"""被审仓库的定位。

★ 存在的理由（2026-09-20 实测）

本目录原有 9 个脚本各自写死了：

    TARGET = ROOT / "审计对象" / "ylinux_old-master"

这在第一代位于 `ai 代码审计/` 时成立。第一代被移入 `第一代-Claude-原型/` 之后，
靶子留在了上一级，于是这些路径全部指空，三处红行是同一个根因：

  · `_t_collect.py` —— scope 为空 → 「入口契约核验：0/22 通过」，22 项全红；
  · `_t_engines.py` —— 引擎候选为空 → 「候选 C0001 不存在」；
  · `_t_agent.py`   —— 对账线索为空 → `_a11[0]` 抛 IndexError。

**这三处都不是审计逻辑的缺陷**，但它们暴露了一个真实的设计问题：把
「找不到靶子」静默地当成「靶子里什么都没有」，会让一整屏判据红掉，
而红的原因与被审代码毫无关系。所以定位收进一个函数，找不到就明确退出。

★ 为什么放在 tests/ 而不是 engine/util.py

`engine/util.py:build_fingerprint()` 用 `engine/**/*.py` + `audit.py` 计算
`code_digest`，而这个项目的全部历史结论都建立在「同指纹才可对照」之上。
往 engine/ 里加一个函数，会让已归档的十几次真实运行与当前代码不再可比。
测试不参与指纹计算（改了测试不该让两份报告失去可比性），所以定位工具放这里。

★ 定位顺序

    1. 环境变量 AUDIT_TARGET —— 显式指定优先；指错了报错，不静默回退到猜；
    2. 从本文件所在目录逐级上溯，每一级试 `审计对象/<name>` 与 `<name>`。

找到第一个存在的目录即返回；都不存在返回 None。
"""
from __future__ import annotations

import os
from pathlib import Path

DEFAULT_NAME = "ylinux_old-master"
ENV_VAR = "AUDIT_TARGET"
SCOPE_DIR = "审计对象"
MAX_UP = 4


def resolve_target(name: str = DEFAULT_NAME, start: Path | None = None) -> Path | None:
    """返回被审仓库的绝对路径；找不到返回 None。"""
    override = os.environ.get(ENV_VAR, "").strip()
    if override:
        p = Path(override).expanduser()
        return p.resolve() if p.is_dir() else None

    base = Path(start or Path(__file__).resolve().parent).resolve()
    for _ in range(MAX_UP + 1):
        for candidate in (base / SCOPE_DIR / name, base / name):
            if candidate.is_dir():
                return candidate.resolve()
        if base.parent == base:
            break
        base = base.parent
    return None


def require_target(name: str = DEFAULT_NAME) -> Path:
    """定位被审仓库；找不到就明确退出，绝不把空范围当成审计结果。"""
    target = resolve_target(name)
    if target is None:
        print(f"⚠️  未找到被审仓库 {name}——脚本需要它位于 {SCOPE_DIR}/ 下，"
              f"或用环境变量 {ENV_VAR} 显式指定。")
        print(f"   例：{ENV_VAR}='/path/to/{name}' python tests/_t_collect.py")
        print("   找不到靶子时**不**降级为空范围继续跑：那会把全部入口契约判成失败，"
              "而失败原因与被审代码无关。")
        raise SystemExit(2)
    return target
