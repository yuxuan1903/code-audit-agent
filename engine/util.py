# -*- coding: utf-8 -*-
"""平台适配与通用工具。

★ 平台约束（README §6 实测）：Windows + 中文用户名下，bash 无法正确处理含中文的路径
（Python 以 GBK 输出路径，bash 按 UTF-8 解码失败）。因此**所有外部工具调用必须走
本模块的 run_tool()**，用 Python subprocess 传绝对路径，不经 shell。
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import sysconfig
from pathlib import Path

# ---------------------------------------------------------------- 编码

def force_utf8() -> None:
    """在任何入口最先调用，避免中文路径/内容在 Windows 控制台乱码。"""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def read_text(path: Path, max_bytes: int = 2_000_000) -> str:
    """宽容读取：优先 utf-8，回退 latin-1（Py2 源码常见）。绝不因编码中断审计。"""
    try:
        raw = path.read_bytes()
    except OSError:
        return ""
    if len(raw) > max_bytes:
        raw = raw[:max_bytes]
    for enc in ("utf-8", "utf-8-sig", "gbk", "latin-1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


# ---------------------------------------------------------------- 外部工具

_SCRIPTS_DIR = Path(sysconfig.get_path("scripts"))


def find_tool(name: str) -> str | None:
    """定位外部工具的可执行文件绝对路径。

    优先 Scripts 目录（与当前解释器同环境的 exe），其次 PATH。
    返回绝对路径字符串；找不到返回 None。
    """
    for suffix in (".exe", ""):
        p = _SCRIPTS_DIR / f"{name}{suffix}"
        if p.exists():
            return str(p)
    from shutil import which
    return which(name)


def run_tool(
    args: list[str],
    cwd: Path | None = None,
    timeout: int = 300,
    env_extra: dict[str, str] | None = None,
) -> tuple[int, str, str]:
    """执行外部工具，返回 (returncode, stdout, stderr)。

    **不经 shell**——这既避免中文路径问题，也消除命令注入面。
    args[0] 若为工具名，自动解析为绝对路径。
    """
    if not args:
        return (-1, "", "empty args")

    exe = find_tool(args[0]) or args[0]
    argv = [exe, *args[1:]]

    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    if env_extra:
        env.update(env_extra)

    try:
        proc = subprocess.run(
            argv,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            timeout=timeout,
            env=env,
        )
    except subprocess.TimeoutExpired:
        return (-1, "", f"timeout after {timeout}s: {' '.join(args)}")
    except FileNotFoundError:
        return (-1, "", f"tool not found: {args[0]}")
    except OSError as e:
        return (-1, "", f"OSError: {e}")

    out = proc.stdout.decode("utf-8", errors="replace")
    err = proc.stderr.decode("utf-8", errors="replace")
    return (proc.returncode, out, err)


def run_tool_json(args: list[str], **kw) -> tuple[Any | None, str]:
    """执行并解析 JSON 输出。返回 (data, error)。"""
    code, out, err = run_tool(args, **kw)
    text = out.strip()
    if not text:
        return (None, f"exit={code} no output; stderr={err[:400]}")
    # 有些工具会在 JSON 前打印日志行
    start = text.find("{")
    start_b = text.find("[")
    if start == -1 or (start_b != -1 and start_b < start):
        start = start_b
    if start > 0:
        text = text[start:]
    try:
        return (json.loads(text), "")
    except json.JSONDecodeError as e:
        return (None, f"JSON parse failed: {e}; head={text[:300]}")


# ---------------------------------------------------------------- 路径

def rel_posix(path: Path, root: Path) -> str:
    """相对 root 的 POSIX 风格路径——报告与去重键统一用它。"""
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def glob_match_posix(rel_path: str, pattern: str) -> bool:
    """POSIX 风格的 glob 匹配（支持 ** 与 *），Windows 下语义一致。"""
    import fnmatch

    rel = rel_path.replace("\\", "/").lstrip("./")
    pat = pattern.replace("\\", "/").lstrip("./")

    if pat.endswith("/**"):
        prefix = pat[:-3]
        if rel == prefix or rel.startswith(prefix + "/"):
            return True
    if fnmatch.fnmatch(rel, pat):
        return True
    # **/x 应同时匹配顶层的 x
    while pat.startswith("**/"):
        pat = pat[3:]
        if fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(rel, f"*/{pat}"):
            return True
    return False


def match_any(rel_path: str, patterns: list[str]) -> str | None:
    for p in patterns or []:
        if glob_match_posix(rel_path, p):
            return p
    return None


# ---------------------------------------------------------------- 构建指纹

def build_fingerprint(extra_config: dict | None = None,
                      root: Path | None = None) -> dict:
    """本次运行的构建指纹（验收报告 §六-9）。

    ★ 存在的理由：Phase 1 的两次真实运行之间落过一批报告层修复，而报告里
    没有任何字段能证明"这两次跑的是不是同一份代码"。于是"同条件复跑"
    只能靠人声明，而**人声明的东西不可核**——想核对的人只能去翻文件时间戳，
    那既不可靠也不可复现。

    指纹把这句话变成可核的：两次运行的 `code_digest` 不同，就**不能**
    把两份报告当作对照，任何"改进了/退步了"的结论都不成立。

    只算**会产生报告的那部分代码**（`engine/` + `audit.py`），不含测试与设计
    文档：改了测试不该让两份报告失去可比性，而改了引擎就必须失去。

    `extra_config` 装的是当次运行的配置快照（预算、阈值、开关）。它与代码
    分开列，是因为两者回答不同的问题——"跑的是哪份代码"与"用的是哪套参数"。
    合成一个哈希，就无法从两个不同的指纹里看出到底哪个变了。
    """
    import hashlib
    root = Path(root or Path(__file__).resolve().parent.parent)
    files = sorted(p for p in [*root.glob("engine/**/*.py"), root / "audit.py"]
                   if p.is_file())
    h = hashlib.sha256()
    per: dict[str, str] = {}
    for p in files:
        rel = p.relative_to(root).as_posix()
        d = hashlib.sha256(p.read_bytes()).hexdigest()[:12]
        per[rel] = d
        h.update(rel.encode("utf-8"))
        h.update(d.encode("utf-8"))
    return {
        "code_digest": h.hexdigest()[:16],
        "code_files": len(per),
        "code": per,
        "config": dict(extra_config or {}),
    }
