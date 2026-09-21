# -*- coding: utf-8 -*-
"""引擎零：vendored（内嵌第三方库）代码识别。

**为什么这层必须存在**：靶子侦察实测（00-侦察记录 §3）表明近一半代码是框架/第三方库拷贝，
是误报的第一大来源。而实测缺陷 **D2**（06 §0.4）证明模型不会自觉归因——
会把 Django 的 `pickle.loads` 报成项目 HIGH 漏洞。因此归因必须由代码强制。

四层识别（02 文档 §8）：
    L1 路径规则      —— 强信号但会漏（`app/sessions/` 不在 `lib/` 下）
    L2 文件头特征    —— 实测在这些文件上**全部失效**（无版权头）
    L3 指纹比对      —— ★ 实测最有效：符号签名 + 模块路径结构同构
    L4 LLM 判定      —— 由 Agent 的 check_vendored 工具调用，见 agent/tools/reasoning.py

设计约束（06 §2.2）：不确定的**不静默丢弃**，进 `suspected` 清单交 Agent 裁决。
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from .util import match_any, read_text


# ---------------------------------------------------------------- 指纹库

# L3a：已知库的特征符号。命中 ≥2 个即判定归属该库。
# 选符号的原则：**该库独有**且项目不太可能自己重名实现。
LIBRARY_SIGNATURES: dict[str, list[str]] = {
    "django": [
        "PasswordResetTokenGenerator", "SessionBase", "SessionStore",
        "ModelBackend", "BaseBackend", "SuspiciousOperation",
        "MiddlewareMixin", "BaseCommand", "ModelAdmin", "AdminSite",
        "CreateView", "UpdateView", "DeleteView", "ListView", "DetailView",
        "FormView", "TemplateView", "ModelForm", "BaseForm",
        "int_to_base36", "base36_to_int", "urlquote", "is_safe_url",
        "get_group_permissions", "has_module_perms", "get_all_permissions",
        "sha_constructor", "md5_constructor", "smart_str", "force_unicode",
        "RequestContext", "render_to_response", "get_object_or_404",
        "LazyUser", "SimpleLazyObject", "ImproperlyConfigured",
    ],
    "flask": [
        "Flask", "Blueprint", "request_started", "app_context",
        "before_first_request", "jsonify", "stream_with_context",
    ],
    "requests": [
        "HTTPAdapter", "PreparedRequest", "CaseInsensitiveDict",
        "RequestException", "SessionRedirectMixin", "InvalidSchema",
    ],
    "six": ["PY2", "PY3", "string_types", "iteritems", "with_metaclass", "add_metaclass"],
    "werkzeug": ["BaseRequest", "BaseResponse", "SharedDataMiddleware", "MapAdapter"],
    "jinja2": ["BaseLoader", "FileSystemLoader", "ChoiceLoader", "Markup", "StrictUndefined"],
    "sqlalchemy": ["declarative_base", "create_engine", "sessionmaker", "scoped_session"],
    "markdown": [
        "Markdown", "Preprocessor", "BlockProcessor",
        "InlineProcessor", "Treeprocessor", "build_extension",
    ],
    "yaml": ["SafeLoader", "FullLoader", "CSafeLoader", "add_constructor"],
    "simplejson": ["JSONEncoder", "JSONDecoder", "JSONDecodeError"],
}

# L3b：已知库的模块路径结构。用**路径后缀**匹配——
# 例如 django/contrib/sessions/backends/base.py ↔ app/sessions/backends/base.py
LIBRARY_LAYOUTS: dict[str, list[str]] = {
    "django": [
        "sessions/backends/base.py", "sessions/backends/db.py",
        "sessions/backends/cache.py", "sessions/backends/file.py",
        "sessions/backends/cached_db.py", "sessions/backends/signed_cookies.py",
        "sessions/models.py", "sessions/middleware.py",
        "auth/backends.py", "auth/tokens.py", "auth/models.py",
        "auth/hashers.py", "auth/forms.py", "auth/views.py",
        "db/models/base.py", "db/models/fields/__init__.py",
        "core/exceptions.py", "core/handlers/base.py",
        "template/backends/django.py", "middleware/csrf.py",
        "contrib/admin/options.py", "contrib/admin/sites.py",
    ],
    "markdown": [
        "markdown/",                    # 目录前缀：整个子树
        "markdown/extensions/__init__.py", "markdown/core.py",
    ],
    "requests": [
        "requests/sessions.py", "requests/models.py", "requests/adapters.py",
    ],
}


def _load_external_signatures(repo: Path) -> tuple[dict, dict]:
    """允许仓库或工具目录用 JSON 覆盖/扩展指纹库。"""
    for base in (repo / "rules", Path(__file__).parent.parent / "rules"):
        p = base / "vendored_signatures.json"
        if p.exists():
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                return (
                    {**LIBRARY_SIGNATURES, **(data.get("symbols") or {})},
                    {**LIBRARY_LAYOUTS, **(data.get("layouts") or {})},
                )
            except Exception:
                pass
    return LIBRARY_SIGNATURES, LIBRARY_LAYOUTS


# ---------------------------------------------------------------- 结果

@dataclass
class VendoredVerdict:
    path: str
    verdict: str                       # vendored | suspected | project
    confidence: float
    reasons: list[str] = field(default_factory=list)
    library: str | None = None
    layers_hit: list[str] = field(default_factory=list)
    # 被项目改造的拷贝：verdict=project 但来源是某库。
    # 报告里要显式声明——"这是 Django 代码的改造版"本身就是有价值的归因信息。
    forked_from: str | None = None

    @property
    def is_vendored(self) -> bool:
        return self.verdict == "vendored"

    @property
    def is_forked(self) -> bool:
        return self.forked_from is not None

    def to_dict(self) -> dict:
        return {
            "path": self.path, "verdict": self.verdict,
            "confidence": round(self.confidence, 2), "library": self.library,
            "forked_from": self.forked_from,
            "layers_hit": self.layers_hit, "reasons": self.reasons,
        }


# ---------------------------------------------------------------- 检测

_SYMBOL_DEF_RE = re.compile(
    r"^\s*(?:class|def)\s+([A-Za-z_][A-Za-z0-9_]*)\s*[\(:]", re.MULTILINE
)
# ★ 仅**顶层**定义才算强证据。实测踩坑：`app/account/models.py` 是项目自写的 User 模型，
# 它实现了 `has_module_perms` 方法——若把类方法也算作"定义了库独有符号"，
# 该文件会被误判为 Django 源码并被静默跳过。项目实现库同名**方法**是常态
# （自定义 User 模型必须实现 has_perm/has_module_perms），定义库同名**顶层类**才异常。
_TOPLEVEL_DEF_RE = re.compile(
    r"^(?:class|def)\s+([A-Za-z_][A-Za-z0-9_]*)\s*[\(:]", re.MULTILINE
)
_SYMBOL_NAME_RE = re.compile(r"\b([A-Z][A-Za-z0-9_]{4,})\b")


def _extract_symbols(code: str) -> tuple[set[str], set[str]]:
    """提取文件符号，**区分「定义」与「引用」**。返回 (defined, referenced)。

    ★ 这个区分是必须的——实测踩过坑：`app/admin/views.py` 引用了
    `RequestContext` / `render_to_response` / `get_object_or_404`（全是 import 进来的），
    若把「引用」等同「定义」，它会被误判为 Django 源码而被**静默跳过**，
    直接丢掉其中的 `os.system` finding。项目代码会引用库 API，但绝不会**定义**
    `SessionBase` / `PasswordResetTokenGenerator` 这类库独有的名字。
    """
    defined: set[str] = set(_TOPLEVEL_DEF_RE.findall(code))
    all_names: set[str] = set(_SYMBOL_DEF_RE.findall(code))
    all_names.update(_SYMBOL_NAME_RE.findall(code))
    for name in re.findall(r"\b([a-z][a-z0-9]*(?:_[a-z0-9]+){2,})\b", code):
        all_names.add(name)
    return (defined, all_names - defined)


def _check_l1(rel_path: str, cfg_paths: list[str]) -> str | None:
    return match_any(rel_path, cfg_paths)


def _check_l2(code: str, markers: list[str]) -> str | None:
    """只看文件头 80 行——库的版权/许可声明通常在开头。"""
    head = "\n".join(code.splitlines()[:80])
    low = head.lower()
    for m in markers:
        if m.lower() in low:
            return m
    return None


# 权重：定义库独有符号是强证据；引用库 API 是弱证据（任何用该库的项目都会引用）
_W_DEFINED = 3.0
_W_REFERENCED = 0.5
_L3_THRESHOLD = 3.0


def _check_l3(rel_path: str, code: str,
              sigs: dict, layouts: dict) -> tuple[str | None, list[str]]:
    """指纹比对。返回 (library, reasons)。

    评分制而非计数制——因为「定义」与「引用」的证据强度差一个量级（见 _extract_symbols）。
    """
    defined, referenced = _extract_symbols(code)
    scores: dict[str, float] = {}
    reasons: dict[str, list[str]] = {}

    for lib, lib_syms in sigs.items():
        d_hit = [s for s in lib_syms if s in defined]
        r_hit = [s for s in lib_syms if s in referenced]
        score = _W_DEFINED * len(d_hit) + _W_REFERENCED * len(r_hit)
        if score >= _L3_THRESHOLD:
            scores[lib] = score
            parts = []
            if d_hit:
                parts.append(f"定义了 {len(d_hit)} 个 {lib} 独有符号（{', '.join(d_hit[:3])}）")
            if r_hit:
                parts.append(f"引用 {len(r_hit)} 个 {lib} API")
            reasons[lib] = ["符号签名：" + "；".join(parts)]

    posix = rel_path.replace("\\", "/")
    for lib, layout in layouts.items():
        for suffix in layout:
            # 以 / 结尾 = 目录前缀匹配（该库的整个子树）
            if suffix.endswith("/"):
                needle = "/" + suffix
                hit = posix.startswith(suffix) or needle in posix
            else:
                hit = posix == suffix or posix.endswith("/" + suffix)
            if hit:
                scores[lib] = scores.get(lib, 0.0) + _W_DEFINED
                reasons.setdefault(lib, []).append(f"模块路径与 {lib} 同构（{suffix}）")
                break

    if not scores:
        return (None, [])
    lib = max(scores, key=lambda k: scores[k])
    return (lib, reasons.get(lib, []))


def classify(
    rel_path: str,
    code: str,
    cfg_paths: list[str],
    cfg_markers: list[str],
    sigs: dict | None = None,
    layouts: dict | None = None,
    require_confirm: bool = True,
) -> VendoredVerdict:
    """判定单个文件的归因。"""
    sigs = sigs if sigs is not None else LIBRARY_SIGNATURES
    layouts = layouts if layouts is not None else LIBRARY_LAYOUTS

    reasons: list[str] = []
    layers: list[str] = []

    l1 = _check_l1(rel_path, cfg_paths)
    l2 = _check_l2(code, cfg_markers)
    lib3, r3 = _check_l3(rel_path, code, sigs, layouts)

    if l1:
        layers.append("L1")
        reasons.append(f"L1 路径命中规则「{l1}」")
    if l2:
        layers.append("L2")
        reasons.append(f"L2 文件头含许可/版权标记「{l2}」")
    if r3:
        layers.append("L3")
        reasons.extend(r3)

    # 裁决
    if l2 or lib3:
        # L2/L3 是内容级证据，足以判定
        conf = 0.9 if (l2 and lib3) else (0.85 if lib3 else 0.75)
        return VendoredVerdict(rel_path, "vendored", conf, reasons, lib3, layers)

    if l1:
        if require_confirm:
            # L1 单独命中不足以排除——实测 app/ 下混有框架代码，
            # 但 lib/ 下也可能有项目自写代码（本靶子的 lib/ylinux_xmlrpc.py 就是）
            return VendoredVerdict(
                rel_path, "suspected", 0.4,
                reasons + ["L1 路径命中但无内容级证据，需 L4 判定"],
                None, layers,
            )
        return VendoredVerdict(rel_path, "vendored", 0.5, reasons, None, layers)

    return VendoredVerdict(rel_path, "project", 0.0, ["未命中任何 vendored 信号"], None, [])


# ---------------------------------------------------------------- 批量

class VendoredIndex:
    """全仓库归因索引。供 collect / agent 工具共享。"""

    def __init__(self, repo: Path, cfg) -> None:
        self.repo = Path(repo)
        self.cfg = cfg
        self.sigs, self.layouts = _load_external_signatures(self.repo)
        self.verdicts: dict[str, VendoredVerdict] = {}

    def scan(self, files: list[Path],
             parsed: dict | None = None) -> dict[str, VendoredVerdict]:
        """两遍扫描。

        第一遍：L1/L2/L3 内容级判定。
        第二遍：反向证据（需要第一遍结果 + 解析出的 import 关系才能做）。

        `parsed` 为 {rel: ParsedModule}；缺省时跳过第二遍（仅测试用）。
        """
        vcfg = self.cfg.vendored
        rels: list[str] = []
        codes: dict[str, str] = {}
        for f in files:
            rel = _rel(f, self.repo)
            rels.append(rel)
            codes[rel] = read_text(f)
            self.verdicts[rel] = classify(
                rel, codes[rel],
                vcfg.path_patterns, vcfg.header_markers,
                self.sigs, self.layouts, vcfg.require_confirm,
            )

        if parsed is not None:
            apply_counter_evidence(
                self.verdicts, _build_module_index(rels), parsed
            )
        return self.verdicts

    # ------------------------------------------------------ 查询

    @property
    def vendored(self) -> list[str]:
        return [p for p, v in self.verdicts.items() if v.verdict == "vendored"]

    @property
    def suspected(self) -> list[str]:
        return [p for p, v in self.verdicts.items() if v.verdict == "suspected"]

    @property
    def project(self) -> list[str]:
        return [p for p, v in self.verdicts.items() if v.verdict == "project"]

    @property
    def forked(self) -> list[str]:
        """被项目改造过的库拷贝——按项目代码审计，但报告中声明来源。"""
        return [p for p, v in self.verdicts.items() if v.is_forked]

    def get(self, rel_path: str) -> VendoredVerdict | None:
        posix = rel_path.replace("\\", "/")
        if posix in self.verdicts:
            return self.verdicts[posix]
        for p, v in self.verdicts.items():
            if p.endswith(posix) or posix.endswith(p):
                return v
        return None

    def is_suspect(self, rel_path: str) -> bool:
        v = self.get(rel_path)
        return bool(v and v.verdict in ("vendored", "suspected"))

    def summary(self) -> dict:
        from collections import Counter
        libs = Counter(v.library for v in self.verdicts.values() if v.library)
        forks = Counter(v.forked_from for v in self.verdicts.values() if v.forked_from)
        return {
            "total": len(self.verdicts),
            "vendored": len(self.vendored),
            "suspected": len(self.suspected),
            "project": len(self.project),
            "forked": len(self.forked),
            "libraries": dict(libs.most_common()),
            "forked_from": dict(forks.most_common()),
        }


# ---------------------------------------------------------------- 反向证据
#
# ★★ 归因的分界线不是「代码从哪来」，而是「谁拥有这段代码的缺陷」。
#
# 实测（靶子 `app/account/backends.py`）：该文件确实是 Django `ModelBackend` 的拷贝，
# 但项目把 `get_group_permissions` 从 ORM 重写成了裸 SQL（第 43-57 行），
# 并改成 `from account.models import User`。此时它**继承了这些缺陷**，必须按项目代码审计。
#
# 判据（本层）：**vendored 库是自包含的——库绝不会 import 宿主项目的模块。**
# 一个被判定 vendored 的文件若 import 了仓库内的**非 vendored** 模块，说明它已被项目改造（fork），
# 归因翻转为项目代码。
#
# 为什么这条规则必须存在（实测教训）：`app/account/backends.py` 是整份 ground truth 中
# **最有判别力的样本**——`%` 拼 SQL 但全部经 `qn()` 引用、唯一的用户输入走
# `cursor.execute(sql, [user_obj.id])` 参数化（Bandit 必报 B608，正确答案是**不报**）。
# 若因「看着像 Django」而静默跳过，恰好丢掉最能区分「模式匹配」与「数据流推理」的那道题。
#
# 误差不对称（因此偏置方向是明确的）：本层误判为 fork → 多审一个 vendored 文件（安全）；
# 漏判 → 静默跳过被改造的项目代码（危险）。故宁可多报。
#
# 注意：`import crypt` / `xmlrpclib` 这类 stdlib 名字**不会**误命中——必须解析到仓库真实文件。


def _build_module_index(rel_paths: list[str]) -> dict[str, str]:
    """dotted 模块名 → 仓库内 rel 路径。为每个文件生成多个候选名。

    因为源码根不确定（本靶子 `app/` 与 `lib/` 都在 sys.path 上，
    `account.models` 与 `app.account.models` 都指向 `app/account/models.py`），
    故逐级剥离前缀生成候选。键冲突时保留**路径分量更多**的那个（更精确）。
    """
    index: dict[str, str] = {}

    def put(name: str, rel: str) -> None:
        if not name:
            return
        old = index.get(name)
        if old is None or rel.count("/") > old.count("/"):
            index[name] = rel

    for rel in rel_paths:
        parts = rel.split("/")
        if not parts[-1].endswith(".py"):
            continue
        stem = parts[-1][:-3]
        parts = parts[:-1] + ([] if stem == "__init__" else [stem])
        # 逐级剥离前导分量：a/b/c.py → a.b.c, b.c, c
        for i in range(len(parts)):
            put(".".join(parts[i:]), rel)
    return index


def _module_imports(m: "ParsedModule | None") -> set[str]:
    """从已解析模块取出所有 import 的 dotted 模块名（含 from X import Y 的 X）。"""
    if m is None or not m.ok:
        return set()
    out: set[str] = set()
    for imp in m.imports:
        if imp.module:
            out.add(imp.module)
        if imp.is_from:
            # from a.b import c  → 也可能 c 本身是子模块（a.b.c）
            for n in imp.names:
                if n and n != "*" and imp.module:
                    out.add(f"{imp.module}.{n}")
        else:
            for n in imp.names:
                out.add(n)
    return out


def apply_counter_evidence(
    verdicts: dict[str, VendoredVerdict],
    module_index: dict[str, str],
    parsed: dict,
) -> dict[str, VendoredVerdict]:
    """第二遍：用「是否 import 项目本地模块」翻转被误判的 vendored。

    单遍、基于**原始 L1/L2/L3 判定**（不迭代传播）——保证结果可解释、可复现。

    同时作用于 `vendored` 与 `suspected`：
      · vendored  + 反向证据 → project（forked_from 记录来源库）
      · suspected + 反向证据 → project（**直接消解嫌疑**，省掉一次 LLM 裁决）
    实测：`lib/ylinux_xmlrpc.py` 因 `lib/**` 命中被判 suspected，但它 import 了
    `ydata.models` 与 `account`——这就是项目代码的实证，无需再问模型。
    """
    for rel, v in verdicts.items():
        if v.verdict not in ("vendored", "suspected"):
            continue
        mods = _module_imports(parsed.get(rel))
        if not mods:
            continue

        local_hits: list[str] = []
        for mod in mods:
            target = module_index.get(mod)
            if not target or target == rel:
                continue
            tv = verdicts.get(target)
            # 目标本身也是 vendored → 库内部自引用（如 markdown 包内互引），不算证据
            if tv is None or tv.verdict == "vendored":
                continue
            local_hits.append(f"{mod} → {target}")

        if not local_hits:
            continue

        was = v.verdict
        v.verdict = "project"
        v.confidence = 0.9 if was == "suspected" else 0.92
        if was == "vendored":
            v.forked_from = v.library
        v.layers_hit = list(v.layers_hit) + ["CE"]
        v.reasons = [
            f"反向证据：import 了 {len(local_hits)} 个仓库内非 vendored 模块"
            f"（{'; '.join(local_hits[:3])}）——"
            + ("已被项目改造，**缺陷归项目所有**" if was == "vendored"
               else "**确证为项目代码**，嫌疑消解"),
        ] + v.reasons

    return verdicts


def _rel(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()
