# -*- coding: utf-8 -*-
"""收敛对账（06 §5.8）——把"推理里提过、账本里没有"的位置找出来。

## 为什么需要它

验收报告 §4 的结论是：两次真实运行的全部漏报，**没有一条是"读不懂代码"或
"判断错了漏洞类型"**。三种形态都落在同一个地方——模型看见了、说出来了，
但没有落账：

  · V9  = 记录遗漏：第 5 轮已把 `delete_all_topic` 定性为越权（C3），
          写进 thinking 时正好被 max_tokens 截断，finding 从未建立。
  · V11 = 覆盖不全：同一轮里识别出 3 处，只落账 1 处。
  · V10 = 低严重度倾向不记："That could allow writing .py or html files.
          But limited. Let me hold."

三者的共同点是：**证据在轨迹里，不在账本里**。而报告只读账本。
所以漏报不是"没发现"，是"发现了但没留下"。

## 它做什么

两项对账，都只用已有数据、不额外调用模型：

  **A 提及对账**：从 thinking / assistant_text 抽出 `文件:行` 引用，与
    已记录 finding、覆盖度证据、候选处置理由逐条比对，列出"提过但没记"的位置。

  **B 文件回访**：列出"读过相当比例、却既无 finding 也无覆盖说明"的文件。
    §4.5 的判断是这类文件最可能藏着漏报，而它用的全是现成数据。

命中的位置不直接变成结论，而是作为**候选**进入账本，按既有契约处置
（confirmed 必须给 finding_id、dismissed 必须给理由）。于是"发现了但决定不报"
从一个静默的省略，变成一条留在报告里的判断。

## 刻意不做的

  · **不读代码、不判断真假**。它只做位置比对，真假由模型或人判。
    任何在这里下结论的尝试都会引入第二套判据，而两套判据必然打架。
  · **不做小作文**。给模型的每条都是"位置 + 你为什么提过它"，
    让它在最小的上下文里做决定。
  · **不重复报**。同一位置只生成一次候选；已处置过的不再出现。
"""
from __future__ import annotations

import re

# ---------------------------------------------------------------- 词表

# 只在推理文本里找这些扩展名。列表短是刻意的：抽不到的位置退化成"没提过"，
# 而抽错的位置要花模型一次工具调用去否掉。
_FILE_EXT = "py|pyw|txt|cfg|ini|conf|json|yml|yaml|md|html|htm|xml|js|sh|sql"

# 一个 `文件:行` 引用。四种写法都出现过，缺一种就漏一批：
#   `settings.py:79` / `admin/views.py lines 62,134` /
#   `settings.py 96-160`（空格分隔）/ `views.py 的第 38 行`
_REF_RE = re.compile(
    r"(?<![\w./\\-])"
    r"(?P<path>(?:[\w.\-]+[/\\])*[\w.\-]+\.(?:" + _FILE_EXT + r"))(?![\w])"
    r"(?:\s*[:：]\s*|\s*[(（]?\s*lines?\s+|\s*第\s*|\s+)"
    r"(?P<l1>\d{1,5})"
    r"(?:\s*[-–~至]\s*(?P<l2>\d{1,5}))?"
)

# 句子切分。中文句读、换行、以及英文句末+空格。
_SEG_SPLIT = re.compile(r"(?<=[。！？；])|\n+|(?<=[.!?;])\s+")

# 只给"文件级提及"用：**不要求跟行号**。
# ★ 为什么必须有它：实测 real-final 里对 `lib/ylinux_xmlrpc.py` 的越权讨论
# 恰好写在被 2000 字上限截断的那一段里，且通篇用反引号写方法名、不带行号——
# 只认 `文件:行` 的话，这个文件在对账里根本不存在。它最后是靠 B 类回访
# 兜住的，而 B 的排序需要知道"模型是否说过它可疑"。
_FILE_RE = re.compile(
    r"(?<![\w./\\-])(?P<path>(?:[\w.\-]+[/\\])*[\w.\-]+\.(?:" + _FILE_EXT + r"))"
    r"(?![\w])"
)

# ★ 危险词表的用法是"同一句里出现了它，这句话才值得对账"。
# 没有它，对账会退化成"把模型读过的每个行号都列出来"——那种清单没人看得完，
# 模型会一律 dismissed，机制就白做了。
# 词表偏宽是有意的：**漏掉一个真实提及的代价，远大于多问一句**。
_HAZARD = (
    # 中文
    "漏洞", "风险", "危险", "可疑", "隐患", "未鉴权", "越权", "未授权",
    "注入", "穿越", "绕过", "硬编码", "明文", "密钥", "凭据", "敏感",
    "未校验", "未过滤", "未验证", "未检查", "缺少", "没有校验", "任意",
    "可被", "攻击者", "泄露", "篡改", "伪造",
    # 英文
    "vulnerab", "inject", "xss", "csrf", "ssrf", "rce", "traversal",
    "arbitrary", "unsanitiz", "unvalidat", "no validat", "not validat",
    "no check", "without check", "missing", "bypass",
    "hardcod", "secret_key", "credential", "privilege",
    "unauthor", "authz", "escalat", "deserializ", "pickle", "exploit",
    "attacker", "malicious", "insecure", "unsafe",
    "delete all", "object-level", "tamper", "forge", "leak",
)
# ★ 刻意剔掉的词：`password` / `secret` / `lack` / `danger`。
# 它们太泛——实测出现过 "I need account/views.py lines 130-254
# (register rest, password reset, ajax login)." 这种纯导航句，只因为
# 出现了 "password" 就被判成危险提及，白白占掉一个对账名额。
# 判别力来自**具体**的词（"hardcod"、"secret_key"、"traversal"），
# 泛词只会把清单塞满。

# 推理文本里回显引擎候选清单的段落（"C0012: B608 SQL in backends.py:43"）。
# 这些位置本来就有自己的处置通道（dispose_candidate），再报一次只是噪音。
_CANDIDATE_ECHO = re.compile(r"\bC\d{4}\b")

# 判定"同一位置"的行容差。取 15 是因为一个函数体通常在这个尺度内；
# 比它宽会把"提了 A 函数、记了 B 函数"误判成已覆盖。
LOC_TOL = 15

# ★ 自动回收（`Ledger._reap_stale`）用的容差，比 LOC_TOL 严得多。
# 两个动作方向相反，对证据的要求也该不同：
#   · `LOC_TOL=15` 决定"**还要不要问一次**"——放宽的代价是少问一次，
#     而漏问恰恰是对账机制存在的理由，所以宁可宽。
#   · 回收决定"**这条线索就地关掉**"——是系统**替模型**下的结论，
#     放宽的代价是一条线索静默消失（理由虽然写明，但没人会去复核
#     一条已经显示为"已处置"的条目）。所以宁可严。
# 取 3：finding 的 location 与线索坐标真正重合、或落在同一小段内才回收。
# 实测意义上，这意味着"同文件里另一个函数被记了 finding"**不会**关掉
# 这条线索——模型仍须自己表态，那正是对账要留下的东西。
REAP_TOL = 3

# 提及的**冷静期**（轮）。刚说出口的位置先给它几轮机会自行落账，
# 到期还没记才提出来对账——否则模型每轮都要处置上一轮自己的探索性发言。
MENTION_GRACE_TURNS = 3


# ---------------------------------------------------------------- 解析

def resolve(name: str, scope) -> str | None:
    """把推理文本里的文件名解析成仓库相对路径。**有歧义就放弃。**

    猜错文件比不猜更糟：对账条目会指向一个模型根本没提过的地方，
    模型只能把它 dismissed，机制的可信度就没了。
    """
    posix = name.replace("\\", "/").lstrip("./")
    files = scope.files
    if posix in files:
        return posix
    # 带目录的片段（`admin/views.py` → `app/admin/views.py`）
    hits = [k for k in files if k.endswith("/" + posix)]
    if len(hits) == 1:
        return hits[0]
    if len(hits) > 1:
        return None
    # 只有 basename（`views.py`）——全仓库唯一才认
    base = posix.rsplit("/", 1)[-1]
    hits = [k for k in files if k.rsplit("/", 1)[-1] == base]
    return hits[0] if len(hits) == 1 else None


def _entry_owner(ep, scope) -> str | None:
    """入口点的**实现文件**。

    ★ `EntryPoint.file` 是声明处，不是实现处——直接拿它统计会得出
    "app/wiki/urls.py 暴露 30 个入口"这种结论，而 urls.py 只是张路由表，
    里面没有一行可审的逻辑。实测第一版就是这么排的，结果 30 条的 urls.py
    把真正藏着漏报的 `lib/ylinux_xmlrpc.py`（8 个 XML-RPC 方法）挤出了名额。

    Django 的两种形态各解一半：
      · http_route：view 是裸函数名（`login`），实现就在同级 views.py
      · xmlrpc：view 是点号路径（`ylinux_xmlrpc.delete_all_topic`），取模块段
    """
    view = (ep.view or "").strip()
    if ep.kind == "xmlrpc":
        mod = view.rsplit(".", 1)[0]
        if "." not in mod:
            tail = mod + ".py"
            hits = [k for k in scope.files if k.endswith("/" + tail)]
            return hits[0] if len(hits) == 1 else None
        tail = "/".join(mod.split(".")) + ".py"
        hits = [k for k in scope.files if k.endswith(tail)]
        return hits[0] if len(hits) == 1 else None
    if "." in view:                       # include('app.x.urls') 之类，跳过
        return None
    d = ep.file.rsplit("/", 1)[0] if "/" in ep.file else ""
    rel = (d + "/views.py") if d else "views.py"
    return rel if rel in scope.files else None


def _hazardous(seg: str) -> str:
    """这句话里的危险词（空串 = 只是个行号，不值得对账）。"""
    low = seg.lower()
    for w in _HAZARD:
        if w in low:
            return w
    return ""


def extract_files(text: str, scope) -> list[dict]:
    """抽出"被点名且被说成可疑"的文件（不要求带行号）。

    只用于给 B 类回访排序：一个"读过、没结论、但推理里说过它可疑"的文件，
    比一个"读过、没结论、也没人提过"的文件更该被回访。
    """
    out: list[dict] = []
    for seg in _SEG_SPLIT.split(text or ""):
        if not seg or len(seg) < 12:
            continue
        haz = _hazardous(seg)
        if not haz:
            continue
        # ★ 一句话里出现多个文件 = 这是"接下来要读哪几个"的**计划**，不是在
        # 判定哪个文件有问题。实测那句 "Now let me look at the remaining views:
        # ydata/views.py (attachment download + path traversal!), ydata/models.py,
        # wiki/views.py, me/views.py, syndication/views.py" 会把 "traversal"
        # 平分给列表里每一个文件，于是 me/views.py（12 个入口）顶掉了真正
        # 该回访的文件。只认**单文件句**——一个文件不可分，多个文件的句子
        # 说不清危险词属于谁。
        if len(list(_FILE_RE.finditer(seg))) > 1:
            continue
        for m in _FILE_RE.finditer(seg):
            rel = resolve(m.group("path"), scope)
            if rel is None:
                continue
            fi = scope.get(rel)
            if fi is None or fi.attribution == "vendored":
                continue
            out.append({"file": rel, "hazard": haz,
                        "seg": " ".join(seg.split())[:220]})
    return out


def extract(text: str, scope, require_hazard: bool = True) -> list[dict]:
    """从一段推理文本里抽出 `文件:行` 引用。

    返回 [{file, line, end_line, hazard, seg}]。

    `require_hazard=False` 用于**finding 的证据文本**：那里的坐标是模型自己
    写下的结论的一部分，不需要危险词来证明它在意——写下就是在意。
    """
    out: list[dict] = []
    for seg in _SEG_SPLIT.split(text or ""):
        if not seg or len(seg) < 12:
            continue
        if _CANDIDATE_ECHO.search(seg):
            continue                       # 回显候选清单，另有处置通道
        haz = _hazardous(seg)
        if require_hazard and not haz:
            continue
        for m in _REF_RE.finditer(seg):
            rel = resolve(m.group("path"), scope)
            if rel is None:
                continue
            fi = scope.get(rel)
            if fi is None or fi.attribution == "vendored":
                continue                   # 第三方代码不进项目漏报对账
            l1 = int(m.group("l1"))
            l2 = int(m.group("l2")) if m.group("l2") else l1
            if l1 < 1 or l1 > max(fi.lines, 1):
                continue                   # 行号超出文件范围 = 解析错了
            out.append({
                "file": rel, "line": l1, "end_line": min(max(l1, l2), fi.lines),
                "hazard": haz,
                "seg": " ".join(seg.split())[:220],
            })
    return out


# ---------------------------------------------------------------- 账本视图

class Accounted:
    """账本里已有的"处置痕迹"。判定一个位置是否已经被交代过。

    只认**两类硬痕迹**：
      · findings 的位置（含 end_line 区间）
      · 引擎候选的位置（候选自有 dispose 通道）

    ★ 曾经还有第三类——"note / 理由文本里点名过这个文件就算处置过"。
    实测把它删掉了，因为它在真实账本上**正好压掉要抓的那两个文件**：
      · `lib/ylinux_xmlrpc.py`：出现在一条 coverage 的 evidence_ref 里
        （"lib/__init__.py、lib/ylinux_xmlrpc.py 全文"）——模型**声称**审过全文，
        而这个文件零 finding。这正是最该被追问的矛盾，却被当成了已处置。
      · `app/account/views.py`：只有一条候选驳回理由里提到它第 221 行，
        而该文件 255 行、真值里的问题在第 38 行。一句话否掉一条候选，
        不等于审过这个文件。
    "文本里出现过文件名"与"这个文件被处置过"是两回事，前者太廉价，
    不能拿来关掉一次追问。判据收紧后代价是：模型确实写进 note 的文件
    可能被再问一次——**问一次的成本，远低于漏一次。**
    """

    # ------------------------------------------------------------ finding 证据坐标
    #
    # ★ 一条 finding 的证据文本里写下的坐标，也是"已处置"。
    # 实测：real-final / real-full 都把同一个存储型 XSS 记成了
    # `app/ydata/models.py:258` 一条（F-002），而证据里明明写着
    # "ydata/forms.py:46 / models.py:258-260 / wiki/utils.py:18" 这条完整数据流。
    # 只比 finding 的 location 字段，就会让同一根链条上的另外三个坐标各被
    # 追问一次——四次追问，一次结论。补上这一步之后，对账问的是
    # 「**这条链之外**还有没有别的东西」，而不是「这条链你还记得吗」。

    @staticmethod
    def _finding_refs(f, scope) -> list[tuple[str, int, int]]:
        ev = getattr(f, "evidence", None)
        if ev is None:
            return []
        blob = " ".join(str(x) for x in (
            getattr(f, "title", ""), ev.snippet, ev.sink, ev.source,
            ev.reachability, ev.sanitizer_check,
            *ev.attack_path, *ev.dataflow, *ev.mitigations_found,
        ) if x)
        return [(r["file"], r["line"], r["end_line"])
                for r in extract(blob, scope, require_hazard=False)]

    def __init__(self, ledger) -> None:
        self.lines: list[tuple[str, int, int]] = []
        # ★ `files` 只放**有 finding 的**文件。候选不算。
        # 曾经把候选文件也并进来，结果 real-final 里 `app/account/views.py`
        # （255 行、10 个对外入口、真值 V11 所在）因为第 221 行有一条引擎候选
        # 被整个文件排除在回访之外——而那条候选讲的是 `'True'` 是不是硬编码口令，
        # 与第 38 行的开放重定向毫无关系。
        # **一条候选被处置，只说明那一行被看过，不说明这个文件被审过。**
        self.files: set[str] = set()

        scope = ledger.scope
        # 证据文本点名过的文件。B 类回访要拿它做排除：证据里出现了这个文件的
        # 某个坐标，就说明它已经被写进一条结论，不再是"读过却没结论"。
        self.named: set[str] = set()

        # 文件 → 覆盖它的 finding id。用于**自动回收过时线索**时写明理由：
        # "该文件随后已记录 finding（F-006）"比"已覆盖"可核对得多。
        self.by_file: dict[str, list[str]] = {}

        for f in ledger.findings.values():
            loc = f.location or {}
            rel = loc.get("file", "")
            ln = int(loc.get("line") or 0)
            self.lines.append((rel, ln, int(loc.get("end_line") or ln)))
            self.files.add(rel)
            self.by_file.setdefault(rel, []).append(f.id)
            for ref in self._finding_refs(f, scope):
                self.lines.append(ref)
                self.named.add(ref[0])
                # ★ 证据文本里的坐标也要记下**是哪条 finding 写的**，
                # 否则回收理由只能退化成"（见账本）"。实测 real-fix 回放：
                # `app/ydata/urls.py:9` 被回收，理由里没有 finding id——
                # 核对它的人得自己翻遍 9 条 finding 才能确认 F-007 的证据
                # 里确实写着 `urls.py:9 ^attachment/(?P<id>\d+)/download`。
                # "可独立核对"是回收机制对模型的承诺，理由本身就要经得起核。
                self.by_file.setdefault(ref[0], []).append(f.id)

        for c in ledger.candidates.values():
            # ★ 必须排除**对账线索自己**。曾经把全部候选都并进来，于是
            # `covers()` 对一条 mention 线索**自己**返回 True——线索的坐标
            # 就写在 `lines` 里。后果：第 4 轮提出的线索，第 5 轮扫描时被
            # `_reap_stale` 立刻回收，理由写着"该位置随后已被 finding 覆盖
            # （见账本）"，而账本里一条 finding 都没有（`by_file` 为空，
            # 所以只能退化成"见账本"）。**机制上线即自我否定，给出的理由
            # 还完全合理**——只有把"线索提出后到底还在不在"钉成断言才看得见。
            #
            # 语义上这条排除是对的：`covers()` 回答的是"**这里已经有结论了吗**"，
            # 而对账线索是**问题**，不是结论。引擎候选要留——它们自有
            # dispose 通道，处置过就是处置过。
            if c.source == "recall":
                continue
            self.lines.append((c.file, c.line, c.line))

    def covers(self, ref: dict, tol: int | None = None) -> bool:
        """`tol` 默认用 `LOC_TOL`（判定"要不要再问一次"）。

        ★ 调用方**可以收紧**它，而且 `_reap_stale` 必须收紧：同容差在
        两个方向上代价不同。"要不要再问一次"放宽 → 少问一次，成本是
        **可能漏问**；"要不要自动关掉一条线索"放宽 → 系统替模型做了决定，
        成本是**线索静默消失**。后者要求证得更死，所以回收走 `REAP_TOL`。
        """
        t = LOC_TOL if tol is None else tol
        rel, ln = ref["file"], ref["line"]
        end = ref.get("end_line", ln)
        for (f, a, b) in self.lines:
            if f != rel:
                continue
            if a - t <= ln <= b + t or a - t <= end <= b + t:
                return True
        if rel in self.files and ln <= 0:
            return True
        return False


# ---------------------------------------------------------------- 扫描器

class RecallScanner:
    """按轮累积推理文本，产出"提过但没落账"的候选条目。

    实例挂在 `Ledger` 上，跨轮存活——因为"提过"这件事发生在过去，
    而处置发生在未来；扫描器要同时看得见两头。
    """

    def __init__(self, scope, max_mention: int = 4, max_file: int = 2,
                 max_total: int = 6, max_mention_total: int = 6,
                 max_file_total: int = 6) -> None:
        self.scope = scope
        self.max_mention = max_mention
        self.max_file = max_file
        self.max_total = max_total
        # ★ 整场运行的总配额。上面三个是"每次对账"的上限，管不住总量：
        # 实测 real-recall 每轮提 2–4 条、从第 20 轮提到第 39 轮，累计 46 条，
        # 模型最后一轮要挤 58 次 dispose——它一条也没做完。
        # 线索的价值在于**被逐条看过**；提出来却没人看，比不提更糟：
        # 它让报告多出一段"未复核"的清单，读者还得自己判断哪些重要。
        self.max_mention_total = max_mention_total
        self.max_file_total = max_file_total
        # 本次运行**累计**产出过多少条，只用于 `stats` 上报。
        # ★ 它们**不是配额**——配额走 `_open_quota()`，语义完全不同。
        # 这两个数曾经是配额判据（`room = max_total - self._n_mention`），
        # 于是"提过"就永久占一格，哪怕那条线索后来被自动回收、模型连看
        # 都没看过。见 `_open_quota()` 的注释：那正是 V10 被挡在门外的原因。
        self._n_mention = 0
        self._n_file = 0
        # 每个文件的入口点数量。★ 它是 B 类排序的主信号：一个**对外暴露
        # 入口**的文件却零 finding，比一个同样读完的工具模块可疑得多。
        # 实测 real-final 里就是这个信号把 `lib/ylinux_xmlrpc.py`（12 个
        # XML-RPC 方法注册）和 `app/account/views.py` 顶进名额的——
        # 而这两个文件正是 V9/V10/V11 三条漏报的所在，它们各自在报告里
        # 一行记录都没有。
        self._entries: dict[str, int] = {}
        for ep in getattr(scope, "entry_points", []) or []:
            owner = _entry_owner(ep, scope)
            if owner:
                self._entries[owner] = self._entries.get(owner, 0) + 1
        self._scanned = 0                  # 已消化的 events 下标
        self._mentions: list[dict] = []    # 全部提及（含 turn）
        self._file_mentions: dict[str, dict] = {}   # rel -> 最早一条危险提及
        self._emitted: set[str] = set()    # 已生成过候选的位置键

    # -------------------------------------------------- 累积

    def ingest(self, events: list[dict]) -> None:
        """消化新事件。只扫 thinking / assistant_text——工具结果是模型的观察，
        不是它的判断，把观察也当"提过"会淹没在文件名列表里。"""
        for ev in events[self._scanned:]:
            kind = ev.get("kind")
            if kind not in ("thinking", "assistant_text"):
                continue
            turn = int(ev.get("turn") or 0)
            text = ev.get("text", "")
            for ref in extract(text, self.scope):
                ref["turn"] = turn
                self._mentions.append(ref)
            for fm in extract_files(text, self.scope):
                fm["turn"] = turn
                self._file_mentions.setdefault(fm["file"], fm)
        self._scanned = len(events)

    # -------------------------------------------------- 对账

    @staticmethod
    def _open_quota(ledger, rule: str) -> int:
        """**当前**还未处置的该类线索条数——配额管的是"模型同时要面对几条"。

        ★ 这里原本是只增不减的计数器 `_n_mention` / `_n_file`，它把两种
        完全不同的情况算成了同一件事：

          · 模型**已经表态过**的——处置过就是处置过，那条线索的使命完成了
          · 位置随后**自行落账**、被 `_reap_stale` 自动回收的——模型连看
            都不必看

        后者在真实运行里占 70~90%（`_tune_recall.py` 实测：模型 20 轮后
        仍在继续工作，会陆续补上 finding，所以"提名 → 随后自己记了"是常态）。
        配额就这样被"最终会自动消失"的位置吃光了。

        real-reap 的第 37 轮（倒数第 3 轮）撞上的正是这样一堵墙：模型在
        推理里提到了 `lib/ylinux_xmlrpc.py:120`——V10 的 basename 净化点，
        落在真值窗口 105±25 内——而 A 类 6 条配额**已在第 32 轮用完**。
        用掉的那 6 条里 **5 条随后被自动回收**，模型一条都没真正处理。
        真值 V10 因此成为三条漏报里唯一仍未落账的。
        回放证明判据**看得见** 120 行（`extract()` 抽得到）——是配额耗尽，
        不是盲区。离线扫描（`tests/_tune_recall.py`）给出的结论很干净：
        累计语义下要捞到 V10 得把配额提到 12；同一批账本上换成"同时待处置
        量"，**冷静期 3 + 配额 6（即当前默认值）就捞到了**。

        改成从账本现读，还顺手消掉了一类缺陷：**"忘记退还"**。计数器需要
        在每一条处置/回收路径上都记得减一，漏一处就永久少一格，而这种漏
        不会报错、只会让机制慢慢变哑（`_emitted` 自己就出过"只写不读"的
        事）。"现在有几条未处置"是账本的当前状态，问一次得一次，没有状态
        可以不同步。
        """
        return sum(1 for c in ledger.candidates.values()
                   if getattr(c, "source", "") == "recall"
                   and getattr(c, "rule", "") == rule and c.is_open)

    def scan(self, ledger, turn: int, coverage_of_file) -> list[dict]:
        """产出本轮应当提出对账的条目（已去重）。**不修改账本**，
        由调用方把它们变成候选——扫描器不持有账本，是刻意的：
        否则测试就得先造一本账。"""
        self.ingest(ledger.events)
        acc = Accounted(ledger)
        out: list[dict] = []

        # ---- A 提及对账
        # 同一位置可能在多轮里被反复提到，合并成一条并记下次数：
        # "说过 4 遍" 与 "说过 1 遍" 是两种不同的信号，前者更该被追问。
        merged: dict[str, dict] = {}
        for ref in self._mentions:
            if turn - ref["turn"] < MENTION_GRACE_TURNS:
                continue                   # 冷静期内，先让它自己落账
            key = f"M|{ref['file']}|{ref['line']}"
            if key in self._emitted:
                continue
            if acc.covers(ref):
                self._emitted.add(key)     # 已经记了，不必再问
                continue
            hit = merged.get(key)
            if hit is None:
                merged[key] = {**ref, "n": 1, "turns": [ref["turn"]]}
            else:
                hit["n"] += 1
                hit["turns"].append(ref["turn"])
                hit["turn"] = max(hit["turn"], ref["turn"])

        cand = sorted(merged.values(),
                      key=lambda r: (-r["n"], -r["turn"]))
        # 配额：模型**同时**最多面对这么多条未处置的 A 类线索。处置掉
        # 一条、或系统回收掉一条过时的，配额立刻释放给下一个位置——
        # 见 `_open_quota()`。剩下的位置若最终没进过提名，由报告层如实
        # 列为"未复核"，而不是继续压在模型头上。
        room = self.max_mention_total - self._open_quota(ledger, "mention")
        for r in cand[:max(0, min(self.max_mention, room))]:
            self._emitted.add(f"M|{r['file']}|{r['line']}")
            self._n_mention += 1
            seen_at = (f"第 {r['turn']} 轮" if r["n"] == 1
                       else f"第 {r['turns'][0]}–{r['turns'][-1]} 轮共 {r['n']} 次")
            out.append({**r, "kind": "mention",
                        "why": f"{seen_at}的推理里提到过这里（「{r['hazard']}」），"
                               f"账本里没有对应记录"})

        # ---- B 文件回访
        # ★ 它必须与 A 并存，不能被 A 挤掉：实测 real-final 里
        # `lib/ylinux_xmlrpc.py` 的越权讨论**没有任何行号**（那段推理正好
        # 在 2000 字处被截断），A 类一条都抽不到，能兜住它的只有 B。
        already = {r["file"] for r in out}      # A 已点名的文件，别再用文件级重复问一遍
        filecand: list[dict] = []
        for rel, spans in ledger.reviewed.items():
            # ★ `F|{rel}` 是"这个文件已经回访过"的标记，必须在这里就跳过。
            # 曾经只有**被选中的**才写进 `_emitted`，而筛选时从不读它——
            # 于是同一个文件每轮都被重新提名。实测 real-recall：
            # `app/admin/views.py` 被提名 **18 次**、`app/wiki/views.py` 17 次，
            # 6 个文件变成 40 条线索，占满 46 条中的 40 条。
            # 模型在第 39 轮的推理里自己认出了这件事："mostly duplicates"。
            # 一条线索只该问一次；问过一次就是账本上一条待处置的记录，
            # 再问一遍不会让它更真，只会把预算烧在重复上。
            if f"F|{rel}" in self._emitted:
                continue
            if rel in acc.files or rel in acc.named or rel in already:
                continue
            fi = self.scope.get(rel)
            if fi is None or fi.attribution == "vendored" or fi.trivial:
                continue
            ratio = coverage_of_file(rel)
            # "读过"是一个门槛，不参与排序：读九成与读满，区别远小于
            # 这两个文件之间的差别。只翻过几行的不算读过——但关键路径上的
            # 门槛放松，因为那里的每一行都值钱。
            if ratio < (0.3 if fi.in_critical_path else 0.8):
                continue
            if fi.lines < 25:
                continue                   # 太短的文件藏不下漏报，只增加噪音
            haz = self._file_mentions.get(rel)
            n_ep = self._entries.get(rel, 0)
            filecand.append({
                "file": rel, "line": 1, "end_line": min(fi.lines, 1),
                "kind": "file", "ratio": ratio, "lines": fi.lines,
                "crit": fi.in_critical_path, "hazard": haz, "entries": n_ep,
                "why": (f"读过 {ratio:.0%}（{fi.lines} 行）"
                        + (f"、对外入口 {n_ep} 个" if n_ep else "")
                        + "，账本里既无问题记录、也无覆盖说明"
                        + (f"；且第 {haz['turn']} 轮的推理里说过它可疑"
                           f"（「{haz['hazard']}」）：「{haz['seg'][:160]}」"
                           if haz else "")),
            })
        # 危险提及 → 入口点越多 → 文件越大。刻意**不**按"读得多全"排：
        # 那个维度会让 100% 读过的小工具模块挤掉 95% 读过的大接口文件，
        # 而后者才是漏报真正藏身的地方。
        filecand.sort(key=lambda r: (not bool(r["hazard"]), not r["entries"],
                                     not r["crit"], -r["lines"]))
        room_f = self.max_file_total - self._open_quota(ledger, "file")
        for r in filecand[:max(0, min(self.max_file, room_f))]:
            self._emitted.add(f"F|{r['file']}")
            self._n_file += 1
            out.append(r)
        return out[:self.max_total]

    @property
    def stats(self) -> dict:
        """上报用。`emitted_*` 是**累计**产出条数，读它时别把它当配额——
        配额是"同时未处置几条"（`_open_quota`），两者不是一回事。
        `emitted` 也不是提名数：它还包含被 `covers()` 判定为"已经记了、
        不必再问"的位置。"""
        return {
            "mentions": len(self._mentions),
            "files_mentioned": len(self._file_mentions),
            "emitted": len(self._emitted),
            "emitted_mention": self._n_mention,
            "emitted_file": self._n_file,
            "quota_mention": self.max_mention_total,
            "quota_file": self.max_file_total,
        }
