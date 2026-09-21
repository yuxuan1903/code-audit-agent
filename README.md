# AI 代码审计 Agent（第一代原型）

对一个**真实**的 Python 2 / Django 1.x 网站代码库做静态安全审计：静态引擎铺面 → LLM Agent 做数据流推理 → 独立对抗验证再复核一遍。**全程不执行被审代码。**

本目录是第一代原型。同项目的第二代（`agent/`，Codex 构建）不属于本次交付。

---

## ⚠️ 先读这一段：这份原型的能力边界

**它从不给出「确认存在漏洞」（`CONFIRMED`）的结论。** 两次真实运行的裁定只落在两档：

| 裁定 | 设计含义 | 本次运行的实际来源 |
|---|---|---|
| `NEEDS_HUMAN` | 代码之外的事实决定结论（部署配置、网关是否鉴权），静态无法判定 | ⚠️ **5 条全部来自「验证者未提交结论」的兜底**——不是验证者的判断。三条 HIGH/CRITICAL 的强制对抗验证**一次都没跑完**（8 轮上限用满，`engine/agent/verify.py:235-239`） |
| `UNVERIFIED` | 未经独立对抗验证 | 与设计含义一致 |

所以两档**都不是「已验证」**。特别地：这次运行里**没有任何一条 finding 经过完整的对抗验证**。报告的摘要句「是验证者把判断退回给了人」在本轮**不成立**——那个误标的机理、影响与不修的理由见 `docs/03-问题与取舍.md` 第 7 条。

交付前对 11 条 finding 逐条回靶子源码核对过锚点与关键前提（**未发现行号偏移**，8 条的关键前提核实成立），逐条结论见 `results/人工分析报告.md`。

用本仓库自带的评分器复跑 `results/` 里那两次真实运行（命令见下）：

| 运行 | 召回 | 误报 | 归因 | 边界声明 |
|---|---|---|---|---|
| `results/fix-d`（**当前代码**的运行） | 2/5 = 40% | 1 项 | 2/2 | 2/2 |
| `results/ctl-b`（旧版代码的运行，**不可与上行对照**） | 3/5 = 60% | 0 项 | 2/2 | 2/2 |

召回率的分母是**人工写的真值清单**（`tests/ground_truth/ylinux.json`），衡量的是「与本项目既有认知的一致程度」，不是绝对真理。

**而且这四个数字都被评分器的缺陷改变过，方向相反**：`fix-d` 的召回被**低估**（V11 被漏计，真实不低于 60%），它的「误报 1 项」被**高估**（S4 是行区间重叠的产物，实际为 0）。两个缺陷都未被修改——由被评者在交付前改高自己的评分是最不该做的动作。机理、证据与不修的理由见 `docs/02-准确性如何验证.md` 第四节。

把这份工具的输出当决策依据之前，请先读 `docs/03-问题与取舍.md`。

---

## 仓库结构

```
.
├── audit.py                     命令行入口
├── engine/                      引擎（本目录逐字节未改动，指纹见下）
│   ├── collect.py               范围契约：入口点、归因、fork 检测
│   ├── engines/                 静态引擎：semgrep / bandit / secret
│   ├── agent/                   Agent 循环：loop / tools / registry / ledger / recall / verify / prompts
│   ├── providers/               LLM 后端：mock / anthropic_compat / openai_compat
│   ├── redact.py                凭据脱敏（运行时闸门）
│   ├── report.py                报告渲染 + 门禁
│   └── schema.py                裁定、覆盖类、归因三套词表
├── tests/                       探针、断言测试、评分器、真值基准
│   ├── score.py                 准确性评分（召回 / 误报 / 归因 / 元信息四维）
│   ├── ground_truth/ylinux.json 人工真值：8 条必须报出 + 6 条必须不报
│   └── _target.py               被审仓库定位（见 `docs/03` 第 2 条）
├── results/                     Agent 的实际运行结果 + 人工分析报告
│   ├── fix-d/ ctl-b/            脱敏后的 audit-report.md + .json
│   ├── 人工分析报告.md           逐条核对 11 条 finding（先读这份）
│   └── README.md                两次运行的出处、脱敏做了什么、没发布什么
├── docs/                        设计思路、准确性验证、问题与取舍、测试记录
├── .gitignore                   挡住运行账本与被审靶子（含理由）
├── .gitattributes               `* -text`：禁止 Git 改写行尾，见下
└── 来源-Claude.md               归属说明与时间戳依据（原样保留）
```

---

## 依赖

**Python**：3.14.5（开发与验证所用）。代码使用 `X | Y` 类型标注与 `from __future__ import annotations`，**需要 3.10+**。

**第三方 Python 包**：`parso`（解析被审的 Python 2 文件——靶子有 9/105 个文件过不了 Py3 的 `ast`）、`PyYAML`（配置文件）。

**外部命令行工具**（需在 `PATH` 上，`--engines-only` 时全都要）：

| 工具 | 用途 | 缺失时的行为 |
|---|---|---|
| `semgrep` | 多语言模式匹配 | 报「无可用引擎」，退出码 2 |
| `bandit` | Python 安全缺陷扫描 | 同上 |
| 内置 `secret` 引擎 | 凭据扫描 | 无需外部工具 |

安装：`pip install parso pyyaml` + 自行安装 `semgrep`、`bandit`。

---

## 运行

### 1. 准备被审仓库

靶子是 YLinus.org 社区站点（Python 2 / Django 1.x，105 个 `.py` / 11,791 行），以 `ylinux_old-master.zip` 分发：

- **大小**：607,455 字节
- **SHA-256**：`30d7e1d5fad98851a8e4cd23f114a78e2c06ecb9de493aa4cf3dcca8781c9364`

**它不随本仓库发布**，原因有三：它是第三方代码、不是本次作业的产出；它自带硬编码凭据；它也**不是**审计结论的一部分——本仓库发布的是「审计这个靶子得到的产物」。

放到下列任一位置即可（`tests/_target.py` 会从 `tests/` 逐级上溯查找）：

```
<克隆目录>/../审计对象/ylinux_old-master     # 推荐：与仓库同级
<克隆目录>/审计对象/ylinux_old-master
```

或显式指定：`export AUDIT_TARGET=/path/to/ylinux_old-master`。
**找不到靶子时脚本会明确退出（码 2）并打印用法，不会降级成空范围继续跑。**

### 2. 离线跑（不调用任何模型）

```bash
python -I audit.py ../审计对象/ylinux_old-master --engines-only --out ./out
```

只跑静态引擎，输出候选清单。不需要 API 密钥。

### 3. 接真实模型

后端通过环境变量配置，**密钥只走环境变量，不写进代码、配置文件或命令行参数**：

| 变量 | 作用 |
|---|---|
| `ANTHROPIC_BASE_URL` | API 基址（留空则按 `--provider auto` 推断：含 `anthropic` 走 Anthropic 兼容，含 `openai`/`deepseek`/`localhost` 走 OpenAI 兼容） |
| `ANTHROPIC_AUTH_TOKEN` 或 `ANTHROPIC_API_KEY` | 凭据 |
| `ANTHROPIC_MODEL` | 模型名 |

```bash
export ANTHROPIC_BASE_URL=...      # 任何 Anthropic 兼容端点
export ANTHROPIC_AUTH_TOKEN=...    # 不要写进文件
export ANTHROPIC_MODEL=...

python -I audit.py ../审计对象/ylinux_old-master --max-turns 50 --out ./out
```

可用的后端：`mock`（离线，脚本化响应，用于测试）、`anthropic_compat`、`openai_compat`。
加 `--gate` 让退出码反映门禁结果；加 `--exclude` 排除目录；`--provider/--model/--base-url` 可覆盖环境变量。

> **诚实说明**：`results/` 里那两次运行用的是 `deepseek-v4-flash`——模型名记在报告的 `build.config.model` 里，报告正文也印了。**没记的是 `--provider auto` 最终解析到哪个端点**（`config` 里存的是配置值 `auto`，`base_url` 也不在产物里），所以「同模型换了端点」这种变化看不出来。见 `docs/03-问题与取舍.md` 第 5 条。

### 4. 退出码

| 码 | 含义 |
|---|---|
| 0 | 审计完成且门禁通过（或未启用门禁） |
| 1 | 门禁未通过（存在达到阈值的**已验证**问题） |
| 2 | 审计本身失败（范围解析失败、无可用引擎等） |

门禁**只由经过对抗验证的 finding 触发**，静态引擎的原始命中不拦门——它们只是候选，未经判断。

---

## 复核准确性（自己跑一遍）

```bash
python -I tests/score.py results/fix-d      # 目录，或直接指向 audit-report.json
python -I tests/score.py results/fix-d --json
```

四个维度分开报（召回 / 误报 / 归因 / 元信息），**刻意不合成一个总分**——合成会把「模式匹配式的多报」和「保守的少报」掩盖成同一个数字。评分器读的就是 `results/` 里那份**已脱敏**的 JSON，所以你跑出来的数字应当与上表一致。

---

## 文档

| 文件 | 内容 |
|---|---|
| `docs/01-设计思路.md` | 为什么这样分层、九条设计决策各自解决什么问题 |
| `docs/02-准确性如何验证.md` | 真值基准怎么写的、四维评分、**评分器自身的已知缺陷** |
| `docs/03-问题与取舍.md` | 主要问题（含三个真实缺陷）、十二项取舍、没做到的事 |
| `docs/04-测试记录.md` | 交付副本内重跑的测试读数 |
| `results/人工分析报告.md` | 对人类读者逐条分析 Agent 的产出 |

---

## 已知边界

- **不执行被审代码**，所以发现不了运行期才构造的调用、依赖部署配置的行为、时序竞态。
- **动态派发无法完全解析**：`getattr`、Django 字符串视图引用、框架信号回调在调用图里不可见。
- **鉴权状态由静态推断**：装饰器与函数体检查之外，实际生效的鉴权还取决于网关与反向代理——这部分不在代码范围内，相关结论标注为 `NEEDS_HUMAN`。
- **9 个文件完全未被 `bandit` 分析**：它用 Py3 的 `ast`，无法解析被审仓库里的 Python 2 语法（实测它会读文件、数行数、记入 metrics，然后一条都不报）。这 9 个文件在报告里逐条列出。
- **脱敏不构成「保证无敏感数据」**：`engine/redact.py` 自己的注释就写着「它不保证扫全（没有任何正则能）」。发布到本仓库的 `results/` 是在它之上又加了三层过遮规则（见 `docs/03` 第 1 条），但这仍然是「把最常见的几类挡住」，不是证明。
- **仓库内行尾不统一**：50 个文件 LF、7 个 CRLF（`engine/providers/` 下 3 个 + `results/` 下 4 个），另有 1 个空文件。这是**刻意的**——`code_digest` 对文件字节计算，统一行尾会让克隆件算不出文档里写的那个哈希。`.gitattributes` 里的 `* -text` 就是为此存在，**不要**改它、也不要做全仓行尾归一化。机理见 `docs/03` 第 8 条。
