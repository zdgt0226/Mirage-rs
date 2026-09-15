# SPEC — install.sh UI/排版/颜色/选项说明 微调优化

状态: **待批准** (human 批准本文件后才动实现代码)
Tier: **2** (行为保持的表现层改动; 唯一半功能改动 = 颜色自动关闭逻辑)
分支隔离: `chore/install-sh-ui-polish` (纯 bash, 无需 build; 不改动 user 工作树的 main)

---

## 0. 范围裁决 (基于 2 个澄清问答, 含一处冲突的解决)

- Q1「范围」= 全面重排措辞 + 调色 + 重设计标题/摘要框 + 全流程排版走查。
- Q2「颜色」= 加自动关色 (NO_COLOR / 非 tty), **配色方案不变**。
- **冲突解决**: Q1 的"重设配色" 与 Q2 的"配色方案不变" 矛盾 → 取更具体的 Q2:
  **ANSI 颜色值 (36/32/33/31/1;35) 保持不变**, 只加"何时上色"的门控。
  "全面重排" 落在 **措辞** 与 **排版/框样式**, 不动颜色值。
  ⚠️ 若你其实想换配色值, 现在说, 我改 SPEC 再批。

---

## 1. 可验证行为 (testable — 会写测试 + 过 gauntlet)

### B1. `_c` 颜色自动关闭 (tty / NO_COLOR 感知)
现状: `_c()` 恒发 ANSI, 输出被管道/重定向或设了 `NO_COLOR` 时日志里是 `\033[..m` 乱码。
改为: 启动时一次性判定 `USE_COLOR` = (stderr 是 tty) AND (环境变量 `NO_COLOR` 未设);
`_c` 在 `USE_COLOR=0` 时**只回原文, 不加任何转义**。

- B1.1 `USE_COLOR=1` 时 `_c 32 "hi"` == `$'\033[32mhi\033[0m'`
- B1.2 `USE_COLOR=0` 时 `_c 32 "hi"` == `hi` (无任何 `\033` 字节)
- B1.3 `NO_COLOR` 已设 (任意值, 含空串) → `USE_COLOR=0` (遵循 no-color.org: 存在即生效)
- B1.4 stderr 非 tty (被管道/文件) 且 `NO_COLOR` 未设 → `USE_COLOR=0`
- B1.5 配色值不变: `USE_COLOR=1` 下 info/ok/warn/err 仍分别用 36/32/33/31, title 用 `1;35`

### B2. `ask_choice` 默认项可见标记
现状: 提示写 "(默认 1)" 但选项列表里第 1 项无标记, 眼睛要来回对。
改为: 默认项 (第 1 项) 行尾追加标记 ` (默认)`。

- B2.1 `ask_choice "t" A B C` 的第 1 行选项渲染含 `1) A (默认)`
- B2.2 非默认项不带该标记 (`2) B` 无 `(默认)`)
- B2.3 选择逻辑 (读入/校验/返回序号) **完全不变** —— 仅列表渲染变

### B3. helper 可被 source 单测 (enabler)
现状: 文件末尾裸 `main "$@"`, 一旦 `source install.sh` 就会跑安装+交互, 无法单测函数。
改为: `[[ "${BASH_SOURCE[0]}" == "${0}" ]] && main "$@"`
—— 直接执行 (`bash install.sh`) 行为**逐字不变**; 被 source 时不自动跑 main, 供测试调函数。

- B3.1 `source install.sh` 不触发 main (无交互、无副作用), 且能调用 `_c`/`info`/`ask_choice` 等
- B3.2 直接执行路径不受影响 (通过 B3.1 的 source-guard 语义保证; 直接跑仍进 main)

### B4. `info/ok/warn/err/title` 输出格式契约 (回归护甲)
把当前输出格式钉成测试, 保证后续排版重排不悄悄改坏 tag/结构:
- B4.1 `info X` → `[*] X`, `ok X` → `[✓] X`, `warn X` → `[!] X` (color 门控见 B1)
- B4.2 `err X` 打印 `[✗] X` 且 `exit 1` (在 subshell 里断言退出码=1)
- B4.3 `title X` 输出含两条 `═` 分隔线 + 居中标题行 (行数/结构断言)

---

## 2. 主观改动 (human 眼判 — 无断言, 靠你审 diff; EVIDENCE 标注为 human-judged)

### S1. 选项说明措辞逐条走查 (只碰读着别扭/不一致的)
覆盖菜单: 主操作菜单、部署形态 (heredoc)、部署模式、路由分流策略、日志等级、
GUI 监听范围、上游类型/SS 加密方式、节点参数获取方式。
原则: 术语与 config 模板/README 一致; 中英括注风格统一; 不改选项的语义/顺序/序号。

### S2. 标题框 + 摘要排版重设计
- `title()` 框样式统一 (宽度/字符), 让 `title` 与手写的 部署形态 heredoc **同一套视觉**。
- `show_server_node` 与最终"安装完成"摘要的标签对齐 (中文宽度对齐用固定列而非手数空格)。
- 全流程缩进层级一致 (顶层 tag 行 vs 4 空格提示体 vs 6 空格明细行的层级规范化)。

---

## 3. 不变量 (negative constraints — 必须存活, 每条在 EVIDENCE 有对应验证或跳过说明)

- **INV1 安装逻辑零改动**: 所有实际动作 —— apt/包管理、`curl`/下载、`systemctl`/服务注册、
  文件/配置生成 (config json)、sysctl、eBPF、FHS 路径、卸载 —— 命令与产物**逐字不变**。
  本次只动: 颜色发射、消息措辞、菜单/框排版、source-guard。
  验证: diff 范围审查 (改动仅落在 UI helper + 消息字符串 + 末行 guard; 非 UI 函数体不变)。
- **INV2 配色值不变** (见 B1.5)。
- **INV3** 脚本仍在 `set -euo pipefail` 下无新增告警; 不给脚本本身引入新硬依赖
  (自动关色只用 `[ -t 2 ]` + `${NO_COLOR+x}`, 全是 bash 内建)。
- **INV4** 交互契约不变: 各 `ask*` 的返回值格式、默认值、序号语义不变 (B2.3 覆盖 ask_choice;
  其余 ask* 不改逻辑只可能改 prompt 文案)。

---

## 4. Setup plan (批准即授权以下环境改动)

- **新增依赖 (工具, 非脚本运行时)**: `shellcheck` (apt) —— 唯一 lint 层, 当前缺失。
  一行理由: bash lint 无替代品; 若你否决, 回落 `bash -n` 语法检查 + 记录 lint 置信度下降。
  不装 `bats` (改用零依赖纯 bash 测试脚本, 遵循"优先 stdlib/已有")。
- **新增文件 (按路径)**:
  - `tests/install_ui_test.sh` — 纯 bash 测试护甲 (可执行, 失败退非零), source install.sh 断言 B1-B4。
  - `tests/mutate_install_ui.sh` — 手工变异脚本 (对 B1 门控 + B2 标记植入已知 bug, 断言测试杀掉; 自动 restore)。
  - `SPEC-install-ui.md` (本文件) + `EVIDENCE-install-ui.md` (完工报告)。
- **改动文件**: `install.sh` (UI helper + 消息 + source-guard) · `CHANGELOG.md` ([Unreleased] 条目)。
- **git**: 已是 repo。分支 `chore/install-sh-ui-polish`; SPEC 批准即 commit; 每个 GREEN/REFACTOR checkpoint commit (mutant restore 用 `git diff` 可核)。

---

## 5. Gauntlet (适用层; 按 Tier 2 + 表现层裁剪, 不静默跳层)

| 层 | 是否适用 | 说明 |
|---|---|---|
| 语法 `bash -n install.sh` | ✅ | 零错误 |
| Lint `shellcheck` | ✅ | 改动区零新增告警 (基线: 先记录 install.sh 现有告警数, 守零新增) |
| 单元测试 `tests/install_ui_test.sh` | ✅ | B1-B4 全过 |
| 变异 `tests/mutate_install_ui.sh` | ✅ | B1 门控/B2 标记植入 bug 必被杀; 自动 restore, 用 git diff 核净 |
| 负向控制 | ✅ | 测试脚本先跑一次"未改的 install.sh"证 B1.2/B2.1 会红 (证测试非空转) |
| 覆盖率 | ⚠️ 简化 | 无 bash 覆盖工具; 以"每个改动 helper 有对应断言"人工核代替, EVIDENCE 说明 |
| 真执行 | ✅ 受限 | source + 调 helper/菜单渲染捕获输出 (dry render); **不跑真实安装** (改系统, 不安全) → 记为受限 |
| 属性测试 | ⚠️ 轻 | B1 往返性: `USE_COLOR=1` 输出剥掉 ANSI == `USE_COLOR=0` 输出 (一个不变式) |
| 供应链/密钥 | ✅ | 依赖集变了 (加 shellcheck 工具, 非脚本运行时): 记录; diff 扫无密钥 |
| 套件健康 | N/A | 测试确定性 (纯字符串断言, 无并发/随机) |
| 复杂度 | ✅ | 新增函数小、单一职责 |

**主观项 (S1/S2) 不进 gauntlet** —— 无机器可判断言; EVIDENCE 明确列为 human-judged, 附 diff 供你审。

---

## 6. 独立验证 (Tier 3 选项)
不启用 (本任务 Tier 2, 表现层)。

---

## 批准
需要你一句明确批准 (针对**本 SPEC**, 不是之前的问答)。可一并确认:
(a) 配色值不变 (§0 冲突解决) 对不对; (b) 允许 apt 装 shellcheck; (c) 分支/新增文件路径 OK。
