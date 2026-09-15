# EVIDENCE — install.sh UI/排版/颜色/选项 微调优化

结论: **PASS** (可验证部分). 主观部分 (S1/S2) 为 human-judged, 附 diff 供审。
Tier: 2. 独立验证: 不启用 (表现层)。
SPEC: [SPEC-install-ui.md](SPEC-install-ui.md) (提交 95cbc2d 批准: "批准，配色值不变，装 shellcheck，路径都 OK，进 RED")。

## 来源状态 (可复现)
- 分支 `chore/install-sh-ui-polish`; install.sh 内容定于 632a55c (最后一次代码编辑)。
- 工具版本: bash 5.2.15 · shellcheck 0.9.0 · script (util-linux 2.38.1) · python3 (变异字面替换)。
- **一键复现**: `bash tests/gauntlet_install_ui.sh` (跑 L1-L6; 数字与下表一致)。
- 隔离: git 分支 (非 worktree; 纯 bash 无需 build, landing tree = 分支本身, 无 ignored 内容差异)。

## SPEC 行为 → 验证映射 (可测)

| 行为 | 验证 | 结果 |
|---|---|---|
| B1 `_c` tty/NO_COLOR 自动关色, 配色值不变 | tests/install_ui_test.sh B1.1/1.2/1.2b/1.3/1.3b/1.4/1.5a-d/1.6 | 全过 |
| B1.3/1.6 NO_COLOR 隔离 (需 -t2 真) | script 分配 pty, NO_COLOR 成唯一变量 | 过 (pty 下: 无 NO_COLOR→1, 有→0) |
| B2 `_render_choice` 默认项标 (默认), 读循环不变 | B2.1/2.2/2.3a | 全过 |
| B3 source-guard (source 不跑 main) | B3.ctrl/3.1/3.2/3.3 (中和 main 副本 + 真 install.sh source) | 全过 |
| B4 info/ok/warn/err/title 格式契约 | B4.1a-c/4.2/4.2b/4.3/4.3b | 全过 |

## Gauntlet (最终一次性运行, 来源状态 632a55c)

| 层 | 命令 | 结果 |
|---|---|---|
| L1 语法 | `bash -n install.sh` (+2 测试文件) | 3/3 OK |
| L2 lint | `shellcheck -f gcc <file>` | install.sh **49** (基线 49, **零新增**); ui_test **0**; mutate **0**; gauntlet **0** |
| L3 单元 | `bash tests/install_ui_test.sh` | **PASS=25 FAIL=0** |
| L4 变异 | `bash tests/mutate_install_ui.sh` | **5/5 KILLED** (M1-M5); fail-closed + git restore 核净 |
| L5 属性 | strip-ANSI(USE_COLOR=1 输出) == USE_COLOR=0 输出 | PASS |
| L6 真渲染 | pty 下 source + 调 info/ok/warn/err/title/_render_choice | 输出正确 (色/tag/统一框/默认标记/[✗]) |
| 复杂度 | 新函数 `_init_color`/`_render_choice` 小且单一职责 | OK |
| 供应链 | 新增**工具** shellcheck (非脚本运行时依赖); 脚本本身零新硬依赖 (色检测只用 `[ -t 2 ]`+`${NO_COLOR+x}` 内建); diff 无密钥 | OK |

### L2 基线说明
install.sh 预存 49 个 shellcheck findings (38×SC2155 等), **不在本次范围** (改它们=scope creep)。
守恒: 改后仍 49 (我 `_render_choice` 一度引入 1 个 SC2318, 已拆两个 local 修回)。

### L4 变异明细 (证 suite 非空转)
- M1 `_c` 恒上色 (忽略 USE_COLOR) → B1.2 杀
- M2 `_init_color` 忽略 NO_COLOR → B1.3 杀 (pty 隔离才可杀)
- M3 `_render_choice` 丢默认标记 → B2.1 杀
- M4 `_render_choice` 全项标默认 → B2.2 杀
- M5 `_c` 恒纯文本 → B1.1 杀
- fail-closed: 目标串未匹配/存活/restore 失败均硬退非零 (负向控制: 变异未改文件即报错)。
- **不变异 source-guard**: 那会让 source 跑真 main (危险); guard 由 B3 的中和副本控制验证 (B3.ctrl 证"无 guard→main 跑"可红)。

## 不变量核查

| 不变量 | 验证 | 结果 |
|---|---|---|
| INV1 安装逻辑零改动 | `git diff main...HEAD -- install.sh` 7 处 hunk 全落在 UI helper/消息/菜单/guard; fetch_release_binary/setup_service/setup_fhs/update_binary/uninstall/config_* 等函数体未动 | ✅ 逐字不变 |
| INV2 配色值不变 | B1.5a-d 断言 info=36/ok=32/warn=33/title=1;35 | ✅ |
| INV3 无新脚本硬依赖 + 无 lint 新增 | 色检测纯 bash 内建; L2 install.sh 49 零新增 | ✅ |
| INV4 交互契约不变 | B2.3 (ask_choice 读循环逻辑不变); 其余 ask* 只改文案不改逻辑 (diff 核) | ✅ |

## 主观改动 (S1/S2, human-judged — 无机器断言, 请审 diff)

- **S2 排版**: `ask_upstream`、`部署形态` 两处手写 ═ 框 → 统一用 `title()` (与其余章节头同一视觉)。
- **S1 措辞**: 主操作菜单选项风格统一 (去混杂英文括注); routing 策略选项半角括号对齐
  (全角逗号=规范中文, 保留)。范围按 SPEC S1 = "只碰读着别扭/不一致的", 非逐字重写。
- 审阅: `git diff main...HEAD -- install.sh`。若要更深的逐菜单重写, 说哪几个我继续。

## 跳过的层 (含理由)
- 覆盖率: 无 bash 覆盖工具; 以"每个改动 helper 有对应断言 + 变异存活=0"人工替代 (见 L3/L4)。
- 套件健康 (随机序): 纯字符串断言, 无并发/随机/顺序依赖, N/A。
- 真实安装执行: 会改系统 (apt/systemctl/FHS), 不安全; 以 pty dry-render (L6) 替代, 记为受限。

## 过程中修正 (诚实记录)
- `_render_choice` 初版沿用原 `local a=(...) n=${#a}` 一行式 → 引入 1 个新 SC2318 → 拆两个 local 修回零新增。
- B1.3/B1.3b 初版在非 tty 下空转 (USE_COLOR 恒 0, 测不出 NO_COLOR 真伪) → 改用 `script` pty 隔离, 并补 B1.6 正向。
- B1.6 初版用 `env -u NO_COLOR pty_color` (env 不能调 shell 函数) → 改子 shell `unset`。
