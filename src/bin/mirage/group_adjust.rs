//! 出站组随节点数自动调整与复选框交互控件模块
//!
//! 原则 2:
//! - 代理节点数 < 2 时不建组；
//! - 代理节点数 >= 2 时:
//!   - 若无组: 候选 auto(urltest, 默认勾选), select(selector, 默认勾选), fallback, load_balance
//!     对每个勾选组选择包含节点; 若同时建 auto 和 select，select 成员首项为 auto
//!     新建组插入到 outbounds 最前面 (select 优先于 auto)
//!     若 routing.default_outbound 显式指向单节点，询问是否改指新组
//!   - 若已有组: 列出现有各组，默认勾选包含全部其它节点的组，新节点加入所选组
//! - 交互控件:
//!   - TTY: 空格切换勾选、上下键移动、回车确认 (通过 libc termios 实现 raw mode, RAII 恢复)
//!   - 非 TTY: 退回行输入 (空格分隔的编号，回车为默认勾选)
//!   - 非交互 (stdin 非 tty 且 EOF 无输入): 保持现状不建组

use std::io::{BufRead, Write};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckboxItem {
    pub key: String,
    pub title: String,
    pub detail: String,
    pub checked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckboxState {
    pub title: String,
    pub items: Vec<CheckboxItem>,
    pub cursor: usize,
}

impl CheckboxState {
    pub fn new(title: String, items: Vec<CheckboxItem>) -> Self {
        Self {
            title,
            items,
            cursor: 0,
        }
    }

    pub fn move_up(&mut self) {
        if self.items.is_empty() {
            return;
        }
        if self.cursor == 0 {
            self.cursor = self.items.len() - 1;
        } else {
            self.cursor -= 1;
        }
    }

    pub fn move_down(&mut self) {
        if self.items.is_empty() {
            return;
        }
        if self.cursor + 1 >= self.items.len() {
            self.cursor = 0;
        } else {
            self.cursor += 1;
        }
    }

    pub fn toggle(&mut self) {
        if let Some(item) = self.items.get_mut(self.cursor) {
            item.checked = !item.checked;
        }
    }

    pub fn checked_keys(&self) -> Vec<String> {
        self.items
            .iter()
            .filter(|it| it.checked)
            .map(|it| it.key.clone())
            .collect()
    }

    /// 渲染为终端行 (供 TTY 模式绘制)
    pub fn render_tty_lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        lines.push(format!("? {} (空格切换勾选，上下键移动，回车确认):", self.title));
        for (i, item) in self.items.iter().enumerate() {
            let pointer = if i == self.cursor { ">" } else { " " };
            let mark = if item.checked { "[x]" } else { "[ ]" };
            let detail = if item.detail.is_empty() {
                String::new()
            } else {
                format!(" - {}", item.detail)
            };
            lines.push(format!("{pointer} {mark} {}{detail}", item.title));
        }
        lines
    }

    /// 渲染行输入提示 (供非 TTY 行输入模式使用)
    pub fn render_line_prompt(&self) -> Vec<String> {
        let mut lines = Vec::new();
        let default_indices: Vec<String> = self
            .items
            .iter()
            .enumerate()
            .filter(|(_, it)| it.checked)
            .map(|(i, _)| (i + 1).to_string())
            .collect();
        let default_str = if default_indices.is_empty() {
            "无".to_string()
        } else {
            default_indices.join(" ")
        };
        lines.push(format!(
            "{} (输入空格分隔的编号如 \"1 2\"，直接回车使用默认 [{default_str}]):",
            self.title
        ));
        for (i, item) in self.items.iter().enumerate() {
            let mark = if item.checked { "[*]" } else { "[ ]" };
            let detail = if item.detail.is_empty() {
                String::new()
            } else {
                format!(" - {}", item.detail)
            };
            lines.push(format!("  [{}] {} {}{detail}", i + 1, mark, item.title));
        }
        lines
    }

    /// 解析行输入 (空格分隔的编号、回车/空输入保留默认)
    pub fn apply_line_input(&mut self, input: &str) -> Result<(), String> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            // 空输入: 保持默认勾选
            return Ok(());
        }
        if trimmed.eq_ignore_ascii_case("all") {
            for it in &mut self.items {
                it.checked = true;
            }
            return Ok(());
        }
        if trimmed.eq_ignore_ascii_case("none") || trimmed == "0" {
            for it in &mut self.items {
                it.checked = false;
            }
            return Ok(());
        }

        let mut chosen_indices = Vec::new();
        for part in trimmed.split_whitespace() {
            let idx = part.parse::<usize>().map_err(|_| {
                format!("非法编号 `{part}`: 请输入数字编号或直接回车")
            })?;
            if idx == 0 || idx > self.items.len() {
                return Err(format!(
                    "编号 `{idx}` 越界 (有效编号范围: 1..={})",
                    self.items.len()
                ));
            }
            chosen_indices.push(idx - 1);
        }

        // 应用所选编号
        for (i, item) in self.items.iter_mut().enumerate() {
            item.checked = chosen_indices.contains(&i);
        }
        Ok(())
    }
}

#[cfg(unix)]
struct RawModeGuard {
    orig: libc::termios,
    fd: libc::c_int,
}

#[cfg(unix)]
impl RawModeGuard {
    fn enter(fd: libc::c_int) -> std::io::Result<Self> {
        unsafe {
            let mut orig = std::mem::zeroed();
            if libc::tcgetattr(fd, &mut orig) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            let mut raw = orig;
            // 关闭规范输入、回显和信号控制 (Ctrl-C 我们自行捕获以恢复终端)
            raw.c_lflag &= !(libc::ICANON | libc::ECHO | libc::ISIG);
            raw.c_cc[libc::VMIN] = 1;
            raw.c_cc[libc::VTIME] = 0;
            if libc::tcsetattr(fd, libc::TCSANOW, &raw) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            // 隐藏光标
            let _ = libc::write(fd, b"\x1b[?25l".as_ptr() as *const libc::c_void, 6);
            Ok(Self { orig, fd })
        }
    }
}

#[cfg(unix)]
impl Drop for RawModeGuard {
    fn drop(&mut self) {
        unsafe {
            // 显示光标并恢复原始终端属性
            let _ = libc::write(self.fd, b"\x1b[?25h".as_ptr() as *const libc::c_void, 6);
            libc::tcsetattr(self.fd, libc::TCSANOW, &self.orig);
        }
    }
}

/// 交互式复选框选择。
/// - 若 is_tty 为 true 且在 unix 环境下，进入 termios raw 模式，支持空格切换、上下键移动、回车确认、Ctrl-C 中止；
/// - 若非 tty，退回行输入模式 (空格分隔编号，回车使用默认)。
pub fn prompt_checkbox_interactive(
    state: CheckboxState,
    reader: &mut dyn BufRead,
    writer: &mut dyn Write,
    is_tty: bool,
) -> Result<Vec<String>, String> {
    #[cfg(unix)]
    if is_tty {
        return run_tty_checkbox(state, writer);
    }

    run_line_checkbox(state, reader, writer)
}

fn run_line_checkbox(
    mut state: CheckboxState,
    reader: &mut dyn BufRead,
    writer: &mut dyn Write,
) -> Result<Vec<String>, String> {
    for line in state.render_line_prompt() {
        writeln!(writer, "{line}").map_err(|e| e.to_string())?;
    }
    write!(writer, "> ").map_err(|e| e.to_string())?;
    writer.flush().map_err(|e| e.to_string())?;

    let mut line = String::new();
    if reader.read_line(&mut line).map_err(|e| e.to_string())? == 0 {
        // EOF 无输入: 保持现状不建组
        return Ok(Vec::new());
    }

    state.apply_line_input(&line)?;
    let selected = state.checked_keys();
    writeln!(writer, "  已选择: [{}]", selected.join(", ")).map_err(|e| e.to_string())?;
    Ok(selected)
}

#[cfg(unix)]
fn run_tty_checkbox(
    mut state: CheckboxState,
    writer: &mut dyn Write,
) -> Result<Vec<String>, String> {
    let stdin_fd = libc::STDIN_FILENO;
    let guard = RawModeGuard::enter(stdin_fd).map_err(|e| format!("启用终端 raw mode 失败: {e}"))?;

    let lines = state.render_tty_lines();
    for l in &lines {
        writeln!(writer, "\r{l}").map_err(|e| e.to_string())?;
    }
    writer.flush().map_err(|e| e.to_string())?;
    let mut last_line_count = lines.len();

    let mut buf = [0u8; 1];
    let res: Result<Vec<String>, String> = (|| loop {
        let n = unsafe { libc::read(stdin_fd, buf.as_mut_ptr() as *mut libc::c_void, 1) };
        if n <= 0 {
            return Err("读取终端输入遇到 EOF 或错误".to_string());
        }
        match buf[0] {
            // Ctrl-C (0x03) 或 Ctrl-D (0x04)
            3 | 4 => return Err("用户取消操作 (Ctrl-C)".to_string()),
            // 回车
            b'\r' | b'\n' => {
                return Ok(state.checked_keys());
            }
            // 空格: 切换勾选
            b' ' => {
                state.toggle();
            }
            // 上下键 (支持 k/j 与 ESC [ A/B)
            b'k' | b'K' => state.move_up(),
            b'j' | b'J' => state.move_down(),
            0x1b => {
                // 读取 ANSI escape sequence
                let mut seq = [0u8; 2];
                let n2 = unsafe { libc::read(stdin_fd, seq.as_mut_ptr() as *mut libc::c_void, 2) };
                if n2 == 2 && seq[0] == b'[' {
                    match seq[1] {
                        b'A' => state.move_up(),
                        b'B' => state.move_down(),
                        _ => {}
                    }
                }
            }
            _ => {}
        }

        // 重绘 UI: 先光标向上移动 last_line_count 行并清屏到末尾
        let new_lines = state.render_tty_lines();
        write!(writer, "\r\x1b[{}A\x1b[J", last_line_count).map_err(|e| e.to_string())?;
        for l in &new_lines {
            writeln!(writer, "\r{l}").map_err(|e| e.to_string())?;
        }
        writer.flush().map_err(|e| e.to_string())?;
        last_line_count = new_lines.len();
    })();

    drop(guard);
    // 换行退出 raw mode
    writeln!(writer).map_err(|e| e.to_string())?;
    if let Ok(ref selected) = res {
        writeln!(writer, "  已选择: [{}]", selected.join(", ")).map_err(|e| e.to_string())?;
    }
    res
}

/// 询问单选 Yes/No (默认由 default_yes 决定)
pub fn prompt_yes_no_interactive(
    prompt: &str,
    default_yes: bool,
    reader: &mut dyn BufRead,
    writer: &mut dyn Write,
) -> Result<bool, String> {
    let hint = if default_yes { "Y/n" } else { "y/N" };
    write!(writer, "{prompt} [{hint}]: ").map_err(|e| e.to_string())?;
    writer.flush().map_err(|e| e.to_string())?;

    let mut line = String::new();
    if reader.read_line(&mut line).map_err(|e| e.to_string())? == 0 {
        return Ok(default_yes);
    }
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Ok(default_yes);
    }
    if trimmed.eq_ignore_ascii_case("y") || trimmed.eq_ignore_ascii_case("yes") {
        Ok(true)
    } else if trimmed.eq_ignore_ascii_case("n") || trimmed.eq_ignore_ascii_case("no") {
        Ok(false)
    } else {
        Ok(default_yes)
    }
}

/// 收集配置中所有完整的 mirage 节点出站的 tag
pub fn collect_mirage_tags(root: &Value) -> Vec<String> {
    root.get("outbounds")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter(|o| o.get("type").and_then(|t| t.as_str()) == Some("mirage"))
                .filter_map(|o| o.get("tag").and_then(|t| t.as_str()).map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// 收集配置中所有已存在的 outbound tags
pub fn collect_all_outbound_tags(root: &Value) -> Vec<String> {
    root.get("outbounds")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|o| o.get("tag").and_then(|t| t.as_str()).map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// 生成不与 taken 冲突的候选 tag
fn generate_unique_tag(base: &str, taken: &mut Vec<String>) -> String {
    if !taken.iter().any(|t| t == base) {
        taken.push(base.to_string());
        return base.to_string();
    }
    for i in 2..1000 {
        let cand = format!("{base}-{i}");
        if !taken.iter().any(|t| t == &cand) {
            taken.push(cand.clone());
            return cand;
        }
    }
    format!("{base}-new")
}

/// 核心原则 2 调度函数:
/// 检查配置中的 mirage 节点数，若 >= 2 则根据是否存在出站组引导用户调整出站组。
/// 返回 Ok(true) 表示修改了配置，Ok(false) 表示无需修改或用户取消。
pub fn adjust_outbound_groups(
    root: &mut Value,
    reader: &mut dyn BufRead,
    writer: &mut dyn Write,
    is_tty: bool,
    new_node_tag: Option<&str>,
) -> Result<bool, String> {
    let mirage_tags = collect_mirage_tags(root);
    if mirage_tags.len() < 2 {
        // 只有一个或零个代理节点时不建任何组 (现状保持)
        return Ok(false);
    }

    let arr = root
        .get_mut("outbounds")
        .and_then(|v| v.as_array_mut())
        .ok_or_else(|| "outbounds 必须为数组".to_string())?;

    // 检查是否已有出站组
    let mut has_existing_groups = false;
    for o in arr.iter() {
        let o_type = o.get("type").and_then(|t| t.as_str()).unwrap_or("");
        if mirage_rs::config::is_group_type(o_type) {
            has_existing_groups = true;
            break;
        }
    }

    if !has_existing_groups {
        // ── 情况 1: 配置里还没有组 ─────────────────────────────────────
        let mut taken = collect_all_outbound_tags(root);
        let auto_tag = generate_unique_tag("auto", &mut taken);
        let select_tag = generate_unique_tag("select", &mut taken);
        let fallback_tag = generate_unique_tag("fallback", &mut taken);
        let lb_tag = generate_unique_tag("load_balance", &mut taken);

        let group_candidates = vec![
            CheckboxItem {
                key: auto_tag.clone(),
                title: format!("{auto_tag} (urltest, 自动测速优选组)"),
                detail: "按 RTT 自动选路，故障自动切换".to_string(),
                checked: true,
            },
            CheckboxItem {
                key: select_tag.clone(),
                title: format!("{select_tag} (selector, 手动选择组)"),
                detail: "可在 WebUI / API 手动切换节点".to_string(),
                checked: true,
            },
            CheckboxItem {
                key: fallback_tag.clone(),
                title: format!("{fallback_tag} (fallback, 故障转移组)"),
                detail: "按节点先后顺序主备切换".to_string(),
                checked: false,
            },
            CheckboxItem {
                key: lb_tag.clone(),
                title: format!("{lb_tag} (load_balance, 负载均衡组)"),
                detail: "多连接轮询分摊流量".to_string(),
                checked: false,
            },
        ];

        let state = CheckboxState::new(
            "检测到多个代理节点，请选择要添加的出站组".to_string(),
            group_candidates,
        );
        let chosen_groups = prompt_checkbox_interactive(state, reader, writer, is_tty)?;
        if chosen_groups.is_empty() {
            writeln!(writer, "  未选择任何出站组，保持现状不建组。").map_err(|e| e.to_string())?;
            return Ok(false);
        }

        let both_auto_and_select =
            chosen_groups.contains(&auto_tag) && chosen_groups.contains(&select_tag);

        let mut new_group_objects: Vec<Value> = Vec::new();

        // 为每个选中的组引导选择节点成员
        for grp in &chosen_groups {
            let mut node_items: Vec<CheckboxItem> = Vec::new();
            if grp == &select_tag && both_auto_and_select {
                // 若同时建了 auto 和 select，select 的成员默认还包含 auto 并放在第一位
                node_items.push(CheckboxItem {
                    key: auto_tag.clone(),
                    title: format!("{auto_tag} (自动优选组)"),
                    detail: "将自动组置于手动选择列表首项".to_string(),
                    checked: true,
                });
            }
            for m in &mirage_tags {
                node_items.push(CheckboxItem {
                    key: m.clone(),
                    title: m.clone(),
                    detail: "代理节点".to_string(),
                    checked: true,
                });
            }

            let prompt_title = format!("请选择加入组 `{grp}` 的成员节点");
            let state = CheckboxState::new(prompt_title, node_items);
            let members = prompt_checkbox_interactive(state, reader, writer, is_tty)?;
            let final_members = if members.is_empty() {
                // 如果用户没选任何节点，则默认全选防空组
                mirage_tags.clone()
            } else {
                members
            };

            if grp == &auto_tag {
                new_group_objects.push(serde_json::json!({
                    "type": "urltest",
                    "tag": auto_tag,
                    "outbounds": final_members
                }));
            } else if grp == &select_tag {
                new_group_objects.push(serde_json::json!({
                    "type": "selector",
                    "tag": select_tag,
                    "outbounds": final_members
                }));
            } else if grp == &fallback_tag {
                new_group_objects.push(serde_json::json!({
                    "type": "fallback",
                    "tag": fallback_tag,
                    "outbounds": final_members
                }));
            } else if grp == &lb_tag {
                new_group_objects.push(serde_json::json!({
                    "type": "load_balance",
                    "tag": lb_tag,
                    "strategy": "round-robin",
                    "outbounds": final_members
                }));
            }
        }

        // 新建的组插入到 outbounds 最前面 (按原则 1 成为默认出站)；
        // select 存在则 select 在最前，否则 auto 在最前
        new_group_objects.sort_by_key(|g| {
            let t = g.get("type").and_then(|v| v.as_str()).unwrap_or("");
            match t {
                "selector" => 0,
                "urltest" => 1,
                "fallback" => 2,
                "load_balance" => 3,
                _ => 4,
            }
        });

        let primary_group_tag = new_group_objects
            .first()
            .and_then(|g| g.get("tag"))
            .and_then(|t| t.as_str())
            .unwrap_or("")
            .to_string();

        let arr = root
            .get_mut("outbounds")
            .and_then(|v| v.as_array_mut())
            .unwrap();
        // 前插到 outbounds 最前
        for g in new_group_objects.into_iter().rev() {
            arr.insert(0, g);
        }

        // 若 routing.default_outbound 显式指向某个单节点，询问是否改指向新建的组 (默认是)
        let explicit_default = root
            .get("routing")
            .and_then(|r| r.get("default_outbound"))
            .and_then(|d| d.as_str())
            .map(str::to_string);

        if let Some(def) = explicit_default {
            if mirage_tags.contains(&def) {
                let prompt = format!(
                    "routing.default_outbound 当前显式指向单节点 `{def}`，是否改指向新建的出站组 `{primary_group_tag}`？"
                );
                if prompt_yes_no_interactive(&prompt, true, reader, writer)? {
                    if let Some(routing) = root.get_mut("routing").and_then(|r| r.as_object_mut()) {
                        routing.insert(
                            "default_outbound".to_string(),
                            serde_json::json!(primary_group_tag),
                        );
                        writeln!(
                            writer,
                            "✓ 已将 routing.default_outbound 改为 `{primary_group_tag}`"
                        )
                        .map_err(|e| e.to_string())?;
                    }
                }
            }
        }

        writeln!(writer, "✓ 已自动创建出站组并置于 outbounds 首部。").map_err(|e| e.to_string())?;
        Ok(true)
    } else {
        // ── 情况 2: 配置里已有组 ─────────────────────────────────────
        // 列出现有各组 (复选框)，默认勾选"当前已包含全部其它节点"的组，用户勾选新节点加入哪些组
        let mut group_items = Vec::new();
        let other_mirage_tags: Vec<String> = if let Some(tag) = new_node_tag {
            mirage_tags.iter().filter(|t| t.as_str() != tag).cloned().collect()
        } else {
            // 如果未能确定单个新节点，则取非最新节点
            if mirage_tags.len() > 1 {
                mirage_tags[..mirage_tags.len() - 1].to_vec()
            } else {
                Vec::new()
            }
        };

        for o in arr.iter() {
            let o_type = o.get("type").and_then(|t| t.as_str()).unwrap_or("");
            if !mirage_rs::config::is_group_type(o_type) {
                continue;
            }
            let g_tag = o.get("tag").and_then(|t| t.as_str()).unwrap_or("").to_string();
            let members: Vec<String> = o
                .get("outbounds")
                .and_then(|m| m.as_array())
                .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
                .unwrap_or_default();

            // 默认勾选"当前已包含全部其它节点"的组
            let default_checked = !other_mirage_tags.is_empty()
                && other_mirage_tags.iter().all(|t| members.contains(t));

            group_items.push(CheckboxItem {
                key: g_tag.clone(),
                title: format!("{g_tag} ({o_type})"),
                detail: format!("当前成员: [{}]", members.join(", ")),
                checked: default_checked,
            });
        }

        if group_items.is_empty() {
            return Ok(false);
        }

        let target_node = new_node_tag.unwrap_or(mirage_tags.last().unwrap().as_str());
        let prompt_title = format!("请选择将新节点 `{target_node}` 加入哪些出站组");
        let state = CheckboxState::new(prompt_title, group_items);
        let chosen = prompt_checkbox_interactive(state, reader, writer, is_tty)?;

        if chosen.is_empty() {
            writeln!(writer, "  未选择任何组加入。").map_err(|e| e.to_string())?;
            return Ok(false);
        }

        let mut updated = false;
        for o in arr.iter_mut() {
            let g_tag = o.get("tag").and_then(|t| t.as_str()).unwrap_or("");
            if chosen.contains(&g_tag.to_string()) {
                if let Some(members) = o.get_mut("outbounds").and_then(|m| m.as_array_mut()) {
                    if !members.iter().any(|m| m.as_str() == Some(target_node)) {
                        members.push(serde_json::json!(target_node));
                        updated = true;
                    }
                }
            }
        }

        if updated {
            writeln!(
                writer,
                "✓ 节点 `{target_node}` 已成功加入选中的出站组: [{}]",
                chosen.join(", ")
            )
            .map_err(|e| e.to_string())?;
        }
        Ok(updated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_line_input_parsing_defaults_and_spaces() {
        let items = vec![
            CheckboxItem { key: "a".into(), title: "Item A".into(), detail: "".into(), checked: true },
            CheckboxItem { key: "b".into(), title: "Item B".into(), detail: "".into(), checked: false },
            CheckboxItem { key: "c".into(), title: "Item C".into(), detail: "".into(), checked: true },
            CheckboxItem { key: "d".into(), title: "Item D".into(), detail: "".into(), checked: false },
        ];
        let mut st = CheckboxState::new("Test".into(), items);

        // 回车 (空串) 保持默认
        st.apply_line_input("").unwrap();
        assert_eq!(st.checked_keys(), vec!["a", "c"]);

        // 空格分隔的编号 "2 4"
        st.apply_line_input("2 4").unwrap();
        assert_eq!(st.checked_keys(), vec!["b", "d"]);

        // "all"
        st.apply_line_input("all").unwrap();
        assert_eq!(st.checked_keys(), vec!["a", "b", "c", "d"]);

        // "none"
        st.apply_line_input("none").unwrap();
        assert!(st.checked_keys().is_empty());

        // 越界报错
        assert!(st.apply_line_input("5").is_err());
        assert!(st.apply_line_input("0 1").is_err());
        assert!(st.apply_line_input("abc").is_err());
    }

    #[test]
    fn test_single_node_does_not_create_groups() {
        let mut root = serde_json::json!({
            "outbounds": [
                { "type": "mirage", "tag": "m1", "server": "1.2.3.4", "server_port": 443, "password": "p", "camouflage_host": "s" },
                { "type": "direct", "tag": "direct" }
            ],
            "routing": { "default_outbound": "direct", "rules": [] }
        });
        let mut reader = Cursor::new(b"\n");
        let mut writer = Vec::new();
        let changed = adjust_outbound_groups(&mut root, &mut reader, &mut writer, false, Some("m1")).unwrap();
        assert!(!changed, "1个节点时不建组");
        assert_eq!(root["outbounds"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn test_second_node_triggers_groups_creation_and_structure() {
        let mut root = serde_json::json!({
            "outbounds": [
                { "type": "mirage", "tag": "m1", "server": "192.0.2.1", "server_port": 443, "password": "p", "camouflage_host": "example.com" },
                { "type": "mirage", "tag": "m2", "server": "192.0.2.2", "server_port": 443, "password": "p", "camouflage_host": "example.com" },
                { "type": "direct", "tag": "direct" }
            ],
            "routing": { "default_outbound": "m1", "rules": [] }
        });

        // 交互输入: 组选择回车 (默认选 auto 和 select), auto 节点选择回车 (默认全选), select 节点选择回车 (默认全选), routing 切换默认回车 (y)
        let mut reader = Cursor::new(b"\n\n\ny\n");
        let mut writer = Vec::new();
        let changed = adjust_outbound_groups(&mut root, &mut reader, &mut writer, false, Some("m2")).unwrap();
        assert!(changed, "2个节点触发建组");

        let obs = root["outbounds"].as_array().unwrap();
        // select 在最前, auto 在其次
        assert_eq!(obs[0]["tag"], "select");
        assert_eq!(obs[0]["type"], "selector");
        assert_eq!(obs[1]["tag"], "auto");
        assert_eq!(obs[1]["type"], "urltest");

        // select 成员首项为 auto
        let sel_members = obs[0]["outbounds"].as_array().unwrap();
        assert_eq!(sel_members[0], "auto");
        assert_eq!(sel_members[1], "m1");
        assert_eq!(sel_members[2], "m2");

        // auto 成员包含 m1, m2
        assert_eq!(obs[1]["outbounds"], serde_json::json!(["m1", "m2"]));

        // default_outbound 更新为 select
        assert_eq!(root["routing"]["default_outbound"], "select");
    }

    #[test]
    fn test_existing_groups_new_node_joins() {
        let mut root = serde_json::json!({
            "outbounds": [
                { "type": "selector", "tag": "select", "outbounds": ["auto", "m1", "m2"] },
                { "type": "urltest", "tag": "auto", "outbounds": ["m1", "m2"] },
                { "type": "mirage", "tag": "m1", "server": "192.0.2.1", "server_port": 443, "password": "p", "camouflage_host": "example.com" },
                { "type": "mirage", "tag": "m2", "server": "192.0.2.2", "server_port": 443, "password": "p", "camouflage_host": "example.com" },
                { "type": "mirage", "tag": "m3", "server": "192.0.2.3", "server_port": 443, "password": "p", "camouflage_host": "example.com" },
                { "type": "direct", "tag": "direct" }
            ],
            "routing": { "default_outbound": "select", "rules": [] }
        });

        // 默认勾选包含所有其它节点 (m1, m2) 的组 (select 和 auto 均全包含)
        // 回车接受默认勾选
        let mut reader = Cursor::new(b"\n");
        let mut writer = Vec::new();
        let changed = adjust_outbound_groups(&mut root, &mut reader, &mut writer, false, Some("m3")).unwrap();
        assert!(changed);

        let obs = root["outbounds"].as_array().unwrap();
        assert_eq!(obs[0]["outbounds"], serde_json::json!(["auto", "m1", "m2", "m3"]));
        assert_eq!(obs[1]["outbounds"], serde_json::json!(["m1", "m2", "m3"]));
    }

    #[test]
    fn test_tag_conflict_resolves_without_overwrite() {
        let mut root = serde_json::json!({
            "outbounds": [
                { "type": "mirage", "tag": "auto", "server": "192.0.2.1", "server_port": 443, "password": "p", "camouflage_host": "example.com" },
                { "type": "mirage", "tag": "m2", "server": "192.0.2.2", "server_port": 443, "password": "p", "camouflage_host": "example.com" },
                { "type": "direct", "tag": "direct" }
            ],
            "routing": { "default_outbound": "direct", "rules": [] }
        });

        let mut reader = Cursor::new(b"\n\n\n");
        let mut writer = Vec::new();
        let changed = adjust_outbound_groups(&mut root, &mut reader, &mut writer, false, Some("m2")).unwrap();
        assert!(changed);

        let obs = root["outbounds"].as_array().unwrap();
        // 原有出站 auto 未被覆盖
        assert!(obs.iter().any(|o| o["tag"] == "auto" && o["type"] == "mirage"));
        // 新建的 urltest 组 tag 自动加后缀变 auto-2
        assert!(obs.iter().any(|o| o["tag"] == "auto-2" && o["type"] == "urltest"));
    }
}
