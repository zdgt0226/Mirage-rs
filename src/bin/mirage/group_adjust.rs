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
            // 截断过长说明: 折行会让"上移 N 行重绘"错位
            let detail = if item.detail.is_empty() {
                String::new()
            } else {
                format!(" - {}", truncate_chars(&item.detail, 40))
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

/// 用户在复选框里按 Ctrl-C / Ctrl-D 取消时的错误文本; 调用方据此整体中止 (不写盘)。
pub const CANCELLED: &str = "用户取消操作";

fn truncate_chars(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(max.saturating_sub(1)).collect();
        t.push('…');
        t
    }
}

/// 终端显示宽度 (近似): 东亚宽字符 / 全角标点按 2 列, 其余 1 列。
fn display_width(s: &str) -> usize {
    s.chars().map(|c| if is_wide(c) { 2 } else { 1 }).sum()
}

fn is_wide(c: char) -> bool {
    matches!(c as u32,
        0x1100..=0x115F | 0x2E80..=0x303E | 0x3041..=0x33FF | 0x3400..=0x4DBF | 0x4E00..=0x9FFF
        | 0xA000..=0xA4CF | 0xAC00..=0xD7A3 | 0xF900..=0xFAFF | 0xFE30..=0xFE4F | 0xFF00..=0xFF60
        | 0xFFE0..=0xFFE6)
}

/// 按显示宽度截断到 `width` 列以内 (超出时末尾换成 …), 保证重绘时一行不折行。
fn fit_width(s: &str, width: usize) -> String {
    if display_width(s) <= width {
        return s.to_string();
    }
    let mut out = String::new();
    let mut w = 0;
    for c in s.chars() {
        let cw = if is_wide(c) { 2 } else { 1 };
        if w + cw + 1 > width {
            break;
        }
        out.push(c);
        w += cw;
    }
    out.push('…');
    out
}

/// 当前终端列数 (取不到时按 80)。
#[cfg(unix)]
fn terminal_width(fd: libc::c_int) -> usize {
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    if unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut ws) } == 0 && ws.ws_col > 0 {
        ws.ws_col as usize
    } else {
        80
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
            Ok(Self { orig, fd })
        }
    }
}

#[cfg(unix)]
impl Drop for RawModeGuard {
    fn drop(&mut self) {
        unsafe {
            // 恢复光标显示 (写到 stdout; 含 panic 展开路径) 与原终端属性
            let _ = libc::write(libc::STDOUT_FILENO, b"\x1b[?25h".as_ptr() as *const libc::c_void, 6);
            libc::tcsetattr(self.fd, libc::TCSANOW, &self.orig);
        }
    }
}

/// 复选框按键 (从一次 read 到的字节块里解析; 终端一次按键的转义序列通常在同一块里到达)。
#[derive(Debug, PartialEq, Eq)]
enum Key {
    Up,
    Down,
    Toggle,
    Enter,
    Cancel,
    Other,
}

/// 把一块输入字节解析成按键序列。单独的 ESC (后面没有 `[`) 当作无操作, 不吞后续按键。
fn parse_keys(chunk: &[u8]) -> Vec<Key> {
    let mut keys = Vec::new();
    let mut i = 0;
    while i < chunk.len() {
        match chunk[i] {
            3 | 4 => keys.push(Key::Cancel),
            b'\r' | b'\n' => keys.push(Key::Enter),
            b' ' => keys.push(Key::Toggle),
            b'k' | b'K' => keys.push(Key::Up),
            b'j' | b'J' => keys.push(Key::Down),
            // CSI (ESC [ A) 与 application cursor 模式的 SS3 (ESC O A) 两种方向键序列
            0x1b if matches!(chunk.get(i + 1), Some(b'[') | Some(b'O')) && i + 2 < chunk.len() => {
                keys.push(match chunk[i + 2] {
                    b'A' => Key::Up,
                    b'B' => Key::Down,
                    _ => Key::Other,
                });
                i += 3;
                continue;
            }
            _ => keys.push(Key::Other),
        }
        i += 1;
    }
    keys
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
    loop {
        write!(writer, "> ").map_err(|e| e.to_string())?;
        writer.flush().map_err(|e| e.to_string())?;

        let mut line = String::new();
        if reader.read_line(&mut line).map_err(|e| e.to_string())? == 0 {
            // EOF 无输入: 保持现状不建组
            return Ok(Vec::new());
        }
        // 输错编号就重输, 不整段放弃
        match state.apply_line_input(&line) {
            Ok(()) => break,
            Err(e) => writeln!(writer, "  {e}, 请重新输入。").map_err(|e| e.to_string())?,
        }
    }
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

    // 每行按终端宽度截断: 折行会让"上移 N 行"重绘错位
    let width = terminal_width(libc::STDOUT_FILENO).saturating_sub(1).max(20);
    let draw = |state: &CheckboxState, writer: &mut dyn Write, prev_lines: usize| -> Result<usize, String> {
        if prev_lines > 0 {
            write!(writer, "\r\x1b[{prev_lines}A\x1b[J").map_err(|e| e.to_string())?;
        }
        let lines = state.render_tty_lines();
        for l in &lines {
            writeln!(writer, "\r{}", fit_width(l, width)).map_err(|e| e.to_string())?;
        }
        writer.flush().map_err(|e| e.to_string())?;
        Ok(lines.len())
    };

    // 隐藏光标 (写到输出端; stdin 可能是只读打开的 /dev/tty)
    let _ = write!(writer, "\x1b[?25l");
    let res: Result<Vec<String>, String> = (|| {
        let mut drawn = draw(&state, writer, 0)?;
        let mut buf = [0u8; 64];
        loop {
            let n = unsafe { libc::read(stdin_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
            if n < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue; // 被信号打断 (如窗口大小变化 SIGWINCH), 重读
            }
            if n <= 0 {
                return Err("读取终端输入遇到 EOF 或错误".to_string());
            }
            for key in parse_keys(&buf[..n as usize]) {
                match key {
                    Key::Cancel => return Err(CANCELLED.to_string()),
                    Key::Enter => return Ok(state.checked_keys()),
                    Key::Toggle => state.toggle(),
                    Key::Up => state.move_up(),
                    Key::Down => state.move_down(),
                    Key::Other => {}
                }
            }
            drawn = draw(&state, writer, drawn)?;
        }
    })();

    let _ = writer.flush();
    drop(guard);
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

/// 建组后给用户的默认出站说明: 默认出站是组 → 说明已走组; 否则提醒组还没被用上。
pub fn default_outbound_note(root: &Value) -> String {
    let def = mirage_rs::config::resolve_default_outbound_from_value(root);
    let is_group = root
        .get("outbounds")
        .and_then(|v| v.as_array())
        .and_then(|a| a.iter().find(|o| o.get("tag").and_then(|t| t.as_str()) == Some(def)))
        .and_then(|o| o.get("type").and_then(|t| t.as_str()))
        .is_some_and(mirage_rs::config::is_group_type);
    if is_group {
        format!("出站组已更新, 默认出站为组 `{def}`。")
    } else {
        format!("出站组已更新, 但默认出站仍是 `{def}`; 要让流量走组, 把 routing.default_outbound 改为组的 tag。")
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
    new_node_tags: &[String],
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
        // 新节点: 调用方给出 (import 一个 / subscribe 一批); 未给出时退化为"不在任何组里的节点"
        let new_tags: Vec<String> = if new_node_tags.is_empty() {
            let in_groups: std::collections::HashSet<String> = arr
                .iter()
                .filter(|o| mirage_rs::config::is_group_type(o.get("type").and_then(|t| t.as_str()).unwrap_or("")))
                .filter_map(|o| o.get("outbounds").and_then(|m| m.as_array()))
                .flatten()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect();
            mirage_tags.iter().filter(|t| !in_groups.contains(*t)).cloned().collect()
        } else {
            new_node_tags.to_vec()
        };
        if new_tags.is_empty() {
            return Ok(false);
        }
        let other_mirage_tags: Vec<String> =
            mirage_tags.iter().filter(|t| !new_tags.contains(t)).cloned().collect();

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

        let target_desc = new_tags.join(", ");
        let prompt_title = format!("请选择将新节点 [{target_desc}] 加入哪些出站组");
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
                    for t in &new_tags {
                        if !members.iter().any(|m| m.as_str() == Some(t.as_str())) {
                            members.push(serde_json::json!(t));
                            updated = true;
                        }
                    }
                }
            }
        }

        if updated {
            writeln!(
                writer,
                "✓ 新节点 [{target_desc}] 已加入出站组: [{}]",
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
        let changed = adjust_outbound_groups(&mut root, &mut reader, &mut writer, false, &["m1".to_string()]).unwrap();
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
        let changed = adjust_outbound_groups(&mut root, &mut reader, &mut writer, false, &["m2".to_string()]).unwrap();
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
        let changed = adjust_outbound_groups(&mut root, &mut reader, &mut writer, false, &["m3".to_string()]).unwrap();
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
        let changed = adjust_outbound_groups(&mut root, &mut reader, &mut writer, false, &["m2".to_string()]).unwrap();
        assert!(changed);

        let obs = root["outbounds"].as_array().unwrap();
        // 原有出站 auto 未被覆盖
        assert!(obs.iter().any(|o| o["tag"] == "auto" && o["type"] == "mirage"));
        // 新建的 urltest 组 tag 自动加后缀变 auto-2
        assert!(obs.iter().any(|o| o["tag"] == "auto-2" && o["type"] == "urltest"));
    }

    #[test]
    fn test_parse_keys_lone_esc_does_not_swallow_next_key() {
        // 单独 ESC 后紧跟回车 (同一块或下一块) 回车照样生效
        assert_eq!(parse_keys(b"\x1b"), vec![Key::Other]);
        assert_eq!(parse_keys(b"\x1b\r"), vec![Key::Other, Key::Enter]);
        assert_eq!(parse_keys(b"\r"), vec![Key::Enter]);
        // 方向键转义序列
        assert_eq!(parse_keys(b"\x1b[A\x1b[B"), vec![Key::Up, Key::Down]);
        // 一块里多个按键 (粘贴 / 快速连按) 逐个解析
        assert_eq!(parse_keys(b"j j\r"), vec![Key::Down, Key::Toggle, Key::Down, Key::Enter]);
        assert_eq!(parse_keys(&[3]), vec![Key::Cancel]);
        // application cursor 模式 (SS3) 的方向键
        assert_eq!(parse_keys(b"\x1bOA\x1bOB"), vec![Key::Up, Key::Down]);
    }

    #[test]
    fn test_fit_width_counts_wide_chars() {
        assert_eq!(fit_width("abc", 10), "abc");
        // 中文按 2 列: 6 个汉字 = 12 列, 截到 10 列以内并加 …
        let t = fit_width("请选择将新节点", 10);
        assert!(display_width(&t) <= 10, "{t}");
        assert!(t.ends_with('…'));
    }

    #[test]
    fn test_subscribe_batch_all_new_nodes_join_chosen_groups() {
        let mut root = serde_json::json!({
            "outbounds": [
                { "type": "urltest", "tag": "auto", "outbounds": ["m1", "m2"] },
                { "type": "mirage", "tag": "m1", "server": "192.0.2.1", "server_port": 443, "password": "p", "camouflage_host": "example.com" },
                { "type": "mirage", "tag": "m2", "server": "192.0.2.2", "server_port": 443, "password": "p", "camouflage_host": "example.com" },
                { "type": "mirage", "tag": "m3", "server": "192.0.2.3", "server_port": 443, "password": "p", "camouflage_host": "example.com" },
                { "type": "mirage", "tag": "m4", "server": "192.0.2.4", "server_port": 443, "password": "p", "camouflage_host": "example.com" }
            ]
        });
        let mut reader = Cursor::new(b"\n");
        let mut writer = Vec::new();
        let new = vec!["m3".to_string(), "m4".to_string()];
        assert!(adjust_outbound_groups(&mut root, &mut reader, &mut writer, false, &new).unwrap());
        assert_eq!(root["outbounds"][0]["outbounds"], serde_json::json!(["m1", "m2", "m3", "m4"]));

        // 未给出新节点列表时退化为"不在任何组里的节点"
        let mut root2 = root.clone();
        root2["outbounds"][0]["outbounds"] = serde_json::json!(["m1", "m2"]);
        let mut reader = Cursor::new(b"\n");
        assert!(adjust_outbound_groups(&mut root2, &mut reader, &mut writer, false, &[]).unwrap());
        assert_eq!(root2["outbounds"][0]["outbounds"], serde_json::json!(["m1", "m2", "m3", "m4"]));
    }

    #[test]
    fn test_default_outbound_note_reflects_whether_group_is_default() {
        let mut root = serde_json::json!({
            "outbounds": [
                { "type": "selector", "tag": "select", "outbounds": ["m1"] },
                { "type": "mirage", "tag": "m1", "server": "192.0.2.1", "server_port": 443, "password": "p", "camouflage_host": "example.com" },
                { "type": "direct", "tag": "direct" }
            ]
        });
        assert!(default_outbound_note(&root).contains("默认出站为组 `select`"));
        root["routing"] = serde_json::json!({ "default_outbound": "direct" });
        assert!(default_outbound_note(&root).contains("仍是 `direct`"));
    }
}
