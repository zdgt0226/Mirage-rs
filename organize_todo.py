import re

with open("README.md", "r", encoding="utf-8") as f:
    content = f.read()

# Locate the TODO section
todo_start = content.find("## 路线图 / TODO")
todo_end = content.find("## 📜 版本迭代概览 (Changelog)")

if todo_start == -1 or todo_end == -1:
    print("Could not find TODO section boundaries.")
    exit(1)

todo_section = content[todo_start:todo_end]
prefix = content[:todo_start]
suffix = content[todo_end:]

# Parse the TODO section
lines = todo_section.split("\n")

header_lines = []
completed = []
partial = []
todo = []
wont_do = []

state = "header"
for line in lines:
    if line.strip() == "## 路线图 / TODO":
        continue
    
    if line.startswith("> ") or line.strip() == "" and state == "header":
        if line.strip() != "":
            header_lines.append(line)
        continue
    else:
        state = "body"

    if "评估后决定不做" in line:
        state = "wont_do"
        wont_do.append(line)
        continue
    
    if state == "wont_do":
        wont_do.append(line)
        continue

    # Categorize by checkbox
    if line.strip().startswith("- [x]"):
        completed.append(line)
    elif line.strip().startswith("- [~]"):
        partial.append(line)
    elif line.strip().startswith("- [ ]"):
        todo.append(line)
    elif line.strip().startswith("-") and state != "wont_do":
        # Maybe some other lists? Just put them in todo for now
        todo.append(line)

new_todo = "## 路线图 / TODO\n\n"
new_todo += "\n".join(header_lines) + "\n\n"

if completed:
    new_todo += "### ✅ 已完成\n\n"
    new_todo += "\n".join(completed) + "\n\n"

if partial:
    new_todo += "### 🚧 部分完成\n\n"
    new_todo += "\n".join(partial) + "\n\n"

if todo:
    new_todo += "### ⏳ 未完成 (计划池)\n\n"
    new_todo += "\n".join(todo) + "\n\n"

if wont_do:
    new_todo += "\n".join(wont_do) + "\n\n"

with open("README.md", "w", encoding="utf-8") as f:
    f.write(prefix + new_todo + suffix)

print("TODO organized.")
