<!-- graft:start -->
## Graft — repo context graph

This repo is indexed in `graft/`: small linked markdown nodes that explain each
system and carry exact file:line spans, kept in sync with the code through git.

For ANY task here — understanding how something works, finding where code lives,
or scoping a change — get context from the graph before grepping or opening
source files. Re-ask freely (it's cheap) and reuse literal identifiers you
already have (symbol, error string, file name) as the query. New to this repo?
Run `graft map` first — a token-budgeted orientation (dir clusters, hubs,
hotspots), no LLM, no key.

- Run `graft ask "<your question>" --source` → ranked nodes with the relevant
  code spans inlined (each hit's ≤8-line crux by default; `--full` for whole
  definitions when the crux isn't enough). Match the tool to the task shape:
  for understanding or editing, the top node IS the answer — cite its
  `covers:` file:line spans and edit straight from `--source`. For
  exhaustive tasks ("every occurrence / every caller of this pattern"), ranked
  results are top-N, not complete — run `graft grep "<literal>"` instead
  (exhaustive over indexed files, grouped by enclosing symbol), falling back
  to raw `grep -rn` only for unindexed files.
- `graft skeleton <file>` → every definition's signature + span, ~10× cheaper
  than reading the file; use it to skim an API surface.
- `graft callers <symbol>` gives precomputed, exact edges — who calls this.
  Add `--direction out` for what it calls, or `--depth N` to walk
  transitively for the full blast radius. For structural questions, skip
  ranking and use this directly.
- Or browse: `graft/INDEX.md` lists every node; follow the links.
- Monorepos and folders of multiple repos rank fairly across sub-projects —
  hits carry `[scope/]` labels naming which one they're from. Narrow with
  `graft ask "<task>" --in <scope>/` once you know where you're working.

If a returned span is truncated ("+N more lines"), open the file at that exact
range before finalizing. Only open source files when a node genuinely lacks a
needed detail, and then at the exact file:line the node points to — never
re-read whole files.

After big code changes, refresh the graph with `graft build` (deterministic,
no API key, $0).
<!-- graft:end -->

## Security & Endpoint Guardrails (硬性规则)

- **禁止硬编码敏感信息**：禁止在仓库中提交任何真实服务器地址、节点链接、口令、密钥（包括测试、示例、文档、环境变量默认值等）。
- **测试与文档占位规范**：测试与示例代码一律使用 RFC 文档专用保留地址（如 `203.0.113.x`、`198.51.100.x`、`192.0.2.x`、`2001:db8::/32`）或保留域名（如 `example.com`、`.example`、`.test`、`localhost`）。
- **真实参数传递规范**：需要连接真实服务器的测试或示例工具，真实参数只能经环境变量传入且**严禁设置任何公网默认值**（缺失时明确提示用法并以非零退出码退出）。
- **CI 门禁与白名单维护**：CI 中的 `bash scripts/check-no-real-endpoints.sh` 为硬门禁。若因业务/测试需要新增合法的公网地址（如公共 DNS、云元数据 IP），必须同步更新 `scripts/endpoint-allowlist.txt` 并注明用途与技术理由。
