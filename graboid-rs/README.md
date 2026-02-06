# graboid-rs

Rust rewrite of the Graboid runtime.

## What it includes

- Axum HTTP API (`/api/v1/jobs`) for submit/list/get/cancel
- SQLite-backed job persistence (`jobs`, `job_logs`, `job_steps`)
- Async job queue with configurable concurrency
- Real-time updates over WebSocket (`/ws`) and SSE (`/api/v1/jobs/{id}/stream`)
- Claude CLI browser automation with selectable MCP backends:
  - `chrome` (managed chrome-devtools MCP)
  - `browser_use` (browser-use MCP, with auto-fallback to chrome on failure)
- HTTP download phase and destination copy/link phase
- Torrent integrations:
  - `qbittorrent`, `transmission`, `aria2`
  - optional embedded backend via `librqbit` feature

## Run

```bash
cd graboid-rs
cargo run
```

Server default bind address: `0.0.0.0:8000`

## Config

Config is loaded from (first match wins):

1. `graboid-rs.toml`
2. `config.toml` (`[graboid_rs]` or `[rust]` section)
3. env vars (`GRABOID_RS_*`)

Main settings:

- `GRABOID_RS_BIND_ADDR`
- `GRABOID_RS_DATABASE_PATH`
- `GRABOID_RS_DOWNLOAD_DIR`
- `GRABOID_RS_JOBS_MAX_CONCURRENT`
- `GRABOID_RS_DOWNLOAD_MAX_PARALLEL`
- `GRABOID_RS_CLAUDE_CMD`
- `GRABOID_RS_CLAUDE_MODEL`
- `GRABOID_RS_API_KEY`
- `GRABOID_RS_CHROME_DEBUG_PORT`
- `GRABOID_RS_BROWSER_MODE`
- `GRABOID_RS_BROWSER_USE_MCP_COMMAND`
- `GRABOID_RS_BROWSER_USE_MCP_ARGS`
- `GRABOID_RS_CLAUDE_TIMEOUT_SECONDS`
- `GRABOID_RS_DOWNLOAD_TIMEOUT_SECONDS`

## Optional Features

- Enable embedded torrents with `librqbit`:

```bash
cargo run --features librqbit-embedded
```

## Nix

From repo root:

```bash
nix develop
cargo run --manifest-path graboid-rs/Cargo.toml
```
