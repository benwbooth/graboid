# Graboid API Reference

This document describes the HTTP/SSE API exposed by Graboid for external integrations.

## Base URL

- Default local server: `http://127.0.0.1:6749`
- OpenAPI JSON: `/api/openapi.json`
- Human docs page: `/api/docs`

## Authentication

Graboid uses two auth modes:

1. Session-cookie auth (UI/admin endpoints)
2. API-key auth (`/api/v1/*` endpoints)

API key can be provided either way:

- Header: `X-API-Key: <key>`
- Query: `?api_key=<key>`

If API key auth is enabled and missing/invalid:

- Missing key: `401`
- Invalid key: `403`

## Common Data Conventions

- IDs: UUID strings for jobs.
- Time fields: RFC3339/ISO-8601 UTC timestamps.
- `progress_percent`: float in `[0,100]` (heuristic progress from the runner/agent pipeline).
- JSON content type: `application/json` unless noted.

## Error Format

Most API errors return:

```json
{
  "error": "message",
  "detail": "message"
}
```

## Core Schemas

### CreateJobRequest

```json
{
  "prompt": "string (required)",
  "source_url": "string",
  "credential_name": "string|null",
  "file_filter": ["glob", "glob"],
  "destination_path": "string",
  "file_operation": "copy",
  "priority": 0,
  "local_read_whitelist": ["/abs/read/path", "./relative/read/path"],
  "local_write_whitelist": ["/abs/write/path", "./relative/write/path"],
  "metadata": {}
}
```

`local_read_whitelist` and `local_write_whitelist` are optional per-job allowlist overrides.
When provided, they are merged with global config allowlists for that job only.

### Job

```json
{
  "id": "uuid",
  "created_at": "2026-02-08T12:34:56.000Z",
  "updated_at": "2026-02-08T12:35:10.000Z",
  "prompt": "...",
  "source_url": "...",
  "credential_name": null,
  "file_filter": [],
  "destination_path": "./downloads",
  "file_operation": "copy",
  "priority": 0,
  "status": "pending|running|browsing|downloading|extracting|copying|complete|failed|cancelled",
  "current_phase": "init|browse|download|extract|copy|done",
  "progress_percent": 42.5,
  "progress_message": "Browsing: ...",
  "found_urls": [],
  "downloaded_files": [],
  "final_paths": [],
  "error_message": "",
  "metadata": {}
}
```

### JobStepDetail

```json
{
  "step_number": 12,
  "action": "Navigate",
  "observation": "Navigate to https://...",
  "url": "https://...",
  "timestamp": "2026-02-08T12:35:01.000Z",
  "is_error": false,
  "screenshot_base64": "... or null",
  "notes": [],
  "claude_messages": ["full agent output line", "..."]
}
```

### JobLogEntry

```json
{
  "id": 123,
  "job_id": "uuid",
  "timestamp": "2026-02-08T12:35:01.000Z",
  "level": "INFO|DEBUG|WARNING|ERROR",
  "source": "component name",
  "message": "text"
}
```

## Public (No API Key Required)

### `GET /health`

Health probe.

Response example:

```json
{ "status": "ok" }
```

### `GET /api/openapi.json`

Returns the OpenAPI 3.1 document.

### `GET /api/docs`

Returns a static HTML API doc page.

### `GET /api/status`

Runtime/build status used by the UI.

Response fields:

- `is_running: bool`
- `task: string`
- `downloads: number`
- `message_count: number`
- `git.backend` and `git.frontend` build stamp objects (`hash`, `timestamp`, `tz`, `epoch`)

### `GET /api/logs`

Global recent logs (not scoped to one job).

Query params:

- `limit` (default `100`, max `2000`)
- `level` (optional)
- `search` (optional)

Response:

```json
{ "logs": [ ... ] }
```

### `GET /api/notes/stats`

Note store aggregate stats.

### `GET /api/ollama/models`

Returns discovered Ollama model names.

Response:

```json
{ "models": ["model1", "model2"] }
```

### `GET /api/claude/models`

Returns discovered/fallback Claude model names.

Response:

```json
{ "models": ["sonnet", "opus", "..."] }
```

## Session-Cookie Endpoints (UI/Admin)

These require an authenticated browser session cookie (login at `/login`).

### `POST /api/config`

Persists config form fields.

- Body: `application/x-www-form-urlencoded`
- Response: `{ "success": true }`

### `GET /api/fs/list`

Lists directories for UI path pickers.

Query params:

- `path` (optional)

Response:

```json
{
  "path": "/absolute/path",
  "parent": "/absolute/parent or null",
  "directories": [
    { "name": "downloads", "path": "/absolute/path/downloads" }
  ]
}
```

### `POST /api/test/torrent`

Tests torrent client connectivity based on form values.

- Body: `application/x-www-form-urlencoded`
- Response always JSON, e.g.:

```json
{ "success": true, "message": "Connected ..." }
```

or

```json
{ "success": false, "error": "..." }
```

### `POST /api/test/llm`

Tests selected LLM provider/model.

- Body: `application/x-www-form-urlencoded`
- Response: `{ "success": bool, "message"?: string, "error"?: string }`

## API-Key Endpoints (`/api/v1/*`)

### `POST /api/v1/jobs`

Creates and enqueues a job.

Request body: `CreateJobRequest`

Response: `Job`

### `GET /api/v1/jobs`

Lists jobs.

Query params:

- `status` (optional)
- `limit` (default `50`, max `1000`)
- `offset` (default `0`)

Response:

```json
{
  "jobs": [ { "...": "Job" } ],
  "total": 123,
  "offset": 0,
  "limit": 50
}
```

Ordering note: jobs are returned newest-first (descending by creation time/id in current implementation).

### `GET /api/v1/jobs/{job_id}`

Returns one `Job`.

### `DELETE /api/v1/jobs/{job_id}`

Cancels a job if still cancellable.

Response:

```json
{ "status": "cancelled", "job_id": "..." }
```

### `GET /api/v1/jobs/{job_id}/detail`

Returns one combined payload used by the UI.

Query params:

- `logs_limit` (default `500`, max `5000`)

Response:

```json
{
  "job": { "...": "Job" },
  "steps": [ { "...": "JobStepDetail" } ],
  "logs": [ { "...": "JobLogEntry" } ]
}
```

### `GET /api/v1/jobs/{job_id}/steps`

Returns raw step rows.

Response:

```json
{ "job_id": "...", "steps": [ ... ] }
```

### `GET /api/v1/jobs/{job_id}/steps/detail`

Returns enriched step details (includes screenshot and agent lines per step).

Response:

```json
{ "steps": [ { "...": "JobStepDetail" } ] }
```

### `GET /api/v1/jobs/{job_id}/screenshots`

Returns all screenshots for the job.

Response:

```json
{
  "job_id": "...",
  "screenshots": [
    {
      "id": 1,
      "timestamp": "...",
      "url": "...",
      "phase": "browse",
      "step_number": 12,
      "data_base64": "..."
    }
  ]
}
```

### `GET /api/v1/jobs/{job_id}/screenshots/latest`

Returns latest screenshot (or `null`).

Response:

```json
{ "job_id": "...", "screenshot": { "...": "screenshot object" } }
```

or

```json
{ "job_id": "...", "screenshot": null }
```

### `GET /api/v1/jobs/{job_id}/logs`

Returns job logs.

Query params:

- `limit` (default `500`, max `5000`)

Response:

```json
{ "job_id": "...", "logs": [ { "...": "JobLogEntry" } ] }
```

### `GET /api/v1/jobs/{job_id}/artifacts/{kind}/{index}`

Downloads one artifact as binary.

Path params:

- `kind`: `downloaded` or `final`
- `index`: zero-based item index

Response:

- `200` with `application/octet-stream` and attachment filename
- `400` when artifact points to a torrent placeholder (`torrent:...`)
- `404` when job/artifact/file is missing

### `GET /api/v1/jobs/{job_id}/stream` (SSE)

Progress-only stream.

Event types:

- `progress` with payload:

```json
{
  "job_id": "...",
  "status": "...",
  "phase": "...",
  "progress_percent": 37.0,
  "progress_message": "...",
  "updated_at": "..."
}
```

- `complete` with full `Job` payload when terminal

### `GET /api/v1/jobs/{job_id}/events` (SSE)

Full job event stream with initial snapshot.

Event types:

- `snapshot` (same shape as `/detail` response)
- `job_update` (full `Job`)
- `job_log` (`JobLogEntry`)
- `job_step` (raw step row)
- `job_screenshot` (screenshot object with `data_base64`)
- `complete` (full `Job`)
- `error` (only if initial snapshot build fails)

Recommended for integrations that need full parity with UI.

### `GET /api/v1/jobs/{job_id}/logs/stream` (SSE)

Logs-only stream.

Event types:

- `log` (`JobLogEntry`)
- `done` (terminal marker)

### `POST /api/v1/key/regenerate`

Regenerates API key and returns it.

Response:

```json
{ "api_key": "new-key" }
```

### `GET /api/v1/credentials`

Returns credential names.

Response:

```json
{ "credentials": ["name1", "name2"] }
```

### `POST /api/v1/credentials`

Creates/updates one credential.

Request body:

```json
{
  "name": "string",
  "username": "string",
  "password": "string",
  "metadata": {}
}
```

Response:

```json
{ "status": "created", "name": "..." }
```

### `DELETE /api/v1/credentials/{name}`

Deletes one credential.

Response:

```json
{ "status": "deleted", "name": "..." }
```

### `GET /api/v1/notes`

Lists notes used by source memory.

Query params:

- `domain` (optional)
- `note_type` (optional)

Response:

```json
{ "notes": [ ... ] }
```

## SSE Client Notes

- Set `Accept: text/event-stream`.
- Keep the HTTP connection open and parse event frames by `event:` + `data:`.
- Server sends keepalive events every ~10s.
- For robust consumers:
  - tolerate duplicate events
  - handle reconnect on disconnect
  - refetch `/api/v1/jobs/{job_id}/detail` after reconnect

## cURL Quickstart

Create job:

```bash
curl -sS -X POST http://127.0.0.1:6749/api/v1/jobs \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_API_KEY" \
  --data '{
    "prompt": "Find and download X",
    "source_url": "",
    "destination_path": "./downloads",
    "file_filter": [],
    "file_operation": "copy",
    "priority": 0,
    "metadata": {}
  }'
```

Tail full live events:

```bash
curl -N "http://127.0.0.1:6749/api/v1/jobs/JOB_ID/events?api_key=YOUR_API_KEY"
```

Fetch job detail snapshot:

```bash
curl -sS "http://127.0.0.1:6749/api/v1/jobs/JOB_ID/detail?api_key=YOUR_API_KEY"
```

## Compatibility Note

- The OpenAPI spec at `/api/openapi.json` is the machine-readable source of truth.
- This markdown is intended for integration/onboarding and is maintained to match current behavior.
