use std::collections::{BTreeMap, HashMap, HashSet};
use std::convert::Infallible;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_stream::stream;
use axum::extract::ws::{Message, WebSocket};
use axum::extract::{Form, Path, Query, State, WebSocketUpgrade};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use cookie::time::Duration as CookieDuration;
use futures::{SinkExt, Stream, StreamExt};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::Sha256;
use tokio::process::Command;
use tokio::sync::{Mutex, broadcast};
use tracing::{debug, warn};

use crate::config::{
    build_flat_config_from_form, generate_api_key, load_config_flat_json, persist_api_key,
    persist_flat_config,
};
use crate::events::ServerEvent;
use crate::models::{CreateJobRequest, Job, JobListResponse, JobStatus, JobStepDetail};
use crate::state::AppState;
use crate::torrent;
use crate::ui::{self, RequestContext};

const SESSION_COOKIE_NAME: &str = "graboid_session";

type HmacSha256 = Hmac<Sha256>;

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/login", get(login_page).post(login_submit))
        .route("/logout", get(logout))
        .route("/", get(index_page))
        .route("/config", get(config_page).post(config_save))
        .route("/notes", get(notes_page))
        .route("/browser", get(browser_page))
        .route("/jobs", get(jobs_page))
        .route("/jobs/{job_id}", get(job_detail_page))
        .route(
            "/jobs/{job_id}/artifacts/{kind}/{index}",
            get(download_job_artifact),
        )
        .route("/jobs/submit", post(submit_job_form))
        .route("/jobs/{job_id}/cancel", post(cancel_job_form))
        .route("/jobs/{job_id}/requeue", post(requeue_job_form))
        .route("/ws", get(ws_upgrade))
        .route("/api/status", get(api_status))
        .route("/api/config", post(api_config_save))
        .route("/api/fs/list", get(api_fs_list))
        .route("/api/test/torrent", post(api_test_torrent))
        .route("/api/test/torznab", post(api_test_torznab))
        .route("/api/test/llm", post(api_test_llm))
        .route("/api/llm/models", get(api_llm_models))
        .route("/api/ollama/models", get(api_ollama_models))
        .route("/api/claude/models", get(api_claude_models))
        .route("/api/notes/stats", get(api_notes_stats))
        .route("/api/logs", get(api_logs))
        .route("/api/openapi.json", get(api_openapi_json))
        .route("/api/docs", get(api_docs_page))
        .route("/api/v1/jobs", post(create_job).get(list_jobs))
        .route("/api/v1/jobs/{job_id}", get(get_job).delete(cancel_job))
        .route("/api/v1/jobs/{job_id}/detail", get(get_job_detail))
        .route("/api/v1/jobs/{job_id}/stream", get(stream_job))
        .route("/api/v1/jobs/{job_id}/events", get(stream_job_events))
        .route(
            "/api/v1/jobs/{job_id}/screenshots",
            get(get_job_screenshots),
        )
        .route(
            "/api/v1/jobs/{job_id}/screenshots/latest",
            get(get_job_latest_screenshot),
        )
        .route("/api/v1/jobs/{job_id}/steps", get(get_job_steps))
        .route(
            "/api/v1/jobs/{job_id}/steps/detail",
            get(get_job_steps_detail),
        )
        .route(
            "/api/v1/jobs/{job_id}/artifacts/{kind}/{index}",
            get(api_download_job_artifact),
        )
        .route("/api/v1/jobs/{job_id}/logs", get(get_job_logs))
        .route("/api/v1/jobs/{job_id}/logs/stream", get(stream_job_logs))
        .route("/api/v1/key/regenerate", post(regenerate_api_key))
        .route(
            "/api/v1/credentials",
            get(list_credentials).post(create_credential),
        )
        .route("/api/v1/credentials/{name}", delete(delete_credential))
        .route("/api/v1/notes", get(get_notes))
        .with_state(state)
}

async fn health() -> impl IntoResponse {
    Json(json!({"status": "ok"}))
}

async fn login_page(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Query(query): Query<HashMap<String, String>>,
) -> Result<Response, ApiError> {
    if current_user(&jar, &state).is_some() {
        return Ok(Redirect::to("/").into_response());
    }

    let page = ui::render_login_page(query.contains_key("error"));
    Ok(Html(page).into_response())
}

#[derive(Debug, Deserialize)]
struct LoginForm {
    username: String,
    password: String,
}

async fn login_submit(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Form(form): Form<LoginForm>,
) -> Result<Response, ApiError> {
    if form.username == state.auth.username && form.password == state.auth.password {
        let token = sign_session_token(&form.username, &state.auth.session_secret);
        let cookie = Cookie::build((SESSION_COOKIE_NAME, token))
            .path("/")
            .http_only(true)
            .same_site(SameSite::Lax)
            .max_age(CookieDuration::seconds(state.auth.session_max_age_seconds))
            .build();
        let jar = jar.add(cookie);
        return Ok((jar, Redirect::to("/")).into_response());
    }

    Ok(Redirect::to("/login?error=1").into_response())
}

async fn logout(jar: CookieJar) -> Result<Response, ApiError> {
    let jar = jar.remove(
        Cookie::build((SESSION_COOKIE_NAME, ""))
            .path("/")
            .max_age(CookieDuration::seconds(0))
            .build(),
    );
    Ok((jar, Redirect::to("/login")).into_response())
}

async fn index_page(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Query(query): Query<HashMap<String, String>>,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    if current_user(&jar, &state).is_none() {
        return Ok(Redirect::to("/login").into_response());
    }
    let runtime = runtime_badge(&state).await;

    let request = request_context(&uri, &headers, &query);
    let page = ui::render_index_page(&request, &state.git_info, &runtime);
    Ok(Html(page).into_response())
}

async fn config_page(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Query(query): Query<HashMap<String, String>>,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    if current_user(&jar, &state).is_none() {
        return Ok(Redirect::to("/login").into_response());
    }

    let config_map = load_config_flat_json(&state.config_path);
    let runtime = runtime_badge(&state).await;
    let request = request_context(&uri, &headers, &query);
    let config_path_display = display_config_path(&state.config_path);
    let page = ui::render_config_page(
        &request,
        &state.git_info,
        &runtime,
        &config_map,
        &config_path_display,
    );
    Ok(Html(page).into_response())
}

async fn config_save(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Form(form): Form<HashMap<String, String>>,
) -> Result<Response, ApiError> {
    if current_user(&jar, &state).is_none() {
        return Ok(Redirect::to("/login").into_response());
    }

    let flat = build_flat_config_from_form(&form);
    persist_flat_config(&state.config_path, &flat).map_err(ApiError::internal)?;
    Ok(Redirect::to("/config?saved=1").into_response())
}

async fn api_config_save(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Form(form): Form<HashMap<String, String>>,
) -> Result<Json<Value>, ApiError> {
    if current_user(&jar, &state).is_none() {
        return Err(ApiError::new(StatusCode::UNAUTHORIZED, "Not authenticated"));
    }

    let flat = build_flat_config_from_form(&form);
    persist_flat_config(&state.config_path, &flat).map_err(ApiError::internal)?;
    Ok(Json(json!({"success": true})))
}

#[derive(Debug, Deserialize)]
struct FsListQuery {
    path: Option<String>,
}

fn config_base_dir(state: &AppState) -> PathBuf {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let Some(parent) = state.config_path.parent() else {
        return cwd;
    };
    if parent.as_os_str().is_empty() {
        return cwd;
    }
    if parent.is_absolute() {
        parent.to_path_buf()
    } else {
        cwd.join(parent)
    }
}

async fn api_fs_list(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Query(query): Query<FsListQuery>,
) -> Result<Json<Value>, ApiError> {
    if current_user(&jar, &state).is_none() {
        return Err(ApiError::new(StatusCode::UNAUTHORIZED, "Not authenticated"));
    }

    let requested = query
        .path
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(&state.config.download_dir);

    let mut root = PathBuf::from(requested);
    if !root.is_absolute() {
        root = config_base_dir(state.as_ref()).join(root);
    }

    let mut canonical = tokio::fs::canonicalize(&root)
        .await
        .unwrap_or_else(|_| root.clone());

    let metadata = tokio::fs::metadata(&canonical).await;
    match metadata {
        Ok(meta) if meta.is_dir() => {}
        _ => {
            if let Some(parent) = canonical.parent() {
                canonical = parent.to_path_buf();
            }
        }
    }

    let canonical = tokio::fs::canonicalize(&canonical)
        .await
        .unwrap_or(canonical);
    let meta = tokio::fs::metadata(&canonical)
        .await
        .map_err(|_| ApiError::bad_request("Path is not readable"))?;
    if !meta.is_dir() {
        return Err(ApiError::bad_request("Path is not a directory"));
    }
    let mut read_dir = tokio::fs::read_dir(&canonical)
        .await
        .map_err(ApiError::internal)?;

    let mut directories = Vec::<(String, String)>::new();
    while let Some(entry) = read_dir.next_entry().await.map_err(ApiError::internal)? {
        let path = entry.path();
        let entry_meta = entry.metadata().await.map_err(ApiError::internal)?;
        if !entry_meta.is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        directories.push((name, path.display().to_string()));
    }
    directories.sort_by(|left, right| {
        left.0
            .to_ascii_lowercase()
            .cmp(&right.0.to_ascii_lowercase())
    });

    let payload = directories
        .into_iter()
        .map(|(name, path)| json!({"name": name, "path": path}))
        .collect::<Vec<_>>();

    let parent = canonical
        .parent()
        .map(|candidate| candidate.display().to_string());

    Ok(Json(json!({
        "path": canonical.display().to_string(),
        "parent": parent,
        "directories": payload,
    })))
}

async fn notes_page(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Query(query): Query<HashMap<String, String>>,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    if current_user(&jar, &state).is_none() {
        return Ok(Redirect::to("/login").into_response());
    }

    let stats = state.db.note_stats().await?;
    let domains = state.db.list_note_domains().await?;
    let mut domain_notes = BTreeMap::new();
    for domain in &domains {
        let notes = state.db.list_notes_for_domain(domain).await?;
        domain_notes.insert(domain.clone(), notes);
    }

    let runtime = runtime_badge(&state).await;
    let request = request_context(&uri, &headers, &query);
    let page = ui::render_notes_page(
        &request,
        &state.git_info,
        &runtime,
        &stats,
        &domains,
        &domain_notes,
    );
    Ok(Html(page).into_response())
}

async fn browser_page(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Query(query): Query<HashMap<String, String>>,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    if current_user(&jar, &state).is_none() {
        return Ok(Redirect::to("/login").into_response());
    }
    let runtime = runtime_badge(&state).await;
    let screenshot = state.runtime.screenshot().await;
    let messages = state.runtime.messages_tail(120).await;
    let request = request_context(&uri, &headers, &query);
    let page = ui::render_browser_page(&request, &state.git_info, &runtime, screenshot, &messages);
    Ok(Html(page).into_response())
}

async fn jobs_page(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Query(query): Query<HashMap<String, String>>,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    if current_user(&jar, &state).is_none() {
        return Ok(Redirect::to("/login").into_response());
    }

    let offset = query
        .get("offset")
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(0)
        .max(0);
    let limit = query
        .get("limit")
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(50)
        .clamp(1, 200);

    let jobs = state.db.list_jobs(None, limit, offset).await?;
    let total = state.db.count_jobs(None).await?;
    let api_key = state.api_key.read().await.clone();
    let runtime = runtime_badge(&state).await;
    let request = request_context(&uri, &headers, &query);
    let page = ui::render_jobs_page(
        &request,
        &state.git_info,
        &runtime,
        &api_key,
        &jobs,
        total,
        offset,
        limit,
        query.get("msg").map(String::as_str),
    );
    Ok(Html(page).into_response())
}

async fn job_detail_page(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Path(job_id): Path<String>,
    Query(query): Query<HashMap<String, String>>,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    if current_user(&jar, &state).is_none() {
        return Ok(Redirect::to("/login").into_response());
    }

    let Some(job) = state.db.get_job(&job_id).await? else {
        return Ok(Redirect::to("/jobs?msg=error:not-found").into_response());
    };

    let steps = build_job_step_details(&state, &job_id).await?;
    let logs = state.db.list_logs(&job_id, 500).await?;
    let api_key = state.api_key.read().await.clone();
    let runtime = runtime_badge(&state).await;
    let request = request_context(&uri, &headers, &query);

    let page = ui::render_job_detail_page(
        &request,
        &state.git_info,
        &runtime,
        &api_key,
        &job,
        &steps,
        &logs,
    );
    Ok(Html(page).into_response())
}

async fn download_job_artifact(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Path((job_id, kind, index)): Path<(String, String, usize)>,
) -> Result<Response, ApiError> {
    if current_user(&jar, &state).is_none() {
        return Ok(Redirect::to("/login").into_response());
    }

    resolve_job_artifact_response(&state, &job_id, &kind, index).await
}

async fn api_download_job_artifact(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((job_id, kind, index)): Path<(String, String, usize)>,
    Query(query): Query<ApiKeyQuery>,
) -> Result<Response, ApiError> {
    verify_api_key(&headers, query.api_key.as_deref(), &state).await?;
    resolve_job_artifact_response(&state, &job_id, &kind, index).await
}

async fn resolve_job_artifact_response(
    state: &Arc<AppState>,
    job_id: &str,
    kind: &str,
    index: usize,
) -> Result<Response, ApiError> {
    let Some(job) = state.db.get_job(&job_id).await? else {
        return Err(ApiError::not_found("job not found"));
    };

    let stored_path = match kind {
        "downloaded" => job.downloaded_files.get(index),
        "final" => job.final_paths.get(index),
        _ => None,
    }
    .ok_or_else(|| ApiError::not_found("artifact not found"))?;

    if stored_path.starts_with("torrent:") {
        return Err(ApiError::bad_request(
            "torrent artifacts are not downloadable files",
        ));
    }

    let artifact_path = std::path::PathBuf::from(stored_path);
    let resolved = if artifact_path.is_absolute() {
        artifact_path
    } else {
        std::env::current_dir()
            .map_err(ApiError::internal)?
            .join(artifact_path)
    };

    let metadata = tokio::fs::metadata(&resolved)
        .await
        .map_err(|_| ApiError::not_found("artifact file missing"))?;
    if !metadata.is_file() {
        return Err(ApiError::not_found("artifact is not a file"));
    }

    let bytes = tokio::fs::read(&resolved)
        .await
        .map_err(ApiError::internal)?;
    let filename = resolved
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("artifact.bin")
        .replace(['"', '\\'], "_");

    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::header::HeaderValue::from_static("application/octet-stream"),
    );
    headers.insert(
        axum::http::header::CONTENT_DISPOSITION,
        axum::http::header::HeaderValue::from_str(&format!("attachment; filename=\"{filename}\""))
            .map_err(ApiError::internal)?,
    );

    Ok((headers, bytes).into_response())
}

async fn submit_job_form(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Form(form): Form<HashMap<String, String>>,
) -> Result<Response, ApiError> {
    if current_user(&jar, &state).is_none() {
        return Ok(Redirect::to("/login").into_response());
    }

    let prompt = form.get("prompt").map(|v| v.trim()).unwrap_or_default();
    if prompt.is_empty() {
        return Ok(Redirect::to("/jobs?msg=error:prompt-required").into_response());
    }

    let source_url = form
        .get("source_url")
        .map(String::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    let destination_path = form
        .get("destination_path")
        .map(String::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    let file_operation = form
        .get("file_operation")
        .cloned()
        .unwrap_or_else(|| "copy".to_string());
    let priority = form
        .get("priority")
        .and_then(|v| v.trim().parse::<i32>().ok())
        .unwrap_or(0);
    let file_filter = form
        .get("file_filter")
        .map(|raw| {
            raw.lines()
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(|v| v.to_string())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let payload = CreateJobRequest {
        prompt: prompt.to_string(),
        source_url,
        credential_name: None,
        file_filter,
        destination_path,
        file_operation,
        priority,
        metadata: Value::Object(Default::default()),
    };

    let job = Job::new(payload, &state.config.download_dir);
    state.db.create_job(&job).await?;
    state.runner.enqueue(job.id.clone()).await?;
    let _ = state.events.send(ServerEvent::JobUpdate(job));

    Ok(Redirect::to("/jobs?msg=submitted").into_response())
}

async fn cancel_job_form(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Path(job_id): Path<String>,
) -> Result<Response, ApiError> {
    if current_user(&jar, &state).is_none() {
        return Ok(Redirect::to("/login").into_response());
    }

    let cancelled = state.runner.cancel(&job_id).await?;
    if cancelled {
        Ok(Redirect::to("/jobs?msg=cancelled").into_response())
    } else {
        Ok(Redirect::to("/jobs?msg=error:not-found").into_response())
    }
}

async fn requeue_job_form(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Path(job_id): Path<String>,
) -> Result<Response, ApiError> {
    if current_user(&jar, &state).is_none() {
        return Ok(Redirect::to("/login").into_response());
    }

    let Some(original) = state.db.get_job(&job_id).await? else {
        return Ok(Redirect::to("/jobs?msg=error:not-found").into_response());
    };

    let payload = CreateJobRequest {
        prompt: original.prompt,
        source_url: original.source_url,
        credential_name: original.credential_name,
        file_filter: original.file_filter,
        destination_path: original.destination_path,
        file_operation: original.file_operation,
        priority: original.priority,
        metadata: original.metadata,
    };

    let job = Job::new(payload, &state.config.download_dir);
    state.db.create_job(&job).await?;
    state.runner.enqueue(job.id.clone()).await?;
    let _ = state.events.send(ServerEvent::JobUpdate(job));

    Ok(Redirect::to("/jobs?msg=requeued").into_response())
}

async fn api_status(State(state): State<Arc<AppState>>) -> Result<Json<Value>, ApiError> {
    let (is_running, current_task, downloads, message_count) =
        state.runtime.snapshot_status().await;
    let git_info = crate::state::GitInfo::capture(&state.project_root);
    Ok(Json(json!({
        "is_running": is_running,
        "task": current_task,
        "downloads": downloads,
        "message_count": message_count,
        "git": {
            "backend": git_info.backend,
            "frontend": git_info.frontend,
        },
    })))
}

async fn api_test_torrent(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Form(form): Form<HashMap<String, String>>,
) -> Result<Json<Value>, ApiError> {
    if current_user(&jar, &state).is_none() {
        return Ok(Json(
            json!({"success": false, "error": "Not authenticated"}),
        ));
    }

    let client_type = form
        .get("torrent_client")
        .map(String::as_str)
        .unwrap_or(state.config.torrent_client.as_str());

    match client_type {
        "embedded" | "auto" => {
            if torrent::embedded_backend_available() {
                Ok(Json(json!({
                    "success": true,
                    "message": torrent::embedded_backend_message()
                })))
            } else {
                Ok(Json(json!({
                    "success": false,
                    "error": torrent::embedded_backend_message()
                })))
            }
        }
        "deluge" => {
            let host = form
                .get("deluge_host")
                .cloned()
                .unwrap_or_else(|| state.config.deluge_host.clone());
            let port = form
                .get("deluge_port")
                .and_then(|v| v.parse::<u16>().ok())
                .unwrap_or(state.config.deluge_port);
            let username = form
                .get("deluge_username")
                .cloned()
                .unwrap_or_else(|| state.config.deluge_username.clone());
            let password = form
                .get("deluge_password")
                .cloned()
                .unwrap_or_else(|| state.config.deluge_password.clone());

            match test_deluge_console(&host, port, &username, &password).await {
                Ok(message) => Ok(Json(json!({"success": true, "message": message}))),
                Err(err) => Ok(Json(json!({"success": false, "error": err}))),
            }
        }
        "rtorrent" => {
            let url = form
                .get("rtorrent_url")
                .cloned()
                .unwrap_or_else(|| state.config.rtorrent_url.clone());

            match test_rtorrent(&url).await {
                Ok(message) => Ok(Json(json!({"success": true, "message": message}))),
                Err(err) => Ok(Json(json!({"success": false, "error": err}))),
            }
        }
        "qbittorrent" => {
            let host = form
                .get("qbittorrent_host")
                .cloned()
                .unwrap_or_else(|| state.config.qbittorrent_host.clone());
            let port = form
                .get("qbittorrent_port")
                .and_then(|v| v.parse::<u16>().ok())
                .unwrap_or(state.config.qbittorrent_port);
            let username = form
                .get("qbittorrent_username")
                .cloned()
                .unwrap_or_else(|| state.config.qbittorrent_username.clone());
            let password = form
                .get("qbittorrent_password")
                .cloned()
                .unwrap_or_else(|| state.config.qbittorrent_password.clone());

            match test_qbittorrent(&host, port, &username, &password).await {
                Ok(message) => Ok(Json(json!({"success": true, "message": message}))),
                Err(err) => Ok(Json(json!({"success": false, "error": err}))),
            }
        }
        "transmission" => {
            let host = form
                .get("transmission_host")
                .cloned()
                .unwrap_or_else(|| state.config.transmission_host.clone());
            let port = form
                .get("transmission_port")
                .and_then(|v| v.parse::<u16>().ok())
                .unwrap_or(state.config.transmission_port);
            let username = form
                .get("transmission_username")
                .cloned()
                .unwrap_or_else(|| state.config.transmission_username.clone());
            let password = form
                .get("transmission_password")
                .cloned()
                .unwrap_or_else(|| state.config.transmission_password.clone());

            match test_transmission(&host, port, &username, &password).await {
                Ok(message) => Ok(Json(json!({"success": true, "message": message}))),
                Err(err) => Ok(Json(json!({"success": false, "error": err}))),
            }
        }
        "aria2" => {
            let host = form
                .get("aria2_host")
                .cloned()
                .unwrap_or_else(|| state.config.aria2_host.clone());
            let port = form
                .get("aria2_port")
                .and_then(|v| v.parse::<u16>().ok())
                .unwrap_or(state.config.aria2_port);
            let secret = form
                .get("aria2_secret")
                .cloned()
                .unwrap_or_else(|| state.config.aria2_secret.clone());

            match test_aria2(&host, port, &secret).await {
                Ok(message) => Ok(Json(json!({"success": true, "message": message}))),
                Err(err) => Ok(Json(json!({"success": false, "error": err}))),
            }
        }
        unsupported => Ok(Json(json!({
            "success": false,
            "error": format!("Test not implemented for {unsupported}")
        }))),
    }
}

async fn api_test_torznab(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Form(form): Form<HashMap<String, String>>,
) -> Result<Json<Value>, ApiError> {
    if current_user(&jar, &state).is_none() {
        return Ok(Json(
            json!({"success": false, "error": "Not authenticated"}),
        ));
    }

    let mut cfg = state.config.as_ref().clone();
    if let Some(value) = form.get("torznab_endpoint") {
        cfg.torznab_endpoint = value.trim().to_string();
    }
    if let Some(value) = form.get("torznab_api_key") {
        cfg.torznab_api_key = value.trim().to_string();
    }
    if let Some(value) = form.get("torznab_categories") {
        cfg.torznab_categories = value.trim().to_string();
    }
    if let Some(value) = form.get("torznab_max_results") {
        cfg.torznab_max_results = value
            .trim()
            .parse::<usize>()
            .ok()
            .unwrap_or(30)
            .clamp(1, 200);
    }
    cfg.torznab_enabled = form.contains_key("torznab_enabled");
    if !cfg.torznab_enabled && !cfg.torznab_endpoint.trim().is_empty() {
        cfg.torznab_enabled = true;
    }

    if cfg.torznab_endpoint.trim().is_empty() {
        return Ok(Json(
            json!({"success": false, "error": "Torznab endpoint URL is required"}),
        ));
    }

    let test_query = "ubuntu";
    let categories = cfg.torznab_categories.trim().to_string();
    let has_categories = !categories.is_empty();
    match torrent::search_torznab_fresh(&cfg, test_query).await {
        Ok(results) if results.is_empty() => Ok(Json(json!({
            "success": false,
            "error": if has_categories {
                match {
                    let mut no_category_cfg = cfg.clone();
                    no_category_cfg.torznab_categories.clear();
                    torrent::search_torznab_fresh(&no_category_cfg, test_query).await
                } {
                    Ok(no_cat_results) if !no_cat_results.is_empty() => format!(
                        "Torznab returned 0 results for '{test_query}' with categories '{}', but found {} result(s) without categories. Your category filter is likely too restrictive.",
                        categories,
                        no_cat_results.len()
                    ),
                    Ok(_) => format!(
                        "Torznab reachable but returned 0 results for '{test_query}' (with and without categories). Check indexers/API key/network."
                    ),
                    Err(err) => format!(
                        "Torznab returned 0 results with categories '{}'; retry without categories failed: {}",
                        categories,
                        err
                    ),
                }
            } else {
                format!(
                    "Torznab reachable but returned 0 results for '{test_query}'. Check indexers/API key/network."
                )
            }
        }))),
        Ok(results) => {
            let top = results
                .first()
                .map(|item| truncate(&item.title, 72))
                .unwrap_or_else(|| "-".to_string());
            let message = format!(
                "Connected. {} result(s) for '{test_query}'. Top: {}",
                results.len(),
                top
            );
            Ok(Json(json!({"success": true, "message": message})))
        }
        Err(err) => Ok(Json(json!({
            "success": false,
            "error": format!("Torznab test failed: {err}")
        }))),
    }
}

async fn api_test_llm(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Form(form): Form<HashMap<String, String>>,
) -> Result<Json<Value>, ApiError> {
    if current_user(&jar, &state).is_none() {
        return Ok(Json(
            json!({"success": false, "error": "Not authenticated"}),
        ));
    }

    let provider = normalize_llm_provider(
        form.get("llm_provider")
            .map(String::as_str)
            .unwrap_or(state.config.llm_provider.as_str()),
    );
    let model = form
        .get("llm_model")
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| state.config.llm_model.clone());

    if provider == "claude_code" || provider == "anthropic" {
        let mut cmd = Command::new(&state.config.claude_cmd);
        cmd.arg("-p")
            .arg("Respond with exactly: OK")
            .arg("--model")
            .arg(&model);

        match tokio::time::timeout(Duration::from_secs(30), cmd.output()).await {
            Ok(Ok(output)) if output.status.success() => {
                let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
                let msg = if stdout.is_empty() {
                    format!("Claude Code ({model}) connected")
                } else {
                    format!(
                        "Claude Code ({model}) connected. Response: {}",
                        truncate(&stdout, 60)
                    )
                };
                return Ok(Json(json!({"success": true, "message": msg})));
            }
            Ok(Ok(output)) => {
                let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
                return Ok(Json(
                    json!({"success": false, "error": format!("Claude exited non-zero: {}", truncate(&stderr, 120))}),
                ));
            }
            Ok(Err(err)) => {
                return Ok(Json(json!({"success": false, "error": err.to_string()})));
            }
            Err(_) => {
                return Ok(Json(
                    json!({"success": false, "error": "Claude test timed out after 30 seconds"}),
                ));
            }
        }
    }

    if matches!(
        provider.as_str(),
        "openai" | "openrouter" | "google" | "ollama"
    ) {
        return Ok(run_codex_llm_test(&state, &form, &provider, &model).await);
    }

    Ok(Json(json!({
        "success": false,
        "error": format!("Unknown provider: {provider}")
    })))
}

fn normalize_llm_provider(raw: &str) -> String {
    let normalized = raw.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        "claude_code".to_string()
    } else {
        normalized
    }
}

async fn run_codex_llm_test(
    state: &Arc<AppState>,
    form: &HashMap<String, String>,
    provider: &str,
    model: &str,
) -> Json<Value> {
    let mut cmd = Command::new("codex");
    cmd.arg("exec")
        .arg("--json")
        .arg("--disable")
        .arg("shell_tool")
        .arg("-m")
        .arg(model)
        .arg("Respond with exactly: OK")
        .stdin(std::process::Stdio::null());

    if let Err(message) = configure_codex_test_provider(&mut cmd, state, form, provider) {
        return Json(json!({"success": false, "error": message}));
    }

    match tokio::time::timeout(Duration::from_secs(45), cmd.output()).await {
        Ok(Ok(output)) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let response = extract_last_codex_agent_message(&stdout);
            let message = if let Some(text) = response {
                format!(
                    "Codex ({provider}, {model}) connected. Response: {}",
                    truncate(&text, 72)
                )
            } else {
                format!("Codex ({provider}, {model}) connected")
            };
            Json(json!({"success": true, "message": message}))
        }
        Ok(Ok(output)) => {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            Json(json!({
                "success": false,
                "error": format!("Codex exited non-zero: {}", truncate(&stderr, 140)),
            }))
        }
        Ok(Err(err)) => Json(json!({"success": false, "error": err.to_string()})),
        Err(_) => Json(json!({"success": false, "error": "Codex test timed out after 45 seconds"})),
    }
}

fn configure_codex_test_provider(
    cmd: &mut Command,
    state: &Arc<AppState>,
    form: &HashMap<String, String>,
    provider: &str,
) -> Result<(), String> {
    match provider {
        "openai" => {
            std::env::var("OPENAI_API_KEY")
                .map_err(|_| "Missing OPENAI_API_KEY environment variable".to_string())?;
        }
        "openrouter" => {
            let key = std::env::var("OPENROUTER_API_KEY")
                .map_err(|_| "Missing OPENROUTER_API_KEY environment variable".to_string())?;
            cmd.env("OPENAI_API_KEY", key)
                .env("OPENAI_BASE_URL", "https://openrouter.ai/api/v1");
        }
        "google" => {
            let key = std::env::var("GOOGLE_API_KEY")
                .map_err(|_| "Missing GOOGLE_API_KEY environment variable".to_string())?;
            cmd.env("OPENAI_API_KEY", key).env(
                "OPENAI_BASE_URL",
                "https://generativelanguage.googleapis.com/v1beta/openai",
            );
        }
        "ollama" => {
            cmd.arg("--oss").arg("--local-provider").arg("ollama");
            let host = form
                .get("ollama_host")
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| state.config.ollama_host.clone());
            if !host.trim().is_empty() {
                cmd.env("OLLAMA_BASE_URL", host);
            }
        }
        other => {
            return Err(format!("Unsupported Codex provider: {other}"));
        }
    }

    Ok(())
}

fn extract_last_codex_agent_message(stdout: &str) -> Option<String> {
    for line in stdout.lines().rev() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Ok(value) = serde_json::from_str::<Value>(trimmed) else {
            continue;
        };
        let Some(item) = value.get("item") else {
            continue;
        };
        if item.get("type").and_then(Value::as_str) != Some("agent_message") {
            continue;
        }
        if let Some(text) = item.get("text").and_then(Value::as_str) {
            let text = text.trim();
            if !text.is_empty() {
                return Some(text.to_string());
            }
        }
    }
    None
}

#[derive(Debug, Deserialize)]
struct LlmModelsQuery {
    provider: Option<String>,
}

async fn api_llm_models(
    State(state): State<Arc<AppState>>,
    Query(query): Query<LlmModelsQuery>,
) -> Result<Json<Value>, ApiError> {
    let provider = normalize_llm_provider(
        query
            .provider
            .as_deref()
            .unwrap_or(state.config.llm_provider.as_str()),
    );
    let models = provider_models(&state, &provider).await;
    Ok(Json(json!({"provider": provider, "models": models})))
}

fn static_model_suggestions(provider: &str) -> Vec<String> {
    match provider {
        "claude_code" | "anthropic" => vec![
            "sonnet".to_string(),
            "opus".to_string(),
            "haiku".to_string(),
            "claude-opus-4-5-20251101".to_string(),
            "claude-sonnet-4-20250514".to_string(),
            "claude-haiku-3-5-20241022".to_string(),
        ],
        "openai" => vec![
            "gpt-4o".to_string(),
            "gpt-4.1".to_string(),
            "o3".to_string(),
            "o3-mini".to_string(),
        ],
        "google" => vec!["gemini-2.0-flash".to_string(), "gemini-2.0-pro".to_string()],
        "openrouter" => vec![
            "anthropic/claude-sonnet-4".to_string(),
            "openai/gpt-4o".to_string(),
            "google/gemini-2.0-flash-001".to_string(),
        ],
        "ollama" => vec![
            "llama3.3".to_string(),
            "qwen2.5-coder".to_string(),
            "deepseek-r1".to_string(),
        ],
        _ => Vec::new(),
    }
}

fn dedupe_model_values(models: Vec<String>) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for model in models {
        let trimmed = model.trim();
        if trimmed.is_empty() {
            continue;
        }
        let key = trimmed.to_ascii_lowercase();
        if seen.insert(key) {
            out.push(trimmed.to_string());
        }
    }
    out
}

async fn provider_models(state: &Arc<AppState>, provider: &str) -> Vec<String> {
    let mut models = match provider {
        "claude_code" | "anthropic" => fetch_claude_model_ids(state).await,
        "ollama" => fetch_ollama_model_ids(&state.config.ollama_host).await,
        "openai" => {
            if let Ok(key) = std::env::var("OPENAI_API_KEY") {
                fetch_openai_compatible_model_ids("https://api.openai.com/v1/models", Some(&key))
                    .await
            } else {
                Vec::new()
            }
        }
        "openrouter" => {
            let key = std::env::var("OPENROUTER_API_KEY").ok();
            fetch_openai_compatible_model_ids("https://openrouter.ai/api/v1/models", key.as_deref())
                .await
        }
        "google" => {
            if let Ok(key) = std::env::var("GOOGLE_API_KEY") {
                fetch_google_model_ids(&key).await
            } else {
                Vec::new()
            }
        }
        _ => Vec::new(),
    };
    models.extend(static_model_suggestions(provider));
    dedupe_model_values(models)
}

async fn fetch_openai_compatible_model_ids(url: &str, bearer_token: Option<&str>) -> Vec<String> {
    let client = reqwest::Client::new();
    let mut request = client.get(url).timeout(Duration::from_secs(10));
    if let Some(token) = bearer_token {
        request = request.bearer_auth(token);
    }
    let Ok(response) = request.send().await else {
        return Vec::new();
    };
    if !response.status().is_success() {
        return Vec::new();
    }
    let Ok(json) = response.json::<Value>().await else {
        return Vec::new();
    };
    json.get("data")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|entry| {
                    entry
                        .get("id")
                        .and_then(Value::as_str)
                        .or_else(|| entry.get("name").and_then(Value::as_str))
                })
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

async fn fetch_google_model_ids(api_key: &str) -> Vec<String> {
    let Ok(url) = reqwest::Url::parse_with_params(
        "https://generativelanguage.googleapis.com/v1beta/models",
        &[("key", api_key)],
    ) else {
        return Vec::new();
    };
    let Ok(response) = reqwest::Client::new()
        .get(url)
        .timeout(Duration::from_secs(10))
        .send()
        .await
    else {
        return Vec::new();
    };
    if !response.status().is_success() {
        return Vec::new();
    }
    let Ok(json) = response.json::<Value>().await else {
        return Vec::new();
    };
    json.get("models")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|entry| entry.get("name").and_then(Value::as_str))
                .map(|raw| raw.strip_prefix("models/").unwrap_or(raw).to_string())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

async fn fetch_ollama_model_ids(host: &str) -> Vec<String> {
    let url = format!("{host}/api/tags");
    let Ok(response) = reqwest::Client::new()
        .get(url)
        .timeout(Duration::from_secs(5))
        .send()
        .await
    else {
        return Vec::new();
    };
    if !response.status().is_success() {
        return Vec::new();
    }
    let Ok(json) = response.json::<Value>().await else {
        return Vec::new();
    };
    json.get("models")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|m| m.get("name").and_then(Value::as_str).map(str::to_string))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

async fn fetch_claude_model_ids(state: &Arc<AppState>) -> Vec<String> {
    let mut cmd = Command::new(&state.config.claude_cmd);
    cmd.arg("-p")
        .arg("List available Claude model IDs as comma-separated values only.");

    let output = tokio::time::timeout(Duration::from_secs(60), cmd.output()).await;
    let Ok(Ok(output)) = output else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }
    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    text.split(',')
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>()
}

async fn api_ollama_models(State(state): State<Arc<AppState>>) -> Result<Json<Value>, ApiError> {
    let mut models = fetch_ollama_model_ids(&state.config.ollama_host).await;
    models.extend(static_model_suggestions("ollama"));
    Ok(Json(json!({"models": dedupe_model_values(models)})))
}

async fn api_claude_models(State(state): State<Arc<AppState>>) -> Result<Json<Value>, ApiError> {
    let mut models = fetch_claude_model_ids(&state).await;
    models.extend(static_model_suggestions("claude_code"));
    Ok(Json(json!({"models": dedupe_model_values(models)})))
}

async fn api_notes_stats(State(state): State<Arc<AppState>>) -> Result<Json<Value>, ApiError> {
    let stats = state.db.note_stats().await?;
    Ok(Json(
        serde_json::to_value(stats).unwrap_or_else(|_| json!({})),
    ))
}

#[derive(Debug, Deserialize)]
struct GlobalLogQuery {
    limit: Option<usize>,
    level: Option<String>,
    search: Option<String>,
}

async fn api_logs(
    State(state): State<Arc<AppState>>,
    Query(query): Query<GlobalLogQuery>,
) -> Result<Json<Value>, ApiError> {
    let limit = query.limit.unwrap_or(100).clamp(1, 2000);
    let mut logs = state
        .runtime
        .global_logs(limit, query.level.as_deref(), query.search.as_deref())
        .await;

    if logs.is_empty() {
        let fallback = state
            .db
            .list_recent_logs(
                limit as i64,
                query.level.as_deref(),
                query.search.as_deref(),
            )
            .await
            .unwrap_or_default();
        logs = fallback
            .into_iter()
            .map(|entry| crate::state::GlobalLogRecord {
                time: entry.timestamp.timestamp_millis() as f64 / 1000.0,
                level: entry.level,
                name: entry.source,
                message: entry.message,
            })
            .collect();
    }

    Ok(Json(json!({"logs": logs})))
}

async fn api_openapi_json() -> Json<Value> {
    Json(build_openapi_spec())
}

async fn api_docs_page() -> Html<String> {
    let spec_pretty =
        serde_json::to_string_pretty(&build_openapi_spec()).unwrap_or_else(|_| "{}".to_string());
    let escaped_spec = escape_html_text(&spec_pretty);
    let html = format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Graboid API Docs</title>
  <style>
    body {{ font-family: ui-sans-serif, system-ui, sans-serif; margin: 2rem; background: #0b1020; color: #e7ecf5; }}
    h1, h2 {{ margin: 0 0 .75rem; }}
    p, li {{ line-height: 1.45; }}
    a {{ color: #8ec7ff; }}
    code, pre {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }}
    .card {{ border: 1px solid #2e405f; border-radius: 10px; padding: 1rem; margin-bottom: 1rem; background: #121d34; }}
    pre {{ overflow: auto; max-height: 520px; padding: .75rem; background: #0a162b; border-radius: 8px; border: 1px solid #24395b; }}
  </style>
</head>
<body>
  <h1>Graboid API</h1>
  <div class="card">
    <p>OpenAPI spec JSON: <a href="/api/openapi.json"><code>/api/openapi.json</code></a></p>
    <p>Human docs: <code>/api/docs</code></p>
    <p>Primary live stream endpoint: <code>/api/v1/jobs/{{job_id}}/events</code> (SSE)</p>
    <p>Auth: pass API key via <code>X-API-Key</code> header or <code>?api_key=...</code> query parameter.</p>
  </div>

  <div class="card">
    <h2>Quick Start</h2>
    <pre><code>curl -sS -X POST http://127.0.0.1:6749/api/v1/jobs \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_API_KEY" \
  --data '{{"prompt":"Find and download ...","destination_path":"./downloads","file_filter":[],"file_operation":"copy","priority":0,"metadata":{{}}}}'

curl -N "http://127.0.0.1:6749/api/v1/jobs/JOB_ID/events?api_key=YOUR_API_KEY"</code></pre>
  </div>

  <div class="card">
    <h2>SSE Event Names</h2>
    <p><code>snapshot</code>, <code>job_update</code>, <code>job_log</code>, <code>job_step</code>, <code>job_screenshot</code>, <code>complete</code></p>
  </div>

  <div class="card">
    <h2>OpenAPI Preview</h2>
    <pre><code>{}</code></pre>
  </div>
</body>
</html>"#,
        escaped_spec
    );
    Html(html)
}

fn escape_html_text(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn build_openapi_spec() -> Value {
    json!({
      "openapi": "3.1.0",
      "info": {
        "title": "Graboid API",
        "version": "1.0.0",
        "description": "Queue jobs, monitor live execution, inspect steps/screenshots/logs, and retrieve artifacts."
      },
      "servers": [
        { "url": "/", "description": "Current host" }
      ],
      "security": [
        { "ApiKeyHeader": [] },
        { "ApiKeyQuery": [] }
      ],
      "paths": {
        "/health": {
          "get": {
            "summary": "Health check",
            "security": [],
            "responses": {
              "200": {
                "description": "Server health",
                "content": { "application/json": { "schema": { "type": "object" } } }
              }
            }
          }
        },
        "/api/openapi.json": {
          "get": {
            "summary": "OpenAPI 3.1 specification",
            "security": [],
            "responses": {
              "200": {
                "description": "OpenAPI JSON",
                "content": { "application/json": { "schema": { "type": "object" } } }
              }
            }
          }
        },
        "/api/docs": {
          "get": {
            "summary": "Human-readable API documentation",
            "security": [],
            "responses": {
              "200": {
                "description": "HTML docs page",
                "content": { "text/html": { "schema": { "type": "string" } } }
              }
            }
          }
        },
        "/api/v1/jobs": {
          "get": {
            "summary": "List jobs",
            "parameters": [
              { "name": "status", "in": "query", "schema": { "$ref": "#/components/schemas/JobStatus" } },
              { "name": "limit", "in": "query", "schema": { "type": "integer", "default": 50, "minimum": 1, "maximum": 1000 } },
              { "name": "offset", "in": "query", "schema": { "type": "integer", "default": 0, "minimum": 0 } },
              { "name": "api_key", "in": "query", "schema": { "type": "string" } }
            ],
            "responses": {
              "200": { "description": "Job list", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/JobListResponse" } } } }
            }
          },
          "post": {
            "summary": "Create and queue a job",
            "requestBody": {
              "required": true,
              "content": {
                "application/json": { "schema": { "$ref": "#/components/schemas/CreateJobRequest" } }
              }
            },
            "responses": {
              "200": { "description": "Queued job", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/Job" } } } }
            }
          }
        },
        "/api/v1/jobs/{job_id}": {
          "get": {
            "summary": "Get job",
            "parameters": [
              { "$ref": "#/components/parameters/JobIdPath" },
              { "name": "api_key", "in": "query", "schema": { "type": "string" } }
            ],
            "responses": {
              "200": { "description": "Job", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/Job" } } } }
            }
          },
          "delete": {
            "summary": "Cancel job",
            "parameters": [
              { "$ref": "#/components/parameters/JobIdPath" },
              { "name": "api_key", "in": "query", "schema": { "type": "string" } }
            ],
            "responses": { "200": { "description": "Cancelled" } }
          }
        },
        "/api/v1/jobs/{job_id}/detail": {
          "get": {
            "summary": "Get combined job detail (job + steps + logs)",
            "parameters": [
              { "$ref": "#/components/parameters/JobIdPath" },
              { "name": "logs_limit", "in": "query", "schema": { "type": "integer", "default": 500, "minimum": 1, "maximum": 5000 } },
              { "name": "api_key", "in": "query", "schema": { "type": "string" } }
            ],
            "responses": { "200": { "description": "Detail payload", "content": { "application/json": { "schema": { "type": "object" } } } } }
          }
        },
        "/api/v1/jobs/{job_id}/events": {
          "get": {
            "summary": "Live SSE stream with snapshot + job updates + steps + logs + screenshots",
            "parameters": [
              { "$ref": "#/components/parameters/JobIdPath" },
              { "name": "api_key", "in": "query", "schema": { "type": "string" } }
            ],
            "responses": {
              "200": {
                "description": "Event stream",
                "content": {
                  "text/event-stream": { "schema": { "type": "string" } }
                }
              }
            }
          }
        },
        "/api/v1/jobs/{job_id}/stream": {
          "get": {
            "summary": "Live SSE progress-only stream",
            "parameters": [
              { "$ref": "#/components/parameters/JobIdPath" },
              { "name": "api_key", "in": "query", "schema": { "type": "string" } }
            ],
            "responses": {
              "200": {
                "description": "Progress event stream",
                "content": { "text/event-stream": { "schema": { "type": "string" } } }
              }
            }
          }
        },
        "/api/v1/jobs/{job_id}/steps": {
          "get": {
            "summary": "Get raw step entries",
            "parameters": [
              { "$ref": "#/components/parameters/JobIdPath" },
              { "name": "api_key", "in": "query", "schema": { "type": "string" } }
            ],
            "responses": { "200": { "description": "Step entries", "content": { "application/json": { "schema": { "type": "object" } } } } }
          }
        },
        "/api/v1/jobs/{job_id}/steps/detail": {
          "get": {
            "summary": "Get enriched step details (notes, agent messages, screenshot_base64)",
            "parameters": [
              { "$ref": "#/components/parameters/JobIdPath" },
              { "name": "api_key", "in": "query", "schema": { "type": "string" } }
            ],
            "responses": {
              "200": {
                "description": "Detailed steps",
                "content": {
                  "application/json": {
                    "schema": {
                      "type": "object",
                      "properties": {
                        "steps": {
                          "type": "array",
                          "items": { "$ref": "#/components/schemas/JobStepDetail" }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        },
        "/api/v1/jobs/{job_id}/screenshots": {
          "get": {
            "summary": "List screenshots with base64 payloads",
            "parameters": [
              { "$ref": "#/components/parameters/JobIdPath" },
              { "name": "api_key", "in": "query", "schema": { "type": "string" } }
            ],
            "responses": { "200": { "description": "Screenshots", "content": { "application/json": { "schema": { "type": "object" } } } } }
          }
        },
        "/api/v1/jobs/{job_id}/screenshots/latest": {
          "get": {
            "summary": "Get latest screenshot",
            "parameters": [
              { "$ref": "#/components/parameters/JobIdPath" },
              { "name": "api_key", "in": "query", "schema": { "type": "string" } }
            ],
            "responses": { "200": { "description": "Latest screenshot", "content": { "application/json": { "schema": { "type": "object" } } } } }
          }
        },
        "/api/v1/jobs/{job_id}/logs": {
          "get": {
            "summary": "Get job logs",
            "parameters": [
              { "$ref": "#/components/parameters/JobIdPath" },
              { "name": "limit", "in": "query", "schema": { "type": "integer", "default": 500, "minimum": 1, "maximum": 5000 } },
              { "name": "api_key", "in": "query", "schema": { "type": "string" } }
            ],
            "responses": { "200": { "description": "Logs", "content": { "application/json": { "schema": { "type": "object" } } } } }
          }
        },
        "/api/v1/jobs/{job_id}/logs/stream": {
          "get": {
            "summary": "Live SSE stream for job logs",
            "parameters": [
              { "$ref": "#/components/parameters/JobIdPath" },
              { "name": "api_key", "in": "query", "schema": { "type": "string" } }
            ],
            "responses": {
              "200": {
                "description": "Log event stream",
                "content": { "text/event-stream": { "schema": { "type": "string" } } }
              }
            }
          }
        },
        "/api/v1/jobs/{job_id}/artifacts/{kind}/{index}": {
          "get": {
            "summary": "Download an output artifact file",
            "parameters": [
              { "$ref": "#/components/parameters/JobIdPath" },
              { "name": "kind", "in": "path", "required": true, "schema": { "type": "string", "enum": ["downloaded", "final"] } },
              { "name": "index", "in": "path", "required": true, "schema": { "type": "integer", "minimum": 0 } },
              { "name": "api_key", "in": "query", "schema": { "type": "string" } }
            ],
            "responses": {
              "200": { "description": "Artifact bytes", "content": { "application/octet-stream": { "schema": { "type": "string", "format": "binary" } } } }
            }
          }
        },
        "/api/v1/notes": {
          "get": {
            "summary": "List notes used by source memory",
            "parameters": [
              { "name": "domain", "in": "query", "schema": { "type": "string" } },
              { "name": "note_type", "in": "query", "schema": { "type": "string" } },
              { "name": "api_key", "in": "query", "schema": { "type": "string" } }
            ],
            "responses": { "200": { "description": "Notes", "content": { "application/json": { "schema": { "type": "object" } } } } }
          }
        },
        "/api/v1/credentials": {
          "get": {
            "summary": "List credential names",
            "parameters": [
              { "name": "api_key", "in": "query", "schema": { "type": "string" } }
            ],
            "responses": { "200": { "description": "Credential names", "content": { "application/json": { "schema": { "type": "object" } } } } }
          },
          "post": {
            "summary": "Create or update credential",
            "parameters": [
              { "name": "api_key", "in": "query", "schema": { "type": "string" } }
            ],
            "requestBody": {
              "required": true,
              "content": { "application/json": { "schema": { "type": "object" } } }
            },
            "responses": { "200": { "description": "Credential saved" } }
          }
        },
        "/api/v1/credentials/{name}": {
          "delete": {
            "summary": "Delete credential",
            "parameters": [
              { "name": "name", "in": "path", "required": true, "schema": { "type": "string" } },
              { "name": "api_key", "in": "query", "schema": { "type": "string" } }
            ],
            "responses": { "200": { "description": "Credential deleted" } }
          }
        },
        "/api/v1/key/regenerate": {
          "post": {
            "summary": "Regenerate API key",
            "parameters": [
              { "name": "api_key", "in": "query", "schema": { "type": "string" } }
            ],
            "responses": { "200": { "description": "Regenerated key", "content": { "application/json": { "schema": { "type": "object" } } } } }
          }
        }
      },
      "components": {
        "parameters": {
          "JobIdPath": {
            "name": "job_id",
            "in": "path",
            "required": true,
            "schema": { "type": "string", "format": "uuid" }
          }
        },
        "securitySchemes": {
          "ApiKeyHeader": {
            "type": "apiKey",
            "in": "header",
            "name": "X-API-Key"
          },
          "ApiKeyQuery": {
            "type": "apiKey",
            "in": "query",
            "name": "api_key"
          }
        },
        "schemas": {
          "JobStatus": {
            "type": "string",
            "enum": ["pending", "running", "browsing", "downloading", "extracting", "copying", "complete", "failed", "cancelled"]
          },
          "JobPhase": {
            "type": "string",
            "enum": ["init", "browse", "download", "extract", "copy", "done"]
          },
          "CreateJobRequest": {
            "type": "object",
            "required": ["prompt"],
            "properties": {
              "prompt": { "type": "string" },
              "source_url": { "type": "string", "default": "" },
              "credential_name": { "type": ["string", "null"] },
              "file_filter": { "type": "array", "items": { "type": "string" }, "default": [] },
              "destination_path": { "type": "string", "default": "" },
              "file_operation": { "type": "string", "default": "copy" },
              "priority": { "type": "integer", "default": 0 },
              "metadata": { "type": "object", "additionalProperties": true, "default": {} }
            }
          },
          "Job": {
            "type": "object",
            "properties": {
              "id": { "type": "string", "format": "uuid" },
              "created_at": { "type": "string", "format": "date-time" },
              "updated_at": { "type": "string", "format": "date-time" },
              "prompt": { "type": "string" },
              "source_url": { "type": "string" },
              "credential_name": { "type": ["string", "null"] },
              "file_filter": { "type": "array", "items": { "type": "string" } },
              "destination_path": { "type": "string" },
              "file_operation": { "type": "string" },
              "priority": { "type": "integer" },
              "status": { "$ref": "#/components/schemas/JobStatus" },
              "current_phase": { "$ref": "#/components/schemas/JobPhase" },
              "progress_percent": { "type": "number" },
              "progress_message": { "type": "string" },
              "found_urls": { "type": "array", "items": { "type": "string" } },
              "downloaded_files": { "type": "array", "items": { "type": "string" } },
              "final_paths": { "type": "array", "items": { "type": "string" } },
              "error_message": { "type": "string" },
              "metadata": { "type": "object", "additionalProperties": true }
            }
          },
          "JobListResponse": {
            "type": "object",
            "properties": {
              "jobs": { "type": "array", "items": { "$ref": "#/components/schemas/Job" } },
              "total": { "type": "integer" },
              "offset": { "type": "integer" },
              "limit": { "type": "integer" }
            }
          },
          "JobStepDetail": {
            "type": "object",
            "properties": {
              "step_number": { "type": "integer" },
              "action": { "type": "string" },
              "observation": { "type": "string" },
              "url": { "type": "string" },
              "timestamp": { "type": "string", "format": "date-time" },
              "is_error": { "type": "boolean" },
              "screenshot_base64": { "type": ["string", "null"] },
              "notes": { "type": "array", "items": { "type": "string" } },
              "claude_messages": { "type": "array", "items": { "type": "string" } }
            }
          }
        }
      }
    })
}

async fn create_job(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<CreateJobRequest>,
) -> Result<Json<Job>, ApiError> {
    verify_api_key(&headers, None, &state).await?;

    if payload.prompt.trim().is_empty() {
        return Err(ApiError::bad_request("prompt is required"));
    }

    if let Some(name) = payload.credential_name.as_deref() {
        let names = state.db.list_credential_names().await?;
        if !names.iter().any(|candidate| candidate == name) {
            return Err(ApiError::bad_request(format!(
                "unknown credential: {}",
                name
            )));
        }
    }

    let job = Job::new(payload, &state.config.download_dir);
    state.db.create_job(&job).await?;
    state.runner.enqueue(job.id.clone()).await?;

    let _ = state.events.send(ServerEvent::JobUpdate(job.clone()));

    Ok(Json(job))
}

#[derive(Debug, Deserialize)]
struct JobListQuery {
    status: Option<String>,
    limit: Option<i64>,
    offset: Option<i64>,
    api_key: Option<String>,
}

async fn list_jobs(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<JobListQuery>,
) -> Result<Json<JobListResponse>, ApiError> {
    verify_api_key(&headers, query.api_key.as_deref(), &state).await?;

    let status = query
        .status
        .as_deref()
        .and_then(|s| s.parse::<JobStatus>().ok());
    let limit = query.limit.unwrap_or(50).clamp(1, 1000);
    let offset = query.offset.unwrap_or(0).max(0);

    let jobs = state.db.list_jobs(status, limit, offset).await?;
    let total = state.db.count_jobs(status).await?;

    Ok(Json(JobListResponse {
        jobs,
        total,
        offset,
        limit,
    }))
}

#[derive(Debug, Deserialize)]
struct ApiKeyQuery {
    api_key: Option<String>,
}

async fn get_job(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(job_id): Path<String>,
    Query(query): Query<ApiKeyQuery>,
) -> Result<Json<Job>, ApiError> {
    verify_api_key(&headers, query.api_key.as_deref(), &state).await?;

    let Some(job) = state.db.get_job(&job_id).await? else {
        return Err(ApiError::not_found("job not found"));
    };

    Ok(Json(job))
}

#[derive(Debug, Deserialize)]
struct JobDetailQuery {
    api_key: Option<String>,
    logs_limit: Option<i64>,
}

async fn get_job_detail(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(job_id): Path<String>,
    Query(query): Query<JobDetailQuery>,
) -> Result<Json<Value>, ApiError> {
    verify_api_key(&headers, query.api_key.as_deref(), &state).await?;
    let log_limit = query.logs_limit.unwrap_or(500).clamp(1, 5000);
    let payload = build_job_detail_payload(&state, &job_id, log_limit).await?;
    Ok(Json(payload))
}

async fn cancel_job(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(job_id): Path<String>,
    Query(query): Query<ApiKeyQuery>,
) -> Result<Json<Value>, ApiError> {
    verify_api_key(&headers, query.api_key.as_deref(), &state).await?;

    let cancelled = state.runner.cancel(&job_id).await?;
    if !cancelled {
        return Err(ApiError::not_found("job not found or already completed"));
    }

    Ok(Json(json!({"status": "cancelled", "job_id": job_id})))
}

async fn build_job_detail_payload(
    state: &Arc<AppState>,
    job_id: &str,
    log_limit: i64,
) -> Result<Value, ApiError> {
    let Some(job) = state.db.get_job(job_id).await? else {
        return Err(ApiError::not_found("job not found"));
    };

    let steps = build_job_step_details(state, job_id).await?;
    let logs = state.db.list_logs(job_id, log_limit.clamp(1, 5000)).await?;

    Ok(json!({
        "job": job,
        "steps": steps,
        "logs": logs,
    }))
}

async fn stream_job(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(job_id): Path<String>,
    Query(query): Query<ApiKeyQuery>,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, ApiError> {
    verify_api_key(&headers, query.api_key.as_deref(), &state).await?;

    let Some(initial_job) = state.db.get_job(&job_id).await? else {
        return Err(ApiError::not_found("job not found"));
    };

    let mut rx = state.events.subscribe();
    let stream = stream! {
        let initial_payload = json!({
            "job_id": initial_job.id,
            "status": initial_job.status,
            "phase": initial_job.current_phase,
            "progress_percent": initial_job.progress_percent,
            "progress_message": initial_job.progress_message,
            "updated_at": initial_job.updated_at,
        });
        yield Ok(Event::default().event("progress").data(initial_payload.to_string()));

        if initial_job.status.is_terminal() {
            let done = serde_json::to_string(&initial_job).unwrap_or_else(|_| "{}".to_string());
            yield Ok(Event::default().event("complete").data(done));
            return;
        }

        loop {
            match rx.recv().await {
                Ok(ServerEvent::JobUpdate(job)) if job.id == job_id => {
                    let payload = json!({
                        "job_id": job.id,
                        "status": job.status,
                        "phase": job.current_phase,
                        "progress_percent": job.progress_percent,
                        "progress_message": job.progress_message,
                        "updated_at": job.updated_at,
                    });
                    yield Ok(Event::default().event("progress").data(payload.to_string()));
                    if job.status.is_terminal() {
                        let done = serde_json::to_string(&job).unwrap_or_else(|_| "{}".to_string());
                        yield Ok(Event::default().event("complete").data(done));
                        break;
                    }
                }
                Ok(_) => {}
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    warn!("job stream lagged by {skipped} events");
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    };

    Ok(Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(10))))
}

async fn stream_job_events(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(job_id): Path<String>,
    Query(query): Query<ApiKeyQuery>,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, ApiError> {
    verify_api_key(&headers, query.api_key.as_deref(), &state).await?;

    let Some(initial_job) = state.db.get_job(&job_id).await? else {
        return Err(ApiError::not_found("job not found"));
    };

    let state_for_stream = state.clone();
    let mut rx = state.events.subscribe();
    let stream = stream! {
        match build_job_detail_payload(&state_for_stream, &job_id, 500).await {
            Ok(snapshot) => {
                yield Ok(Event::default().event("snapshot").data(snapshot.to_string()));
            }
            Err(err) => {
                let payload = json!({"error": err.message.clone()});
                yield Ok(Event::default().event("error").data(payload.to_string()));
            }
        }

        if initial_job.status.is_terminal() {
            let done = serde_json::to_string(&initial_job).unwrap_or_else(|_| "{}".to_string());
            yield Ok(Event::default().event("complete").data(done));
            return;
        }

        let mut seen_log_ids = HashSet::new();
        let mut seen_step_ids = HashSet::new();
        let mut seen_screenshot_ids = HashSet::new();

        loop {
            match rx.recv().await {
                Ok(ServerEvent::JobUpdate(job)) if job.id == job_id => {
                    let payload = serde_json::to_string(&job).unwrap_or_else(|_| "{}".to_string());
                    yield Ok(Event::default().event("job_update").data(payload));
                    if job.status.is_terminal() {
                        let done = serde_json::to_string(&job).unwrap_or_else(|_| "{}".to_string());
                        yield Ok(Event::default().event("complete").data(done));
                        break;
                    }
                }
                Ok(ServerEvent::JobLog(log)) if log.job_id == job_id => {
                    if seen_log_ids.insert(log.id) {
                        let payload = serde_json::to_string(&log).unwrap_or_else(|_| "{}".to_string());
                        yield Ok(Event::default().event("job_log").data(payload));
                    }
                }
                Ok(ServerEvent::JobStep(step)) if step.job_id == job_id => {
                    if seen_step_ids.insert(step.id) {
                        let payload = serde_json::to_string(&step).unwrap_or_else(|_| "{}".to_string());
                        yield Ok(Event::default().event("job_step").data(payload));
                    }
                }
                Ok(ServerEvent::JobScreenshot(shot)) if shot.job_id == job_id => {
                    if seen_screenshot_ids.insert(shot.id) {
                        let payload = json!({
                            "id": shot.id,
                            "job_id": shot.job_id,
                            "timestamp": shot.timestamp,
                            "url": shot.url,
                            "phase": shot.phase,
                            "step_number": shot.step_number,
                            "data_base64": STANDARD.encode(&shot.screenshot_data),
                        });
                        yield Ok(Event::default().event("job_screenshot").data(payload.to_string()));
                    }
                }
                Ok(_) => {}
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    warn!("job event stream lagged by {skipped} events");
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    };

    Ok(Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(10))))
}

async fn get_job_screenshots(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(job_id): Path<String>,
    Query(query): Query<ApiKeyQuery>,
) -> Result<Json<Value>, ApiError> {
    verify_api_key(&headers, query.api_key.as_deref(), &state).await?;
    let shots = state.db.list_screenshots(&job_id).await?;

    let payload = shots
        .into_iter()
        .map(|s| {
            json!({
                "id": s.id,
                "timestamp": s.timestamp,
                "url": s.url,
                "phase": s.phase,
                "step_number": s.step_number,
                "data_base64": STANDARD.encode(s.screenshot_data),
            })
        })
        .collect::<Vec<_>>();

    Ok(Json(json!({"job_id": job_id, "screenshots": payload})))
}

async fn get_job_latest_screenshot(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(job_id): Path<String>,
    Query(query): Query<ApiKeyQuery>,
) -> Result<Json<Value>, ApiError> {
    verify_api_key(&headers, query.api_key.as_deref(), &state).await?;

    let screenshot = state.db.latest_screenshot(&job_id).await?;
    let payload = screenshot.map(|s| {
        json!({
            "id": s.id,
            "timestamp": s.timestamp,
            "url": s.url,
            "phase": s.phase,
            "step_number": s.step_number,
            "data_base64": STANDARD.encode(s.screenshot_data),
        })
    });

    Ok(Json(json!({"job_id": job_id, "screenshot": payload})))
}

async fn get_job_steps(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(job_id): Path<String>,
    Query(query): Query<ApiKeyQuery>,
) -> Result<Json<Value>, ApiError> {
    verify_api_key(&headers, query.api_key.as_deref(), &state).await?;

    let steps = state.db.list_steps(&job_id).await?;
    Ok(Json(json!({"job_id": job_id, "steps": steps})))
}

async fn get_job_steps_detail(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(job_id): Path<String>,
    Query(query): Query<ApiKeyQuery>,
) -> Result<Json<Value>, ApiError> {
    verify_api_key(&headers, query.api_key.as_deref(), &state).await?;
    let detail = build_job_step_details(&state, &job_id).await?;
    Ok(Json(json!({"steps": detail})))
}

async fn build_job_step_details(
    state: &Arc<AppState>,
    job_id: &str,
) -> Result<Vec<JobStepDetail>, ApiError> {
    let steps = state.db.list_steps(job_id).await?;
    let screenshots = state.db.list_screenshots(job_id).await?;
    let logs = state.db.list_logs(job_id, 5000).await?;

    let mut screenshot_by_step = HashMap::<i64, String>::new();
    for shot in screenshots {
        if let Some(step_number) = shot.step_number {
            screenshot_by_step.insert(step_number, STANDARD.encode(shot.screenshot_data));
        }
    }

    let actionable_types = HashSet::from([
        "navigation_tip",
        "workaround",
        "download_method",
        "site_structure",
    ]);
    let learning_logs = logs
        .iter()
        .filter(|log| log.source == "learning")
        .filter(|log| {
            extract_learning_type(&log.message)
                .map(|kind| actionable_types.contains(kind.as_str()))
                .unwrap_or(false)
        })
        .cloned()
        .collect::<Vec<_>>();

    let mut claude_messages_by_step = HashMap::<i64, Vec<String>>::new();
    if !steps.is_empty() {
        let mut step_idx = 0usize;
        let first_step_time = steps[0].timestamp;

        for log in logs.iter().filter(|log| {
            matches!(
                log.source.as_str(),
                "agent_output" | "agent" | "claude_output" | "claude"
            )
        }) {
            if log.timestamp < first_step_time {
                continue;
            }

            while step_idx + 1 < steps.len() && steps[step_idx + 1].timestamp <= log.timestamp {
                step_idx += 1;
            }

            let message = log.message.trim().to_string();
            if message.trim().is_empty() {
                continue;
            }
            claude_messages_by_step
                .entry(steps[step_idx].step_number)
                .or_default()
                .push(message);
        }
    }

    let detail = steps
        .into_iter()
        .map(|step| {
            let mut notes = step.notes.clone();
            let claude_messages = claude_messages_by_step
                .remove(&step.step_number)
                .unwrap_or_default();

            for learning in &learning_logs {
                let delta = (learning.timestamp - step.timestamp).num_seconds().abs();
                if delta < 30 {
                    notes.push(learning.message.clone());
                }
            }

            dedupe_preserve_order(&mut notes);

            JobStepDetail {
                step_number: step.step_number,
                action: step.action,
                observation: step.observation,
                url: step.url,
                timestamp: step.timestamp,
                is_error: step.is_error,
                screenshot_base64: screenshot_by_step.get(&step.step_number).cloned(),
                notes,
                claude_messages,
            }
        })
        .collect::<Vec<_>>();

    Ok(detail)
}

#[derive(Debug, Deserialize)]
struct JobLogQuery {
    limit: Option<i64>,
    api_key: Option<String>,
}

async fn get_job_logs(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(job_id): Path<String>,
    Query(query): Query<JobLogQuery>,
) -> Result<Json<Value>, ApiError> {
    verify_api_key(&headers, query.api_key.as_deref(), &state).await?;

    let limit = query.limit.unwrap_or(500).clamp(1, 5000);
    let logs = state.db.list_logs(&job_id, limit).await?;

    Ok(Json(json!({"job_id": job_id, "logs": logs})))
}

async fn stream_job_logs(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(job_id): Path<String>,
    Query(query): Query<ApiKeyQuery>,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, ApiError> {
    verify_api_key(&headers, query.api_key.as_deref(), &state).await?;

    let Some(initial_job) = state.db.get_job(&job_id).await? else {
        return Err(ApiError::not_found("job not found"));
    };

    let mut rx = state.events.subscribe();
    let initial_logs = state.db.list_logs(&job_id, 500).await?;

    let stream = stream! {
        let mut seen = initial_logs.iter().map(|l| l.id).collect::<std::collections::HashSet<_>>();

        for log in initial_logs {
            let payload = serde_json::to_string(&log).unwrap_or_else(|_| "{}".to_string());
            yield Ok(Event::default().event("log").data(payload));
        }

        if initial_job.status.is_terminal() {
            yield Ok(Event::default().event("done").data("{}"));
            return;
        }

        loop {
            match rx.recv().await {
                Ok(ServerEvent::JobLog(log)) if log.job_id == job_id => {
                    if seen.insert(log.id) {
                        let payload = serde_json::to_string(&log).unwrap_or_else(|_| "{}".to_string());
                        yield Ok(Event::default().event("log").data(payload));
                    }
                }
                Ok(ServerEvent::JobUpdate(job)) if job.id == job_id && job.status.is_terminal() => {
                    yield Ok(Event::default().event("done").data("{}"));
                    break;
                }
                Ok(_) => {}
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    warn!("log stream lagged by {skipped} events");
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    };

    Ok(Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(10))))
}

async fn regenerate_api_key(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<ApiKeyQuery>,
) -> Result<Json<Value>, ApiError> {
    verify_api_key(&headers, query.api_key.as_deref(), &state).await?;

    let new_key = generate_api_key();
    persist_api_key(&state.config_path, &new_key).map_err(ApiError::internal)?;
    {
        let mut key = state.api_key.write().await;
        *key = new_key.clone();
    }

    Ok(Json(json!({"api_key": new_key})))
}

async fn list_credentials(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<ApiKeyQuery>,
) -> Result<Json<Value>, ApiError> {
    verify_api_key(&headers, query.api_key.as_deref(), &state).await?;
    let names = state.db.list_credential_names().await?;
    Ok(Json(json!({"credentials": names})))
}

#[derive(Debug, Deserialize)]
struct CredentialCreateRequest {
    name: String,
    username: String,
    password: String,
    #[serde(default = "default_json_object")]
    metadata: Value,
}

async fn create_credential(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<ApiKeyQuery>,
    Json(payload): Json<CredentialCreateRequest>,
) -> Result<Json<Value>, ApiError> {
    verify_api_key(&headers, query.api_key.as_deref(), &state).await?;

    if payload.name.trim().is_empty() {
        return Err(ApiError::bad_request("Credential name is required"));
    }
    if payload.username.trim().is_empty() {
        return Err(ApiError::bad_request("Credential username is required"));
    }

    state
        .db
        .upsert_credential(
            payload.name.trim(),
            payload.username.trim(),
            &payload.password,
            &payload.metadata,
        )
        .await?;

    Ok(Json(json!({
        "status": "created",
        "name": payload.name.trim(),
    })))
}

async fn delete_credential(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Query(query): Query<ApiKeyQuery>,
) -> Result<Json<Value>, ApiError> {
    verify_api_key(&headers, query.api_key.as_deref(), &state).await?;
    let deleted = state.db.delete_credential(&name).await?;
    if !deleted {
        return Err(ApiError::not_found("Credential not found"));
    }
    Ok(Json(json!({"status": "deleted", "name": name})))
}

#[derive(Debug, Deserialize)]
struct NotesQuery {
    domain: Option<String>,
    note_type: Option<String>,
    api_key: Option<String>,
}

async fn get_notes(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<NotesQuery>,
) -> Result<Json<Value>, ApiError> {
    verify_api_key(&headers, query.api_key.as_deref(), &state).await?;

    let mut notes = if let Some(domain) = query.domain.as_deref() {
        let normalized = normalize_domain(domain);
        state.db.list_notes_for_domain(&normalized).await?
    } else {
        state.db.list_notes().await?
    };

    if let Some(note_type) = query.note_type.as_deref() {
        notes.retain(|n| n.note_type == note_type);
    }

    Ok(Json(json!({"notes": notes})))
}

async fn ws_upgrade(ws: WebSocketUpgrade, State(state): State<Arc<AppState>>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_ws(socket, state))
}

async fn handle_ws(socket: WebSocket, state: Arc<AppState>) {
    let (sender, mut receiver) = socket.split();
    let sender = Arc::new(Mutex::new(sender));
    let mut rx = state.events.subscribe();

    let is_running = state.runtime.is_running().await;
    let task = state.runtime.current_task().await;
    let messages = state.runtime.messages_tail(20).await;

    let init_msg = json!({
        "type": "init",
        "is_running": is_running,
        "task": task,
        "messages": messages,
    });

    if sender
        .lock()
        .await
        .send(Message::Text(init_msg.to_string().into()))
        .await
        .is_err()
    {
        return;
    }

    if let Some((data, url)) = state.runtime.screenshot().await {
        let shot_msg = json!({"type": "screenshot", "data": data, "url": url});
        if sender
            .lock()
            .await
            .send(Message::Text(shot_msg.to_string().into()))
            .await
            .is_err()
        {
            return;
        }
    }

    let send_sender = sender.clone();
    let send_task = tokio::spawn(async move {
        while let Ok(event) = rx.recv().await {
            let text = event.as_json_value().to_string();
            if send_sender
                .lock()
                .await
                .send(Message::Text(text.into()))
                .await
                .is_err()
            {
                break;
            }
        }
    });

    let recv_sender = sender.clone();
    let recv_task = tokio::spawn(async move {
        while let Some(msg) = receiver.next().await {
            match msg {
                Ok(Message::Text(text)) => {
                    if let Ok(value) = serde_json::from_str::<Value>(&text) {
                        if value.get("type").and_then(Value::as_str) == Some("ping") {
                            let pong = json!({"type": "pong"}).to_string();
                            if recv_sender
                                .lock()
                                .await
                                .send(Message::Text(pong.into()))
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                    }
                }
                Ok(Message::Ping(payload)) => {
                    debug!("ws ping {} bytes", payload.len());
                    if recv_sender
                        .lock()
                        .await
                        .send(Message::Pong(payload))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Ok(Message::Close(_)) => break,
                Ok(_) => {}
                Err(_) => break,
            }
        }
    });

    tokio::select! {
        _ = send_task => {}
        _ = recv_task => {}
    }
}

fn current_user(jar: &CookieJar, state: &AppState) -> Option<String> {
    let token = jar.get(SESSION_COOKIE_NAME)?.value().to_string();
    verify_session_token(
        &token,
        &state.auth.session_secret,
        state.auth.session_max_age_seconds,
    )
}

async fn runtime_badge(state: &AppState) -> ui::RuntimeBadge {
    let (is_running, current_task, _downloads, _message_count) =
        state.runtime.snapshot_status().await;
    ui::RuntimeBadge {
        is_running,
        current_task,
    }
}

fn sign_session_token(username: &str, secret: &str) -> String {
    let timestamp = chrono::Utc::now().timestamp().to_string();
    let data = format!("{username}:{timestamp}");

    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("hmac key init failed");
    mac.update(data.as_bytes());
    let signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());

    URL_SAFE_NO_PAD.encode(format!("{data}:{signature}").as_bytes())
}

fn verify_session_token(token: &str, secret: &str, max_age_seconds: i64) -> Option<String> {
    let decoded = URL_SAFE_NO_PAD.decode(token).ok()?;
    let decoded = String::from_utf8(decoded).ok()?;

    let mut parts = decoded.rsplitn(3, ':');
    let signature = parts.next()?;
    let timestamp = parts.next()?;
    let username = parts.next()?;

    let ts = timestamp.parse::<i64>().ok()?;
    let now = chrono::Utc::now().timestamp();
    if now - ts > max_age_seconds {
        return None;
    }

    let data = format!("{username}:{timestamp}");
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).ok()?;
    mac.update(data.as_bytes());
    let expected = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());

    if expected == signature {
        Some(username.to_string())
    } else {
        None
    }
}

async fn verify_api_key(
    headers: &HeaderMap,
    query_key: Option<&str>,
    state: &AppState,
) -> Result<(), ApiError> {
    let expected = state.api_key.read().await.clone();
    if expected.is_empty() {
        return Ok(());
    }

    let provided = headers
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .or(query_key)
        .unwrap_or_default();

    if provided.is_empty() {
        return Err(ApiError::new(StatusCode::UNAUTHORIZED, "API key required"));
    }

    if provided == expected {
        Ok(())
    } else {
        Err(ApiError::new(StatusCode::FORBIDDEN, "Invalid API key"))
    }
}

async fn test_qbittorrent(
    host: &str,
    port: u16,
    username: &str,
    password: &str,
) -> Result<String, String> {
    let base = endpoint_base(host, port);
    let client = reqwest::Client::builder()
        .cookie_store(true)
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|err| err.to_string())?;

    let login = client
        .post(format!("{base}/api/v2/auth/login"))
        .form(&[("username", username), ("password", password)])
        .send()
        .await
        .map_err(|err| format!("connection failed: {err}"))?;

    if !login.status().is_success() {
        return Err(format!("login request failed with HTTP {}", login.status()));
    }

    let login_text = login
        .text()
        .await
        .unwrap_or_else(|_| String::from("unknown response"));
    if !login_text.to_ascii_lowercase().contains("ok") {
        return Err("qBittorrent authentication failed".to_string());
    }

    let torrents = client
        .get(format!("{base}/api/v2/torrents/info?limit=1"))
        .send()
        .await
        .map_err(|err| format!("connected but list request failed: {err}"))?;

    if !torrents.status().is_success() {
        return Err(format!(
            "authenticated but list request returned HTTP {}",
            torrents.status()
        ));
    }

    let count = torrents
        .json::<Value>()
        .await
        .ok()
        .and_then(|v| v.as_array().map(|arr| arr.len()))
        .unwrap_or(0);

    Ok(format!(
        "Connected to qBittorrent. {count} active torrent(s) sampled."
    ))
}

async fn test_transmission(
    host: &str,
    port: u16,
    username: &str,
    password: &str,
) -> Result<String, String> {
    let endpoint = format!("{}/transmission/rpc", endpoint_base(host, port));
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|err| err.to_string())?;

    let payload = json!({
        "method": "session-get",
        "arguments": {}
    });

    let user = username.trim();
    let mut first_request = client.post(&endpoint).json(&payload);
    if !user.is_empty() {
        first_request = first_request.basic_auth(user, Some(password));
    }
    let first = first_request
        .send()
        .await
        .map_err(|err| format!("connection failed: {err}"))?;

    let session_id = if first.status() == StatusCode::CONFLICT {
        first
            .headers()
            .get("X-Transmission-Session-Id")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
            .ok_or_else(|| "missing X-Transmission-Session-Id header".to_string())?
    } else if first.status().is_success() {
        return Ok("Connected to Transmission.".to_string());
    } else {
        return Err(format!(
            "Transmission RPC failed with HTTP {}",
            first.status()
        ));
    };

    let mut second_request = client
        .post(&endpoint)
        .header("X-Transmission-Session-Id", session_id)
        .json(&payload);
    if !user.is_empty() {
        second_request = second_request.basic_auth(user, Some(password));
    }
    let second = second_request
        .send()
        .await
        .map_err(|err| format!("session request failed: {err}"))?;

    if !second.status().is_success() {
        return Err(format!(
            "Transmission session request failed with HTTP {}",
            second.status()
        ));
    }

    Ok("Connected to Transmission.".to_string())
}

async fn test_aria2(host: &str, port: u16, secret: &str) -> Result<String, String> {
    let endpoint = format!("{}/jsonrpc", endpoint_base(host, port));
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|err| err.to_string())?;

    let mut params = Vec::<Value>::new();
    if !secret.trim().is_empty() {
        params.push(Value::String(format!("token:{}", secret.trim())));
    }

    let payload = json!({
        "jsonrpc": "2.0",
        "id": "graboid",
        "method": "aria2.getVersion",
        "params": params,
    });

    let response = client
        .post(&endpoint)
        .json(&payload)
        .send()
        .await
        .map_err(|err| format!("connection failed: {err}"))?;

    if !response.status().is_success() {
        return Err(format!("aria2 RPC failed with HTTP {}", response.status()));
    }

    let version = response
        .json::<Value>()
        .await
        .ok()
        .and_then(|v| v.get("result").cloned())
        .and_then(|result| {
            result
                .get("version")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .unwrap_or_else(|| "unknown".to_string());

    Ok(format!("Connected to aria2 (version {version})."))
}

async fn test_deluge_console(
    host: &str,
    port: u16,
    username: &str,
    password: &str,
) -> Result<String, String> {
    let target = format!("{}:{}", host.trim(), port);
    let user = if username.trim().is_empty() {
        "localclient"
    } else {
        username.trim()
    };
    let pass = if password.trim().is_empty() {
        "deluge"
    } else {
        password.trim()
    };

    let script = format!("connect {target} {user} {pass}; info; exit");
    let output = Command::new("deluge-console")
        .arg(script)
        .output()
        .await
        .map_err(|err| format!("failed to execute deluge-console: {err}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let detail = if !stderr.is_empty() { stderr } else { stdout };
        return Err(if detail.is_empty() {
            format!("deluge-console exited with status {}", output.status)
        } else {
            format!("deluge-console failed: {}", truncate(&detail, 220))
        });
    }

    Ok("Connected to Deluge via deluge-console.".to_string())
}

async fn test_rtorrent(rtorrent_url: &str) -> Result<String, String> {
    let url = rtorrent_url.trim();
    if url.is_empty() {
        return Err("rtorrent_url is required".to_string());
    }
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err("rTorrent test currently supports only HTTP(S) XML-RPC endpoints".to_string());
    }

    let payload = xmlrpc_request("system.client_version", &[]);
    let response = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|err| err.to_string())?
        .post(url)
        .header("Content-Type", "text/xml")
        .body(payload)
        .send()
        .await
        .map_err(|err| format!("connection failed: {err}"))?;

    if !response.status().is_success() {
        return Err(format!(
            "rTorrent XML-RPC failed with HTTP {}",
            response.status()
        ));
    }

    let body = response.text().await.unwrap_or_default();
    if body.contains("<fault>") {
        return Err("rTorrent XML-RPC returned a fault".to_string());
    }

    Ok("Connected to rTorrent XML-RPC endpoint.".to_string())
}

fn xmlrpc_request(method: &str, params: &[&str]) -> String {
    let mut body = String::new();
    body.push_str(r#"<?xml version="1.0"?>"#);
    body.push_str("<methodCall>");
    body.push_str("<methodName>");
    body.push_str(method);
    body.push_str("</methodName>");
    body.push_str("<params>");
    for param in params {
        body.push_str("<param><value><string>");
        body.push_str(&xml_escape(param));
        body.push_str("</string></value></param>");
    }
    body.push_str("</params></methodCall>");
    body
}

fn xml_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn endpoint_base(host: &str, port: u16) -> String {
    let trimmed = host.trim().trim_end_matches('/');
    let trimmed = if trimmed.is_empty() {
        "127.0.0.1"
    } else {
        trimmed
    };
    if trimmed.contains("://") {
        if has_explicit_port(trimmed) {
            trimmed.to_string()
        } else {
            format!("{trimmed}:{port}")
        }
    } else {
        format!("http://{trimmed}:{port}")
    }
}

fn has_explicit_port(base: &str) -> bool {
    let without_scheme = base.split_once("://").map(|(_, rest)| rest).unwrap_or(base);
    without_scheme
        .rsplit_once(':')
        .and_then(|(_, maybe_port)| maybe_port.parse::<u16>().ok())
        .is_some()
}

fn display_config_path(path: &PathBuf) -> String {
    let absolute = if path.is_absolute() {
        path.clone()
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .unwrap_or_else(|_| path.clone())
    };
    let normalized = absolute.canonicalize().unwrap_or(absolute);

    if let Ok(home) = std::env::var("HOME") {
        let home_path = PathBuf::from(home);
        if let Ok(rest) = normalized.strip_prefix(&home_path) {
            if rest.as_os_str().is_empty() {
                return "~".to_string();
            }
            return format!("~{}{}", std::path::MAIN_SEPARATOR, rest.display());
        }
    }

    normalized.display().to_string()
}

fn request_context(
    uri: &Uri,
    headers: &HeaderMap,
    query: &HashMap<String, String>,
) -> RequestContext {
    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("http")
        .to_string();
    let netloc = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost")
        .to_string();

    RequestContext {
        path: uri.path().to_string(),
        scheme,
        netloc,
        query_params: query.clone(),
    }
}

fn extract_learning_type(message: &str) -> Option<String> {
    if !message.starts_with('[') {
        return None;
    }
    let end = message.find(']')?;
    let kind = message.get(1..end)?.trim().to_ascii_lowercase();
    if kind.is_empty() { None } else { Some(kind) }
}

fn dedupe_preserve_order(values: &mut Vec<String>) {
    let mut seen = HashSet::new();
    values.retain(|value| seen.insert(value.clone()));
}

fn default_json_object() -> Value {
    Value::Object(Default::default())
}

fn normalize_domain(input: &str) -> String {
    if let Ok(parsed) = reqwest::Url::parse(input) {
        if let Some(host) = parsed.host_str() {
            return host.to_string();
        }
    }
    input.trim().to_string()
}

fn truncate(text: &str, max_len: usize) -> String {
    if text.len() <= max_len {
        text.to_string()
    } else {
        format!("{}...", &text[..max_len])
    }
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: String,
    detail: String,
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, message)
    }

    fn internal(err: impl std::fmt::Display) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(value: anyhow::Error) -> Self {
        Self::internal(value)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = Json(ErrorBody {
            error: self.message.clone(),
            detail: self.message,
        });
        (self.status, body).into_response()
    }
}
