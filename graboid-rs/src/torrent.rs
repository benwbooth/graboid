use std::collections::{HashMap, HashSet};
use std::future::Future;
#[cfg(feature = "librqbit-embedded")]
use std::path::Path;
use std::path::PathBuf;
#[cfg(feature = "librqbit-embedded")]
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
#[cfg(feature = "librqbit-embedded")]
use globset::{Glob, GlobSet, GlobSetBuilder};
use regex::Regex;
use reqwest::StatusCode;
use serde_json::{Value, json};
use tokio::process::Command;

use crate::config::AppConfig;

#[derive(Debug, Clone)]
pub struct TorznabSearchResult {
    pub title: String,
    pub download_url: String,
    pub details_url: Option<String>,
    pub seeders: Option<i64>,
    pub size_bytes: Option<u64>,
    pub indexer: Option<String>,
}

pub async fn add_torrent(cfg: &AppConfig, source: &str) -> Result<String> {
    match cfg.torrent_client.as_str() {
        "auto" => add_auto(cfg, source).await,
        "embedded" => add_embedded(cfg, source).await,
        "deluge" => add_deluge(cfg, source).await,
        "rtorrent" => add_rtorrent(cfg, source).await,
        "qbittorrent" => add_qbittorrent(cfg, source).await,
        "transmission" => add_transmission(cfg, source).await,
        "aria2" => add_aria2(cfg, source).await,
        unsupported => bail!("unsupported torrent client: {unsupported}"),
    }
}

pub async fn search_torznab(cfg: &AppConfig, query: &str) -> Result<Vec<TorznabSearchResult>> {
    search_torznab_internal(cfg, query, None, None).await
}

pub async fn search_torznab_fresh(
    cfg: &AppConfig,
    query: &str,
) -> Result<Vec<TorznabSearchResult>> {
    // Force Jackett/Prowlarr to hit upstream indexers instead of serving cached results.
    search_torznab_internal(cfg, query, Some(false), Some(75)).await
}

async fn search_torznab_internal(
    cfg: &AppConfig,
    query: &str,
    cache: Option<bool>,
    timeout_override_secs: Option<u64>,
) -> Result<Vec<TorznabSearchResult>> {
    if !cfg.torznab_enabled {
        return Ok(Vec::new());
    }

    let endpoint = cfg.torznab_endpoint.trim();
    if endpoint.is_empty() {
        bail!("torznab_enabled is true but torznab_endpoint is empty");
    }

    let normalized_query = build_torznab_query(query);
    if normalized_query.is_empty() {
        bail!("torznab query is empty");
    }

    let max_results = cfg.torznab_max_results.max(1).min(200);
    let timeout_secs = timeout_override_secs
        .unwrap_or(cfg.download_timeout_seconds)
        .clamp(10, 120);
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(cfg.download_allow_insecure)
        .timeout(Duration::from_secs(timeout_secs))
        .build()
        .context("failed creating Torznab HTTP client")?;

    let mut request = client
        .get(endpoint)
        .query(&[("t", "search"), ("q", normalized_query.as_str())])
        .query(&[("limit", max_results.to_string())]);

    if !cfg.torznab_api_key.trim().is_empty() {
        request = request.query(&[("apikey", cfg.torznab_api_key.trim())]);
    }
    if !cfg.torznab_categories.trim().is_empty() {
        request = request.query(&[("cat", cfg.torznab_categories.trim())]);
    }
    if let Some(cache_enabled) = cache {
        request = request.query(&[("cache", if cache_enabled { "true" } else { "false" })]);
    }

    let response = request
        .send()
        .await
        .with_context(|| format!("torznab search request failed for endpoint {endpoint}"))?;
    if !response.status().is_success() {
        bail!("torznab search failed with HTTP {}", response.status());
    }

    let body = response
        .text()
        .await
        .context("failed reading Torznab response body")?;
    if let Some(feed_error) = parse_torznab_error(&body) {
        bail!("torznab feed error: {feed_error}");
    }
    let mut results = parse_torznab_feed(&body);
    results.retain(|item| is_torznab_download_url(&item.download_url));
    if results.is_empty() {
        return Ok(Vec::new());
    }

    rank_torznab_results(&mut results, &normalized_query);

    let mut deduped = Vec::new();
    let mut seen_urls = HashSet::new();
    for item in results {
        if seen_urls.insert(item.download_url.clone()) {
            deduped.push(item);
        }
        if deduped.len() >= max_results {
            break;
        }
    }

    Ok(deduped)
}

pub async fn selective_fetch_from_torrent(
    cfg: &AppConfig,
    source: &str,
    prompt: &str,
    file_filter: &[String],
) -> Result<Vec<PathBuf>> {
    if file_filter.is_empty() {
        bail!("file_filter is empty; selective torrent fetch requires desired file patterns")
    }
    if !matches!(cfg.torrent_client.as_str(), "embedded" | "auto") {
        bail!(
            "selective torrent fetch currently requires torrent_client=embedded or auto (current: {})",
            cfg.torrent_client
        );
    }

    #[cfg(feature = "librqbit-embedded")]
    {
        selective_fetch_embedded(cfg, source, prompt, file_filter).await
    }

    #[cfg(not(feature = "librqbit-embedded"))]
    {
        let _ = (cfg, source, prompt, file_filter);
        bail!(
            "selective torrent fetch requires embedded backend support (enable cargo feature `librqbit-embedded`)"
        );
    }
}

pub fn embedded_backend_available() -> bool {
    cfg!(feature = "librqbit-embedded")
}

pub fn embedded_backend_message() -> &'static str {
    if embedded_backend_available() {
        "Embedded torrent backend is available (librqbit)."
    } else {
        "Embedded torrent backend is not built in this binary. Rebuild with feature `librqbit-embedded` or use qBittorrent/Transmission/aria2."
    }
}

async fn add_embedded(cfg: &AppConfig, source: &str) -> Result<String> {
    #[cfg(feature = "librqbit-embedded")]
    {
        return add_embedded_librqbit(cfg, source).await;
    }

    #[cfg(not(feature = "librqbit-embedded"))]
    {
        let _ = (cfg, source);
        bail!(
            "embedded torrent backend unavailable in this build (enable cargo feature `librqbit-embedded`)"
        );
    }
}

#[cfg(feature = "librqbit-embedded")]
async fn add_embedded_librqbit(cfg: &AppConfig, source: &str) -> Result<String> {
    let session = embedded_session(cfg).await?;
    let add_request = build_embedded_add_request(source).await?;

    session
        .add_torrent(add_request, None)
        .await
        .context("embedded torrent add failed")?;

    Ok(extract_magnet_hash(source).unwrap_or_else(|| fallback_torrent_id("embedded", source)))
}

#[cfg(feature = "librqbit-embedded")]
async fn selective_fetch_embedded(
    cfg: &AppConfig,
    source: &str,
    prompt: &str,
    file_filter: &[String],
) -> Result<Vec<PathBuf>> {
    use librqbit::{AddTorrentOptions, AddTorrentResponse};

    let session = embedded_session(cfg).await?;
    let list_response = tokio::time::timeout(
        Duration::from_secs(90),
        session.add_torrent(
            build_embedded_add_request(source).await?,
            Some(AddTorrentOptions {
                list_only: true,
                paused: true,
                overwrite: true,
                output_folder: Some(cfg.download_dir().display().to_string()),
                ..Default::default()
            }),
        ),
    )
    .await
    .context("timed out while listing torrent contents")?
    .context("failed to list torrent contents")?;

    let list = match list_response {
        AddTorrentResponse::ListOnly(list) => list,
        _ => bail!("torrent list_only mode returned unexpected response"),
    };

    let selected = select_torrent_files(&list.info, prompt, file_filter)?;
    if selected.file_indices.is_empty() {
        bail!("no suitable torrent files matched prompt/file_filter");
    }

    let selected_set = selected
        .file_indices
        .iter()
        .copied()
        .collect::<HashSet<_>>();
    let output_folder = list.output_folder.clone();
    let add_opts = AddTorrentOptions {
        paused: false,
        overwrite: true,
        output_folder: Some(output_folder.display().to_string()),
        only_files: Some(selected.file_indices.clone()),
        ..Default::default()
    };
    let add_response = session
        .add_torrent(build_embedded_add_request(source).await?, Some(add_opts))
        .await
        .context("failed starting selective torrent download")?;

    let (torrent_id, handle) = match add_response {
        AddTorrentResponse::Added(id, handle) => (id, handle),
        AddTorrentResponse::AlreadyManaged(id, handle) => {
            session
                .update_only_files(&handle, &selected_set)
                .await
                .context("failed updating existing torrent file selection")?;
            session
                .unpause(&handle)
                .await
                .context("failed unpausing existing torrent")?;
            (id, handle)
        }
        AddTorrentResponse::ListOnly(_) => {
            bail!("torrent add returned list-only response unexpectedly")
        }
    };

    tokio::time::timeout(Duration::from_secs(90), handle.wait_until_initialized())
        .await
        .context("timed out waiting for torrent metadata initialization")?
        .context("torrent initialization failed")?;

    let selective_timeout = cfg.download_timeout_seconds.max(120);
    tokio::time::timeout(
        Duration::from_secs(selective_timeout),
        handle.wait_until_completed(),
    )
    .await
    .with_context(|| {
        format!(
            "timed out waiting for selective torrent download after {}s",
            selective_timeout
        )
    })?
    .context("selective torrent download failed")?;

    let mut paths = handle
        .with_metadata(|metadata| {
            selected
                .file_indices
                .iter()
                .filter_map(|idx| metadata.file_infos.get(*idx))
                .map(|fi| output_folder.join(&fi.relative_filename))
                .collect::<Vec<PathBuf>>()
        })
        .context("failed resolving selected torrent file paths")?;
    paths.retain(|path| path.exists());
    if paths.is_empty() {
        bail!("selected torrent files did not materialize on disk");
    }

    let _ = session
        .delete(librqbit::api::TorrentIdOrHash::Id(torrent_id), false)
        .await;

    Ok(paths)
}

#[cfg(feature = "librqbit-embedded")]
async fn embedded_session(cfg: &AppConfig) -> Result<Arc<librqbit::Session>> {
    use librqbit::{Session, SessionOptions, SessionPersistenceConfig};
    use tokio::sync::OnceCell;

    static SESSION: OnceCell<Arc<Session>> = OnceCell::const_new();

    let download_dir = cfg.download_dir();
    tokio::fs::create_dir_all(&download_dir)
        .await
        .with_context(|| {
            format!(
                "failed creating embedded download dir {}",
                download_dir.display()
            )
        })?;

    let persistence_dir = download_dir.join(".rqbit-session");
    tokio::fs::create_dir_all(&persistence_dir)
        .await
        .with_context(|| {
            format!(
                "failed creating embedded session dir {}",
                persistence_dir.display()
            )
        })?;

    SESSION
        .get_or_try_init(|| async {
            let mut options = SessionOptions::default();
            options.fastresume = true;
            options.persistence = Some(SessionPersistenceConfig::Json {
                folder: Some(persistence_dir.clone()),
            });

            let session = Session::new_with_opts(download_dir.clone(), options)
                .await
                .context("failed initializing embedded librqbit session")?;
            Ok::<Arc<Session>, anyhow::Error>(session)
        })
        .await
        .cloned()
}

#[cfg(feature = "librqbit-embedded")]
async fn build_embedded_add_request(source: &str) -> Result<librqbit::AddTorrent<'static>> {
    if source.starts_with("magnet:")
        || source.starts_with("http://")
        || source.starts_with("https://")
    {
        return Ok(librqbit::AddTorrent::from_url(source.to_string()));
    }

    if source.trim().is_empty() {
        bail!("empty torrent source");
    }

    let bytes = tokio::fs::read(source)
        .await
        .with_context(|| format!("failed reading torrent file {source}"))?;
    Ok(librqbit::AddTorrent::from_bytes(bytes))
}

async fn add_qbittorrent(cfg: &AppConfig, source: &str) -> Result<String> {
    let base = endpoint_base(&cfg.qbittorrent_host, cfg.qbittorrent_port);
    let client = reqwest::Client::builder()
        .cookie_store(true)
        .danger_accept_invalid_certs(cfg.download_allow_insecure)
        .timeout(Duration::from_secs(15))
        .build()
        .context("failed to create qBittorrent HTTP client")?;

    let login = client
        .post(format!("{base}/api/v2/auth/login"))
        .form(&[
            ("username", cfg.qbittorrent_username.as_str()),
            ("password", cfg.qbittorrent_password.as_str()),
        ])
        .send()
        .await
        .context("qBittorrent login request failed")?;

    if !login.status().is_success() {
        bail!("qBittorrent login failed with HTTP {}", login.status());
    }

    let login_text = login.text().await.unwrap_or_default();
    if !login_text.to_ascii_lowercase().contains("ok") {
        bail!("qBittorrent login rejected credentials");
    }

    let add = client
        .post(format!("{base}/api/v2/torrents/add"))
        .form(&[
            ("urls", source),
            ("savepath", cfg.download_dir.as_str()),
            ("category", "graboid"),
        ])
        .send()
        .await
        .context("qBittorrent add request failed")?;

    if !add.status().is_success() {
        bail!("qBittorrent add failed with HTTP {}", add.status());
    }

    let body = add.text().await.unwrap_or_default();
    if body.to_ascii_lowercase().contains("fails") {
        bail!("qBittorrent rejected torrent: {body}");
    }

    Ok(extract_magnet_hash(source).unwrap_or_else(|| fallback_torrent_id("qbit", source)))
}

async fn add_transmission(cfg: &AppConfig, source: &str) -> Result<String> {
    let endpoint = format!(
        "{}/transmission/rpc",
        endpoint_base(&cfg.transmission_host, cfg.transmission_port)
    );
    let payload = json!({
        "method": "torrent-add",
        "arguments": {
            "filename": source,
            "download-dir": cfg.download_dir,
        }
    });
    let response = transmission_rpc(
        endpoint,
        payload,
        cfg.download_allow_insecure,
        &cfg.transmission_username,
        &cfg.transmission_password,
    )
    .await?;

    if response.get("result").and_then(Value::as_str) != Some("success") {
        bail!(
            "Transmission returned error: {}",
            response
                .get("result")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
        );
    }

    let hash = response
        .get("arguments")
        .and_then(|args| {
            args.get("torrent-added")
                .or_else(|| args.get("torrent-duplicate"))
        })
        .and_then(|t| t.get("hashString"))
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| extract_magnet_hash(source))
        .unwrap_or_else(|| fallback_torrent_id("transmission", source));

    Ok(hash)
}

async fn add_deluge(cfg: &AppConfig, source: &str) -> Result<String> {
    let host = cfg.deluge_host.trim();
    if host.is_empty() {
        bail!("deluge_host is required when torrent_client=deluge");
    }

    let username = if cfg.deluge_username.trim().is_empty() {
        "localclient"
    } else {
        cfg.deluge_username.trim()
    };
    let password = if cfg.deluge_password.trim().is_empty() {
        "deluge"
    } else {
        cfg.deluge_password.trim()
    };
    let save_dir = if cfg.download_dir.trim().is_empty() {
        "."
    } else {
        cfg.download_dir.trim()
    };
    let target = format!("{host}:{}", cfg.deluge_port);
    let script = format!(
        "connect \"{}\" \"{}\" \"{}\"; add -p \"{}\" \"{}\"; exit",
        escape_deluge_arg(&target),
        escape_deluge_arg(username),
        escape_deluge_arg(password),
        escape_deluge_arg(save_dir),
        escape_deluge_arg(source.trim()),
    );

    let output = Command::new("deluge-console")
        .arg(script)
        .output()
        .await
        .context("failed to execute deluge-console")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let detail = if !stderr.is_empty() { stderr } else { stdout };
        if detail.is_empty() {
            bail!("deluge-console exited with status {}", output.status);
        }
        bail!("deluge-console failed: {}", truncate(&detail, 220));
    }

    Ok(extract_magnet_hash(source).unwrap_or_else(|| fallback_torrent_id("deluge", source)))
}

async fn add_rtorrent(cfg: &AppConfig, source: &str) -> Result<String> {
    let endpoint = cfg.rtorrent_url.trim();
    if endpoint.is_empty() {
        bail!("rtorrent_url is required when torrent_client=rtorrent");
    }
    if !(endpoint.starts_with("http://") || endpoint.starts_with("https://")) {
        bail!("rTorrent runtime currently supports only HTTP(S) XML-RPC endpoints");
    }

    let mut verbose_params = vec![String::new(), source.trim().to_string()];
    if !cfg.download_dir.trim().is_empty() {
        verbose_params.push(format!("d.directory.set={}", cfg.download_dir.trim()));
    }

    if let Err(primary_err) = rtorrent_rpc(
        endpoint,
        "load.start_verbose",
        &verbose_params,
        cfg.download_allow_insecure,
    )
    .await
    {
        let fallback = vec![String::new(), source.trim().to_string()];
        rtorrent_rpc(
            endpoint,
            "load.start",
            &fallback,
            cfg.download_allow_insecure,
        )
        .await
        .with_context(|| {
            format!("rTorrent add failed (load.start_verbose error: {primary_err})")
        })?;
    }

    Ok(extract_magnet_hash(source).unwrap_or_else(|| fallback_torrent_id("rtorrent", source)))
}

async fn add_aria2(cfg: &AppConfig, source: &str) -> Result<String> {
    let endpoint = format!("{}/jsonrpc", endpoint_base(&cfg.aria2_host, cfg.aria2_port));
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(cfg.download_allow_insecure)
        .timeout(Duration::from_secs(15))
        .build()
        .context("failed to create aria2 HTTP client")?;

    let mut params = Vec::new();
    if !cfg.aria2_secret.trim().is_empty() {
        params.push(Value::String(format!("token:{}", cfg.aria2_secret.trim())));
    }
    params.push(Value::Array(vec![Value::String(source.to_string())]));
    params.push(json!({ "dir": cfg.download_dir }));

    let payload = json!({
        "jsonrpc": "2.0",
        "id": "graboid",
        "method": "aria2.addUri",
        "params": params,
    });

    let response = client
        .post(&endpoint)
        .json(&payload)
        .send()
        .await
        .context("aria2 add request failed")?;

    if !response.status().is_success() {
        bail!("aria2 add failed with HTTP {}", response.status());
    }

    let json = response
        .json::<Value>()
        .await
        .context("aria2 response was not valid JSON")?;
    if let Some(err) = json.get("error") {
        let message = err
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("unknown aria2 error");
        bail!("aria2 error: {message}");
    }

    let gid = json
        .get("result")
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| extract_magnet_hash(source))
        .unwrap_or_else(|| fallback_torrent_id("aria2", source));

    Ok(gid)
}

async fn add_auto(cfg: &AppConfig, source: &str) -> Result<String> {
    let mut errors = Vec::new();
    let timeout = Duration::from_secs(6);

    if embedded_backend_available() {
        if let Some(id) =
            try_auto_candidate("embedded", timeout, add_embedded(cfg, source), &mut errors).await
        {
            return Ok(id);
        }
    } else {
        errors.push("embedded: backend not compiled in".to_string());
    }

    if let Some(id) = try_auto_candidate(
        "qbittorrent",
        timeout,
        add_qbittorrent(cfg, source),
        &mut errors,
    )
    .await
    {
        return Ok(id);
    }
    if let Some(id) = try_auto_candidate(
        "transmission",
        timeout,
        add_transmission(cfg, source),
        &mut errors,
    )
    .await
    {
        return Ok(id);
    }
    if let Some(id) =
        try_auto_candidate("aria2", timeout, add_aria2(cfg, source), &mut errors).await
    {
        return Ok(id);
    }
    if let Some(id) =
        try_auto_candidate("deluge", timeout, add_deluge(cfg, source), &mut errors).await
    {
        return Ok(id);
    }
    if !cfg.rtorrent_url.trim().is_empty() {
        if let Some(id) =
            try_auto_candidate("rtorrent", timeout, add_rtorrent(cfg, source), &mut errors).await
        {
            return Ok(id);
        }
    } else {
        errors.push("rtorrent: skipped because rtorrent_url is empty".to_string());
    }

    bail!(
        "auto torrent client failed; attempted backends: {}",
        errors.join(" | ")
    )
}

async fn try_auto_candidate<F>(
    name: &str,
    timeout: Duration,
    op: F,
    errors: &mut Vec<String>,
) -> Option<String>
where
    F: Future<Output = Result<String>>,
{
    match tokio::time::timeout(timeout, op).await {
        Ok(Ok(id)) => Some(id),
        Ok(Err(err)) => {
            errors.push(format!("{name}: {err}"));
            None
        }
        Err(_) => {
            errors.push(format!("{name}: timed out after {}s", timeout.as_secs()));
            None
        }
    }
}

async fn transmission_rpc(
    endpoint: String,
    payload: Value,
    allow_insecure: bool,
    username: &str,
    password: &str,
) -> Result<Value> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(allow_insecure)
        .timeout(Duration::from_secs(15))
        .build()
        .context("failed to create Transmission HTTP client")?;

    let user = username.trim();
    let mut session_id: Option<String> = None;
    for _ in 0..3 {
        let mut request = client.post(&endpoint).json(&payload);
        if let Some(id) = session_id.as_deref() {
            request = request.header("X-Transmission-Session-Id", id);
        }
        if !user.is_empty() {
            request = request.basic_auth(user, Some(password));
        }

        let response = request
            .send()
            .await
            .context("transmission request failed")?;
        if response.status() == StatusCode::CONFLICT {
            session_id = response
                .headers()
                .get("X-Transmission-Session-Id")
                .and_then(|value| value.to_str().ok())
                .map(str::to_string);
            continue;
        }
        if !response.status().is_success() {
            bail!("transmission RPC failed with HTTP {}", response.status());
        }
        let json = response
            .json::<Value>()
            .await
            .context("failed decoding transmission response")?;
        return Ok(json);
    }

    Err(anyhow!("failed negotiating transmission session ID"))
}

async fn rtorrent_rpc(
    endpoint: &str,
    method: &str,
    params: &[String],
    allow_insecure: bool,
) -> Result<()> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(allow_insecure)
        .timeout(Duration::from_secs(15))
        .build()
        .context("failed to create rTorrent HTTP client")?;

    let params_refs = params.iter().map(String::as_str).collect::<Vec<_>>();
    let payload = xmlrpc_request(method, &params_refs);

    let response = client
        .post(endpoint)
        .header("Content-Type", "text/xml")
        .body(payload)
        .send()
        .await
        .with_context(|| format!("rTorrent request failed for method `{method}`"))?;

    if !response.status().is_success() {
        bail!(
            "rTorrent XML-RPC `{method}` failed with HTTP {}",
            response.status()
        );
    }

    let body = response.text().await.unwrap_or_default();
    if body.contains("<fault>") {
        bail!(
            "rTorrent XML-RPC fault on `{method}`: {}",
            truncate(&body.replace('\n', " "), 220)
        );
    }
    Ok(())
}

#[cfg(feature = "librqbit-embedded")]
struct SelectedTorrentFiles {
    file_indices: Vec<usize>,
}

#[cfg(feature = "librqbit-embedded")]
fn select_torrent_files(
    info: &librqbit::TorrentMetaV1Info<librqbit::ByteBufOwned>,
    prompt: &str,
    file_filter: &[String],
) -> Result<SelectedTorrentFiles> {
    let matcher = build_filter_matcher(file_filter)?;
    let keywords = build_keywords(prompt, file_filter);

    let mut direct_matches = Vec::<(usize, i64, u64)>::new();
    let mut archive_matches = Vec::<(usize, i64, u64)>::new();

    for (idx, details) in info
        .iter_file_details()
        .context("failed to iterate torrent files")?
        .enumerate()
    {
        let filename = details
            .filename
            .to_string()
            .unwrap_or_else(|_| "<invalid-name>".to_string());
        let path = Path::new(&filename);
        let lower = filename.to_ascii_lowercase();
        let size = details.len;

        let mut score = 0_i64;
        for keyword in &keywords {
            if lower.contains(keyword) {
                score += 8;
            }
        }
        if lower.contains("sample") || lower.contains("preview") {
            score -= 12;
        }
        score += ((size / (128 * 1024 * 1024)) as i64).min(24);

        let matched_filter = matcher.as_ref().map(|m| m.is_match(path)).unwrap_or(false);

        if matched_filter && !is_archive_filename(&lower) {
            direct_matches.push((idx, score + 30, size));
            continue;
        }

        if is_archive_filename(&lower) {
            let archive_boost = if matched_filter { 25 } else { 0 };
            archive_matches.push((idx, score + archive_boost + 15, size));
        }
    }

    if !direct_matches.is_empty() {
        direct_matches.sort_by(|l, r| r.1.cmp(&l.1).then_with(|| r.2.cmp(&l.2)));
        let selected = direct_matches
            .into_iter()
            .map(|(idx, _, _)| idx)
            .take(8)
            .collect::<Vec<_>>();
        return Ok(SelectedTorrentFiles {
            file_indices: selected,
        });
    }

    archive_matches.sort_by(|l, r| r.1.cmp(&l.1).then_with(|| r.2.cmp(&l.2)));
    let selected = archive_matches
        .into_iter()
        .map(|(idx, _, _)| idx)
        .take(1)
        .collect::<Vec<_>>();

    Ok(SelectedTorrentFiles {
        file_indices: selected,
    })
}

#[cfg(feature = "librqbit-embedded")]
fn build_filter_matcher(file_filter: &[String]) -> Result<Option<GlobSet>> {
    let mut builder = GlobSetBuilder::new();
    let mut added = 0usize;
    for raw in file_filter {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(glob) = Glob::new(trimmed) {
            builder.add(glob);
            added += 1;
        }
    }
    if added == 0 {
        return Ok(None);
    }
    Ok(Some(
        builder
            .build()
            .context("failed compiling torrent filter matcher")?,
    ))
}

#[cfg(feature = "librqbit-embedded")]
fn build_keywords(prompt: &str, file_filter: &[String]) -> Vec<String> {
    let mut keywords = HashSet::new();
    for source in std::iter::once(prompt).chain(file_filter.iter().map(String::as_str)) {
        for token in source
            .to_ascii_lowercase()
            .split(|c: char| !c.is_ascii_alphanumeric())
        {
            let token = token.trim();
            if token.len() < 2 {
                continue;
            }
            if matches!(
                token,
                "the"
                    | "and"
                    | "for"
                    | "from"
                    | "with"
                    | "file"
                    | "files"
                    | "download"
                    | "archive"
                    | "rom"
                    | "set"
            ) {
                continue;
            }
            keywords.insert(token.to_string());
        }
    }
    let mut values = keywords.into_iter().collect::<Vec<_>>();
    values.sort();
    values
}

#[cfg(feature = "librqbit-embedded")]
fn is_archive_filename(filename_lower: &str) -> bool {
    [
        ".zip", ".7z", ".rar", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz",
        ".tar.zst", ".tzst", ".zst", ".gz", ".bz2", ".xz",
    ]
    .iter()
    .any(|suffix| filename_lower.ends_with(suffix))
}

fn parse_torznab_feed(xml: &str) -> Vec<TorznabSearchResult> {
    let Ok(item_re) = Regex::new(r"(?is)<item\b[^>]*>(.*?)</item>") else {
        return Vec::new();
    };
    let Ok(title_re) = Regex::new(r"(?is)<title\b[^>]*>(.*?)</title>") else {
        return Vec::new();
    };
    let Ok(link_re) = Regex::new(r"(?is)<link\b[^>]*>(.*?)</link>") else {
        return Vec::new();
    };
    let Ok(guid_re) = Regex::new(r"(?is)<guid\b[^>]*>(.*?)</guid>") else {
        return Vec::new();
    };
    let Ok(enclosure_url_re) =
        Regex::new(r#"(?is)<enclosure\b[^>]*\burl\s*=\s*["']([^"']+)["'][^>]*>"#)
    else {
        return Vec::new();
    };
    let Ok(enclosure_len_re) =
        Regex::new(r#"(?is)<enclosure\b[^>]*\blength\s*=\s*["']([^"']+)["'][^>]*>"#)
    else {
        return Vec::new();
    };
    let Ok(attr_re) = Regex::new(
        r#"(?is)<torznab:attr\b[^>]*\bname\s*=\s*["']([^"']+)["'][^>]*\bvalue\s*=\s*["']([^"']*)["'][^>]*>"#,
    ) else {
        return Vec::new();
    };

    let mut items = Vec::new();
    for captures in item_re.captures_iter(xml) {
        let Some(item_raw) = captures.get(1).map(|m| m.as_str()) else {
            continue;
        };

        let title = title_re
            .captures(item_raw)
            .and_then(|m| m.get(1).map(|v| decode_xml_text(v.as_str())))
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "untitled".to_string());

        let details_url = guid_re
            .captures(item_raw)
            .and_then(|m| m.get(1).map(|v| decode_xml_text(v.as_str())))
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .or_else(|| {
                link_re
                    .captures(item_raw)
                    .and_then(|m| m.get(1).map(|v| decode_xml_text(v.as_str())))
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
            });

        let download_url = enclosure_url_re
            .captures(item_raw)
            .and_then(|m| m.get(1).map(|v| decode_xml_text(v.as_str())))
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .or_else(|| {
                link_re
                    .captures(item_raw)
                    .and_then(|m| m.get(1).map(|v| decode_xml_text(v.as_str())))
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
            })
            .or_else(|| {
                guid_re
                    .captures(item_raw)
                    .and_then(|m| m.get(1).map(|v| decode_xml_text(v.as_str())))
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
            });

        let Some(download_url) = download_url else {
            continue;
        };

        let mut attrs = HashMap::<String, String>::new();
        for attr_caps in attr_re.captures_iter(item_raw) {
            let Some(name) = attr_caps.get(1).map(|m| m.as_str()) else {
                continue;
            };
            let Some(value) = attr_caps.get(2).map(|m| m.as_str()) else {
                continue;
            };
            attrs.insert(
                name.trim().to_ascii_lowercase(),
                decode_xml_text(value).trim().to_string(),
            );
        }

        let seeders = attrs
            .get("seeders")
            .and_then(|value| value.parse::<i64>().ok())
            .or_else(|| {
                attrs
                    .get("peers")
                    .and_then(|value| value.parse::<i64>().ok())
            });
        let indexer = attrs
            .get("indexer")
            .or_else(|| attrs.get("jackettindexer"))
            .cloned()
            .filter(|value| !value.trim().is_empty());
        let size_bytes = attrs
            .get("size")
            .and_then(|value| value.parse::<u64>().ok())
            .or_else(|| {
                enclosure_len_re
                    .captures(item_raw)
                    .and_then(|m| m.get(1).map(|v| v.as_str().trim().to_string()))
                    .and_then(|value| value.parse::<u64>().ok())
            });

        items.push(TorznabSearchResult {
            title,
            download_url,
            details_url,
            seeders,
            size_bytes,
            indexer,
        });
    }

    items
}

fn parse_torznab_error(xml: &str) -> Option<String> {
    let Ok(error_re) = Regex::new(
        r#"(?is)<error\b[^>]*\bcode\s*=\s*["']([^"']*)["'][^>]*\bdescription\s*=\s*["']([^"']*)["'][^>]*/?>"#,
    ) else {
        return None;
    };
    let Some(captures) = error_re.captures(xml) else {
        return None;
    };
    let code = captures
        .get(1)
        .map(|m| decode_xml_text(m.as_str()))
        .unwrap_or_default();
    let description = captures
        .get(2)
        .map(|m| decode_xml_text(m.as_str()))
        .unwrap_or_else(|| "Unknown Torznab error".to_string());
    let code = code.trim();
    if code.is_empty() {
        Some(description.trim().to_string())
    } else {
        Some(format!("code {code}: {}", description.trim()))
    }
}

fn decode_xml_text(raw: &str) -> String {
    let mut text = raw.trim().to_string();
    if text.starts_with("<![CDATA[") && text.ends_with("]]>") && text.len() >= 12 {
        text = text[9..text.len() - 3].to_string();
    }
    text.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
}

fn build_torznab_query(prompt: &str) -> String {
    let stop_words = HashSet::from([
        "a", "an", "and", "archive", "as", "at", "by", "download", "file", "files", "for", "from",
        "get", "in", "is", "it", "my", "of", "on", "or", "site", "the", "to", "with",
    ]);
    let mut tokens = Vec::new();
    let mut seen = HashSet::new();

    for token in prompt
        .to_ascii_lowercase()
        .split(|ch: char| !ch.is_ascii_alphanumeric())
    {
        let trimmed = token.trim();
        if trimmed.len() < 2 || stop_words.contains(trimmed) {
            continue;
        }
        if seen.insert(trimmed.to_string()) {
            tokens.push(trimmed.to_string());
        }
        if tokens.len() >= 12 {
            break;
        }
    }

    if tokens.is_empty() {
        prompt.trim().to_string()
    } else {
        tokens.join(" ")
    }
}

fn torznab_query_keywords(query: &str) -> Vec<String> {
    query
        .to_ascii_lowercase()
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .map(str::trim)
        .filter(|value| value.len() >= 2)
        .map(str::to_string)
        .collect::<Vec<_>>()
}

fn torznab_score(item: &TorznabSearchResult, keywords: &[String]) -> i64 {
    let title = item.title.to_ascii_lowercase();
    let mut score = 0_i64;
    for keyword in keywords {
        if title.contains(keyword) {
            score += 10;
        }
    }

    if title.contains("sample") || title.contains("trailer") || title.contains("cam") {
        score -= 18;
    }
    if item.download_url.starts_with("magnet:") {
        score += 8;
    }
    if let Some(seeders) = item.seeders {
        score += seeders.clamp(0, 600) / 6;
    }
    if let Some(size) = item.size_bytes {
        let size_boost = (size / (100 * 1024 * 1024)) as i64;
        score += size_boost.clamp(0, 24);
    }

    score
}

fn rank_torznab_results(results: &mut [TorznabSearchResult], query: &str) {
    let keywords = torznab_query_keywords(query);
    results.sort_by(|left, right| {
        let right_score = torznab_score(right, &keywords);
        let left_score = torznab_score(left, &keywords);
        right_score
            .cmp(&left_score)
            .then_with(|| right.seeders.unwrap_or(0).cmp(&left.seeders.unwrap_or(0)))
            .then_with(|| left.title.len().cmp(&right.title.len()))
    });
}

fn is_torznab_download_url(url: &str) -> bool {
    let lower = url.trim().to_ascii_lowercase();
    lower.starts_with("magnet:") || lower.starts_with("http://") || lower.starts_with("https://")
}

fn extract_magnet_hash(source: &str) -> Option<String> {
    if !source.starts_with("magnet:") {
        return None;
    }
    let re = Regex::new(r"(?i)xt=urn:btih:([a-z0-9]{32,40})").ok()?;
    re.captures(source)
        .and_then(|caps| caps.get(1))
        .map(|m| m.as_str().to_ascii_lowercase())
}

fn fallback_torrent_id(prefix: &str, source: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(source.as_bytes());
    let digest = hasher.finalize();
    format!("{prefix}-{:x}", digest)[..20.min(prefix.len() + 1 + 64)].to_string()
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

fn escape_deluge_arg(input: &str) -> String {
    input
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace(';', "\\;")
}

fn truncate(input: &str, max: usize) -> String {
    if input.len() <= max {
        return input.to_string();
    }
    format!("{}...", &input[..max])
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

#[cfg(test)]
mod tests {
    use super::{
        build_torznab_query, parse_torznab_error, parse_torznab_feed, rank_torznab_results,
    };

    #[test]
    fn torznab_query_removes_common_noise_tokens() {
        let query = build_torznab_query("download the tmnt arcade nes rom from a torrent site");
        assert!(query.contains("tmnt"));
        assert!(query.contains("arcade"));
        assert!(query.contains("nes"));
        assert!(!query.contains("download"));
        assert!(!query.contains("site"));
    }

    #[test]
    fn torznab_feed_parser_extracts_core_fields() {
        let xml = r#"<?xml version="1.0"?>
<rss>
  <channel>
    <item>
      <title><![CDATA[TMNT Arcade Game (USA)]]></title>
      <guid>https://example.test/details/123</guid>
      <link>magnet:?xt=urn:btih:abcdef0123456789abcdef0123456789abcdef01</link>
      <torznab:attr name="seeders" value="57" />
      <torznab:attr name="indexer" value="DemoIndexer" />
      <torznab:attr name="size" value="123456789" />
    </item>
  </channel>
</rss>"#;

        let mut items = parse_torznab_feed(xml);
        assert_eq!(items.len(), 1);
        let item = items.remove(0);
        assert_eq!(item.title, "TMNT Arcade Game (USA)");
        assert!(item.download_url.starts_with("magnet:?xt=urn:btih:"));
        assert_eq!(item.seeders, Some(57));
        assert_eq!(item.indexer.as_deref(), Some("DemoIndexer"));
        assert_eq!(item.size_bytes, Some(123456789));
        assert_eq!(
            item.details_url.as_deref(),
            Some("https://example.test/details/123")
        );
    }

    #[test]
    fn torznab_ranking_prefers_seeded_keyword_matches() {
        let xml = r#"<?xml version="1.0"?>
<rss>
  <channel>
    <item>
      <title>TMNT Arcade Good Release</title>
      <link>magnet:?xt=urn:btih:1111111111111111111111111111111111111111</link>
      <torznab:attr name="seeders" value="45" />
    </item>
    <item>
      <title>Unrelated title sample</title>
      <link>magnet:?xt=urn:btih:2222222222222222222222222222222222222222</link>
      <torznab:attr name="seeders" value="2" />
    </item>
  </channel>
</rss>"#;

        let mut items = parse_torznab_feed(xml);
        rank_torznab_results(&mut items, "tmnt arcade");
        assert_eq!(items[0].title, "TMNT Arcade Good Release");
    }

    #[test]
    fn torznab_error_parser_extracts_code_and_description() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<error code="100" description="Invalid API Key" />"#;

        let error = parse_torznab_error(xml);
        assert_eq!(error.as_deref(), Some("code 100: Invalid API Key"));
    }
}
