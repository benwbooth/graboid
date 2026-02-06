use std::future::Future;
#[cfg(feature = "librqbit-embedded")]
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use regex::Regex;
use reqwest::StatusCode;
use serde_json::{Value, json};
use tokio::process::Command;

use crate::config::AppConfig;

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
    use librqbit::{AddTorrent, Session, SessionOptions, SessionPersistenceConfig};
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

    let session = SESSION
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
        .await?
        .clone();

    let add_request = if source.starts_with("magnet:")
        || source.starts_with("http://")
        || source.starts_with("https://")
    {
        AddTorrent::from_url(source)
    } else {
        let bytes = tokio::fs::read(source)
            .await
            .with_context(|| format!("failed reading torrent file {source}"))?;
        AddTorrent::from_bytes(bytes)
    };

    session
        .add_torrent(add_request, None)
        .await
        .context("embedded torrent add failed")?;

    Ok(extract_magnet_hash(source).unwrap_or_else(|| fallback_torrent_id("embedded", source)))
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
