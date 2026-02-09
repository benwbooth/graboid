use std::collections::HashSet;
use std::fs;
#[cfg(any(
    feature = "remote-ftp",
    feature = "remote-sftp",
    feature = "remote-samba"
))]
use std::io::Read;
#[cfg(feature = "remote-sftp")]
use std::net::TcpStream;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use regex::Regex;
use serde_json::{Value, json};
use tokio::io::{self, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};

#[cfg(any(feature = "remote-ftp", feature = "remote-samba"))]
use remotefs::RemoteFs;
#[cfg(feature = "remote-ftp")]
use remotefs_ftp::FtpFs;
#[cfg(feature = "remote-samba")]
use remotefs_smb::{SmbCredentials, SmbFs, SmbOptions};
#[cfg(feature = "remote-sftp")]
use ssh2::{Session, Sftp};

use crate::config::{AppConfig, NamedSource};
use crate::path_policy::LocalPathPolicy;
use crate::torrent;

const JSONRPC_VERSION: &str = "2.0";
const MCP_PROTOCOL_VERSION: &str = "2024-11-05";

pub async fn run_stdio_server_from_cli() -> Result<()> {
    let mut config_path: Option<PathBuf> = None;
    let mut args = std::env::args().skip(2);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" => {
                let Some(path) = args.next() else {
                    return Err(anyhow!("--config requires a path value"));
                };
                config_path = Some(PathBuf::from(path));
            }
            _ => {}
        }
    }

    run_stdio_server(config_path.as_deref()).await
}

async fn run_stdio_server(config_path: Option<&Path>) -> Result<()> {
    let mut reader = BufReader::new(io::stdin());
    let mut writer = BufWriter::new(io::stdout());

    loop {
        let Some(payload) = read_jsonrpc_message(&mut reader).await? else {
            break;
        };

        let request = match parse_jsonrpc_request(payload) {
            Ok(request) => request,
            Err(err) => {
                let response = jsonrpc_error_response(
                    Value::Null,
                    -32700,
                    "Invalid JSON-RPC request",
                    err.to_string(),
                );
                write_jsonrpc_message(&mut writer, &response).await?;
                continue;
            }
        };

        let Some(id) = request.id.clone() else {
            handle_notification(&request.method);
            continue;
        };

        let response = handle_request(id, &request.method, &request.params, config_path).await;
        write_jsonrpc_message(&mut writer, &response).await?;
    }

    Ok(())
}

#[derive(Debug, Clone)]
struct JsonRpcRequest {
    id: Option<Value>,
    method: String,
    params: Value,
}

fn parse_jsonrpc_request(payload: Value) -> Result<JsonRpcRequest> {
    let object = payload
        .as_object()
        .ok_or_else(|| anyhow!("request payload must be a JSON object"))?;
    let method = object
        .get("method")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("request.method must be a string"))?
        .to_string();

    Ok(JsonRpcRequest {
        id: object.get("id").cloned(),
        method,
        params: object.get("params").cloned().unwrap_or(Value::Null),
    })
}

fn handle_notification(method: &str) {
    let _ = method;
}

async fn handle_request(
    id: Value,
    method: &str,
    params: &Value,
    config_path: Option<&Path>,
) -> Value {
    match method {
        "initialize" => {
            let protocol = params
                .get("protocolVersion")
                .and_then(Value::as_str)
                .unwrap_or(MCP_PROTOCOL_VERSION);
            jsonrpc_ok_response(
                id,
                json!({
                    "protocolVersion": protocol,
                    "capabilities": {
                        "tools": {}
                    },
                    "serverInfo": {
                        "name": "graboid-tools",
                        "version": env!("CARGO_PKG_VERSION")
                    },
                    "instructions": "Use these tools for Torznab search and torrent client operations."
                }),
            )
        }
        "ping" => jsonrpc_ok_response(id, json!({})),
        "tools/list" => jsonrpc_ok_response(id, json!({ "tools": tool_definitions() })),
        "tools/call" => match handle_tool_call(params, config_path).await {
            Ok(result) => jsonrpc_ok_response(id, result),
            Err(err) => jsonrpc_ok_response(id, tool_error_result(&err.to_string())),
        },
        _ => jsonrpc_error_response(id, -32601, "Method not found", method.to_string()),
    }
}

fn tool_definitions() -> Vec<Value> {
    vec![
        json!({
            "name": "torznab_search",
            "description": "Search the configured Torznab endpoint and return ranked torrent candidates.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": { "type": "string", "description": "Search query text." },
                    "fresh": { "type": "boolean", "description": "If true, request uncached indexer results." },
                    "max_results": { "type": "integer", "minimum": 1, "maximum": 200, "description": "Maximum results to return." }
                },
                "required": ["query"],
                "additionalProperties": false
            }
        }),
        json!({
            "name": "web_search_links",
            "description": "Fetch an HTML page and list links, optionally filtered by query terms. Useful for large directory pages.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "url": { "type": "string", "description": "HTTP/HTTPS page URL to scan." },
                    "query": { "type": "string", "description": "Optional search text; links are filtered by these terms." },
                    "match_mode": {
                        "type": "string",
                        "enum": ["all", "any"],
                        "description": "When query has multiple terms, require all or any term match. Default: all."
                    },
                    "offset": { "type": "integer", "minimum": 0, "description": "Skip this many matched links before returning results." },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 500, "description": "Maximum links to return. Default: 200." },
                    "max_fetch_bytes": { "type": "integer", "minimum": 4096, "maximum": 4000000, "description": "Maximum HTML bytes to fetch/parse. Default: 2000000." }
                },
                "required": ["url"],
                "additionalProperties": false
            }
        }),
        json!({
            "name": "torrent_add",
            "description": "Add a magnet/.torrent/URL to the configured torrent client backend.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "source": { "type": "string", "description": "Magnet URI, torrent URL, or torrent file path." },
                    "client": {
                        "type": "string",
                        "enum": ["auto", "embedded", "qbittorrent", "transmission", "deluge", "rtorrent", "aria2"],
                        "description": "Optional override for this call only."
                    }
                },
                "required": ["source"],
                "additionalProperties": false
            }
        }),
        json!({
            "name": "torrent_selective_fetch",
            "description": "For embedded/auto backend, list and selectively download torrent contents using prompt + file filter patterns.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "source": { "type": "string", "description": "Magnet URI, torrent URL, or torrent file path." },
                    "prompt": { "type": "string", "description": "Task prompt context used for selection." },
                    "file_filter": { "type": "array", "items": { "type": "string" }, "description": "Glob-style patterns for desired files." }
                },
                "required": ["source", "prompt", "file_filter"],
                "additionalProperties": false
            }
        }),
        json!({
            "name": "source_catalog",
            "description": "List configured named sources (SFTP/FTP/Samba) and local filesystem allowlists.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }
        }),
        json!({
            "name": "source_list_dir",
            "description": "List directory entries from local or named remote sources (SFTP/FTP/Samba).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "source_name": { "type": "string", "description": "Optional source name from `source_catalog`; omit or use `local` for local filesystem." },
                    "path": { "type": "string", "description": "Directory path to list." }
                },
                "required": ["path"],
                "additionalProperties": false
            }
        }),
        json!({
            "name": "source_read_text",
            "description": "Read a text file from local or named remote sources.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "source_name": { "type": "string", "description": "Optional source name from `source_catalog`; omit or use `local` for local filesystem." },
                    "path": { "type": "string", "description": "File path to read." },
                    "max_bytes": { "type": "integer", "minimum": 1, "maximum": 1048576, "description": "Optional max bytes to read." }
                },
                "required": ["path"],
                "additionalProperties": false
            }
        }),
        json!({
            "name": "source_copy_to_downloads",
            "description": "Copy a file from local or named remote sources into Graboid's download directory.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "source_name": { "type": "string", "description": "Optional source name from `source_catalog`; omit or use `local` for local filesystem." },
                    "path": { "type": "string", "description": "Source file path." },
                    "destination_subpath": { "type": "string", "description": "Optional relative path under downloads for target file or folder." }
                },
                "required": ["path"],
                "additionalProperties": false
            }
        }),
        json!({
            "name": "torrent_client_info",
            "description": "Return current torrent and Torznab configuration visibility for planning tool calls.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }
        }),
    ]
}

async fn handle_tool_call(params: &Value, config_path: Option<&Path>) -> Result<Value> {
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("tools/call params.name is required"))?;
    let args = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let cfg = load_runtime_config(config_path);
    let path_policy = LocalPathPolicy::from_config(&cfg);
    let named_sources = cfg.named_sources();

    match name {
        "torznab_search" => {
            let query = required_string(&args, "query")?;
            let fresh = optional_bool(&args, "fresh").unwrap_or(false);
            let max_results = optional_u64(&args, "max_results")
                .map(|value| value.clamp(1, 200) as usize)
                .unwrap_or_else(|| cfg.torznab_max_results.clamp(1, 200));

            let mut results = if fresh {
                torrent::search_torznab_fresh(&cfg, query).await?
            } else {
                torrent::search_torznab(&cfg, query).await?
            };
            if results.len() > max_results {
                results.truncate(max_results);
            }

            let structured = json!({
                "query": query,
                "fresh": fresh,
                "count": results.len(),
                "results": results.iter().map(|item| {
                    json!({
                        "title": item.title,
                        "download_url": item.download_url,
                        "details_url": item.details_url,
                        "seeders": item.seeders,
                        "size_bytes": item.size_bytes,
                        "indexer": item.indexer
                    })
                }).collect::<Vec<_>>()
            });
            Ok(tool_ok_result(
                &format_torznab_text(query, fresh, &results),
                structured,
            ))
        }
        "web_search_links" => {
            let page_url = required_string(&args, "url")?;
            let query = optional_string(&args, "query")
                .unwrap_or("")
                .trim()
                .to_string();
            let match_mode = optional_string(&args, "match_mode")
                .unwrap_or("all")
                .to_ascii_lowercase();
            if match_mode != "all" && match_mode != "any" {
                return Ok(tool_error_result(
                    "match_mode must be either `all` or `any`",
                ));
            }
            let offset = optional_u64(&args, "offset").unwrap_or(0) as usize;
            let limit = optional_u64(&args, "limit")
                .map(|value| value.clamp(1, 500) as usize)
                .unwrap_or(200);
            let max_fetch_bytes = optional_u64(&args, "max_fetch_bytes")
                .map(|value| value.clamp(4096, 4_000_000) as usize)
                .unwrap_or(2_000_000);

            let (resolved_url, html, truncated) =
                fetch_web_page_html(page_url, max_fetch_bytes).await?;
            let title = extract_html_title(&html);
            let links = extract_html_links(&resolved_url, &html);
            let query_terms = tokenize_query_terms(&query);
            let matched = links
                .into_iter()
                .filter(|entry| {
                    if query_terms.is_empty() {
                        return true;
                    }
                    link_matches_query(entry, &query_terms, &match_mode)
                })
                .collect::<Vec<_>>();
            let total_matched = matched.len();
            let page_links = matched
                .into_iter()
                .skip(offset)
                .take(limit)
                .map(|entry| {
                    json!({
                        "text": entry.text,
                        "href": entry.href,
                        "url": entry.url
                    })
                })
                .collect::<Vec<_>>();

            let structured = json!({
                "url": resolved_url.to_string(),
                "title": title,
                "query": query,
                "match_mode": match_mode,
                "offset": offset,
                "limit": limit,
                "max_fetch_bytes": max_fetch_bytes,
                "html_truncated": truncated,
                "total_matched": total_matched,
                "returned": page_links.len(),
                "links": page_links
            });
            Ok(tool_ok_result(
                &format!(
                    "web_search_links matched {total_matched} link(s) at {} and returned {} result(s) (offset={}, limit={}).",
                    resolved_url,
                    structured["returned"].as_u64().unwrap_or(0),
                    offset,
                    limit
                ),
                structured,
            ))
        }
        "torrent_add" => {
            let source = required_string(&args, "source")?;
            let mut cfg = cfg;
            if let Some(client) = optional_string(&args, "client") {
                cfg.torrent_client = client.to_string();
            }
            let id = torrent::add_torrent(&cfg, source).await?;
            let structured = json!({
                "source": source,
                "torrent_id": id,
                "client": cfg.torrent_client
            });
            Ok(tool_ok_result(
                &format!(
                    "Added torrent source to client `{}` with id `{}`.",
                    cfg.torrent_client, id
                ),
                structured,
            ))
        }
        "torrent_selective_fetch" => {
            let source = required_string(&args, "source")?;
            let prompt = required_string(&args, "prompt")?;
            let file_filter = required_string_array(&args, "file_filter")?;
            let files =
                torrent::selective_fetch_from_torrent(&cfg, source, prompt, &file_filter).await?;
            let file_paths = files
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>();

            let structured = json!({
                "source": source,
                "prompt": prompt,
                "file_filter": file_filter,
                "count": file_paths.len(),
                "files": file_paths
            });
            Ok(tool_ok_result(
                &format!(
                    "Selective torrent fetch completed with {} matching file(s).",
                    files.len()
                ),
                structured,
            ))
        }
        "source_catalog" => {
            let named = named_sources
                .iter()
                .map(|source| {
                    json!({
                        "name": source.name,
                        "kind": source.kind,
                        "host": source.host,
                        "port": source.port,
                        "location": source.location,
                        "username": source.username,
                        "has_password": !source.password.trim().is_empty()
                    })
                })
                .collect::<Vec<_>>();
            let read_allowlist = path_policy
                .read_roots()
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>();
            let write_allowlist = path_policy
                .write_roots()
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>();
            let remote_protocols = json!({
                "ftp": ftp_enabled(),
                "sftp": sftp_enabled(),
                "samba": samba_enabled()
            });

            let structured = json!({
                "named_sources": named,
                "local_read_allowlist": read_allowlist,
                "local_write_allowlist": write_allowlist,
                "remote_protocols": remote_protocols
            });
            Ok(tool_ok_result(
                "Loaded source catalog with local allowlists and remote protocol capabilities.",
                structured,
            ))
        }
        "source_list_dir" => {
            let source_name = optional_string(&args, "source_name");
            let path = required_string(&args, "path")?;
            match resolve_source(source_name, &named_sources)? {
                SourceTarget::Local => {
                    let dir = resolve_local_path(path);
                    if !path_policy.is_read_allowed(&dir) {
                        return Ok(tool_error_result(&format!(
                            "Local read blocked by allowlist: {}",
                            dir.display()
                        )));
                    }
                    let listing = list_local_dir(&dir)?;
                    let structured = json!({
                        "source": "local",
                        "path": dir.display().to_string(),
                        "parent": dir.parent().map(|p| p.display().to_string()),
                        "directories": listing.directories,
                        "files": listing.files
                    });
                    Ok(tool_ok_result(
                        &format!(
                            "Listed {} directories and {} files at {}.",
                            structured["directories"]
                                .as_array()
                                .map(|v| v.len())
                                .unwrap_or(0),
                            structured["files"].as_array().map(|v| v.len()).unwrap_or(0),
                            dir.display()
                        ),
                        structured,
                    ))
                }
                SourceTarget::Named(source) => {
                    let listing = list_named_source_dir(source, path)?;
                    let structured = json!({
                        "source": source.name,
                        "source_kind": source.kind,
                        "path": listing.path,
                        "parent": listing.parent,
                        "directories": listing.directories,
                        "files": listing.files
                    });
                    Ok(tool_ok_result(
                        &format!(
                            "Listed {} directories and {} files at {} via source `{}`.",
                            structured["directories"]
                                .as_array()
                                .map(|v| v.len())
                                .unwrap_or(0),
                            structured["files"].as_array().map(|v| v.len()).unwrap_or(0),
                            structured["path"].as_str().unwrap_or(path),
                            source.name
                        ),
                        structured,
                    ))
                }
            }
        }
        "source_read_text" => {
            let source_name = optional_string(&args, "source_name");
            let path = required_string(&args, "path")?;
            let max_bytes = optional_u64(&args, "max_bytes")
                .unwrap_or(131_072)
                .clamp(1, 1_048_576) as usize;
            match resolve_source(source_name, &named_sources)? {
                SourceTarget::Local => {
                    let file_path = resolve_local_path(path);
                    if !path_policy.is_read_allowed(&file_path) {
                        return Ok(tool_error_result(&format!(
                            "Local read blocked by allowlist: {}",
                            file_path.display()
                        )));
                    }
                    let raw = fs::read(&file_path)
                        .with_context(|| format!("failed reading {}", file_path.display()))?;
                    let truncated = raw.len() > max_bytes;
                    let slice = if truncated { &raw[..max_bytes] } else { &raw };
                    let text = String::from_utf8_lossy(slice).to_string();
                    let structured = json!({
                        "source": "local",
                        "path": file_path.display().to_string(),
                        "bytes_total": raw.len(),
                        "bytes_returned": slice.len(),
                        "truncated": truncated,
                        "text": text
                    });
                    Ok(tool_ok_result(
                        &format!("Read {} byte(s) from {}.", slice.len(), file_path.display()),
                        structured,
                    ))
                }
                SourceTarget::Named(source) => {
                    let read = read_named_source_text(source, path, max_bytes)?;
                    let structured = json!({
                        "source": source.name,
                        "source_kind": source.kind,
                        "path": read.path,
                        "bytes_total": read.bytes_total,
                        "bytes_returned": read.bytes_returned,
                        "truncated": read.truncated,
                        "text": read.text
                    });
                    Ok(tool_ok_result(
                        &format!(
                            "Read {} byte(s) from {} via source `{}`.",
                            read.bytes_returned, read.path, source.name
                        ),
                        structured,
                    ))
                }
            }
        }
        "source_copy_to_downloads" => {
            let source_name = optional_string(&args, "source_name");
            let path = required_string(&args, "path")?;
            let destination_subpath = optional_string(&args, "destination_subpath");
            match resolve_source(source_name, &named_sources)? {
                SourceTarget::Local => {
                    let source_path = resolve_local_path(path);
                    if !path_policy.is_read_allowed(&source_path) {
                        return Ok(tool_error_result(&format!(
                            "Local read blocked by allowlist: {}",
                            source_path.display()
                        )));
                    }

                    let target_path = resolve_download_target(
                        &cfg.download_dir(),
                        &source_path,
                        destination_subpath,
                    )?;
                    if !path_policy.is_write_allowed(&target_path) {
                        return Ok(tool_error_result(&format!(
                            "Local write blocked by allowlist: {}",
                            target_path.display()
                        )));
                    }

                    if let Some(parent) = target_path.parent() {
                        fs::create_dir_all(parent).with_context(|| {
                            format!("failed creating target directory {}", parent.display())
                        })?;
                    }
                    fs::copy(&source_path, &target_path).with_context(|| {
                        format!(
                            "failed copying {} -> {}",
                            source_path.display(),
                            target_path.display()
                        )
                    })?;

                    let structured = json!({
                        "source": "local",
                        "source_path": source_path.display().to_string(),
                        "target_path": target_path.display().to_string()
                    });
                    Ok(tool_ok_result(
                        &format!(
                            "Copied file from {} to {}.",
                            source_path.display(),
                            target_path.display()
                        ),
                        structured,
                    ))
                }
                SourceTarget::Named(source) => {
                    let source_path = resolve_named_remote_path(source, path)?;
                    let target_path = resolve_download_target(
                        &cfg.download_dir(),
                        Path::new(&source_path),
                        destination_subpath,
                    )?;
                    if !path_policy.is_write_allowed(&target_path) {
                        return Ok(tool_error_result(&format!(
                            "Local write blocked by allowlist: {}",
                            target_path.display()
                        )));
                    }
                    let copy = copy_named_source_file(source, &source_path, &target_path)?;
                    let structured = json!({
                        "source": source.name,
                        "source_kind": source.kind,
                        "source_path": copy.source_path,
                        "target_path": copy.target_path.display().to_string(),
                        "bytes_copied": copy.bytes_copied
                    });
                    Ok(tool_ok_result(
                        &format!(
                            "Copied {} byte(s) from {} to {} via source `{}`.",
                            copy.bytes_copied,
                            copy.source_path,
                            copy.target_path.display(),
                            source.name
                        ),
                        structured,
                    ))
                }
            }
        }
        "torrent_client_info" => {
            let structured = json!({
                "torrent_client": cfg.torrent_client,
                "download_dir": cfg.download_dir,
                "embedded_backend_available": torrent::embedded_backend_available(),
                "embedded_backend_message": torrent::embedded_backend_message(),
                "torznab_enabled": cfg.torznab_enabled,
                "torznab_endpoint": cfg.torznab_endpoint,
                "torznab_categories": cfg.torznab_categories,
                "torznab_max_results": cfg.torznab_max_results,
                "named_sources_count": named_sources.len(),
                "local_read_allowlist": path_policy.read_roots().iter().map(|path| path.display().to_string()).collect::<Vec<_>>(),
                "local_write_allowlist": path_policy.write_roots().iter().map(|path| path.display().to_string()).collect::<Vec<_>>(),
            });
            Ok(tool_ok_result(
                "Loaded torrent client and Torznab runtime configuration.",
                structured,
            ))
        }
        _ => Ok(tool_error_result(&format!("Unknown tool `{name}`"))),
    }
}

fn required_string<'a>(args: &'a Value, key: &str) -> Result<&'a str> {
    args.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("missing required string argument `{key}`"))
}

fn optional_string<'a>(args: &'a Value, key: &str) -> Option<&'a str> {
    args.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn optional_bool(args: &Value, key: &str) -> Option<bool> {
    args.get(key).and_then(Value::as_bool)
}

fn optional_u64(args: &Value, key: &str) -> Option<u64> {
    args.get(key).and_then(Value::as_u64)
}

fn required_string_array(args: &Value, key: &str) -> Result<Vec<String>> {
    let values = args
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("missing required string array argument `{key}`"))?;
    let mut out = Vec::new();
    for value in values {
        let Some(item) = value.as_str() else {
            continue;
        };
        let trimmed = item.trim();
        if trimmed.is_empty() {
            continue;
        }
        out.push(trimmed.to_string());
    }
    if out.is_empty() {
        return Err(anyhow!("argument `{key}` cannot be empty"));
    }
    Ok(out)
}

fn load_runtime_config(config_path: Option<&Path>) -> AppConfig {
    if let Some(path) = config_path {
        AppConfig::load_from_path(path)
    } else {
        AppConfig::load()
    }
}

enum SourceTarget<'a> {
    Local,
    Named(&'a NamedSource),
}

fn resolve_source<'a>(
    source_name: Option<&str>,
    named_sources: &'a [NamedSource],
) -> Result<SourceTarget<'a>> {
    let Some(name) = source_name.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(SourceTarget::Local);
    };
    if name.eq_ignore_ascii_case("local") {
        return Ok(SourceTarget::Local);
    }

    named_sources
        .iter()
        .find(|source| source.name.eq_ignore_ascii_case(name))
        .map(SourceTarget::Named)
        .ok_or_else(|| anyhow!("unknown source `{name}`; check source_catalog for valid names"))
}

#[derive(Default)]
struct LocalDirListing {
    directories: Vec<Value>,
    files: Vec<Value>,
}

fn list_local_dir(path: &Path) -> Result<LocalDirListing> {
    if !path.exists() {
        return Err(anyhow!("directory does not exist: {}", path.display()));
    }
    if !path.is_dir() {
        return Err(anyhow!("path is not a directory: {}", path.display()));
    }

    let mut entries = fs::read_dir(path)
        .with_context(|| format!("failed listing {}", path.display()))?
        .filter_map(|entry| entry.ok())
        .collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.file_name().to_string_lossy().to_string());

    let mut listing = LocalDirListing::default();
    for entry in entries.into_iter().take(400) {
        let name = entry.file_name().to_string_lossy().to_string();
        let entry_path = normalize_local_path(&entry.path());
        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(_) => continue,
        };

        if metadata.is_dir() {
            listing.directories.push(json!({
                "name": name,
                "path": entry_path.display().to_string()
            }));
            continue;
        }

        if metadata.is_file() {
            listing.files.push(json!({
                "name": name,
                "path": entry_path.display().to_string(),
                "size_bytes": metadata.len()
            }));
        }
    }

    Ok(listing)
}

fn resolve_local_path(raw: &str) -> PathBuf {
    let input = PathBuf::from(raw.trim());
    let absolute = if input.is_absolute() {
        input
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(input)
    };
    normalize_local_path(&absolute)
}

fn normalize_local_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                let _ = normalized.pop();
            }
            Component::Normal(segment) => normalized.push(segment),
        }
    }
    normalized
}

fn resolve_download_target(
    download_dir: &Path,
    source_path: &Path,
    destination_subpath: Option<&str>,
) -> Result<PathBuf> {
    let source_name = source_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow!("source path has no filename: {}", source_path.display()))?;

    let base = normalize_local_path(download_dir);
    let target = match destination_subpath
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        Some(subpath) => {
            let sub = PathBuf::from(subpath);
            if sub.is_absolute() {
                return Err(anyhow!(
                    "destination_subpath must be relative under download dir"
                ));
            }
            let is_dir_hint = subpath.ends_with('/') || subpath.ends_with('\\');
            let joined = if is_dir_hint {
                base.join(sub).join(source_name)
            } else {
                base.join(sub)
            };
            normalize_local_path(&joined)
        }
        None => base.join(source_name),
    };

    Ok(target)
}

#[derive(Default)]
struct SourceDirListing {
    path: String,
    parent: Option<String>,
    directories: Vec<Value>,
    files: Vec<Value>,
}

struct SourceTextRead {
    path: String,
    bytes_total: usize,
    bytes_returned: usize,
    truncated: bool,
    text: String,
}

struct SourceCopyResult {
    source_path: String,
    target_path: PathBuf,
    bytes_copied: u64,
}

#[cfg(any(
    feature = "remote-ftp",
    feature = "remote-sftp",
    feature = "remote-samba"
))]
#[derive(Clone)]
struct NamedListEntry {
    name: String,
    path: String,
    is_dir: bool,
    size_bytes: Option<u64>,
}

fn ftp_enabled() -> bool {
    cfg!(feature = "remote-ftp")
}

fn sftp_enabled() -> bool {
    cfg!(feature = "remote-sftp")
}

fn samba_enabled() -> bool {
    cfg!(feature = "remote-samba")
}

fn list_named_source_dir(source: &NamedSource, request_path: &str) -> Result<SourceDirListing> {
    match source.kind.as_str() {
        "ftp" => list_ftp_dir(source, request_path),
        "sftp" => list_sftp_dir(source, request_path),
        "samba" => list_samba_dir(source, request_path),
        other => Err(anyhow!(
            "source `{}` has unsupported kind `{other}`; expected one of sftp/ftp/samba",
            source.name
        )),
    }
}

fn read_named_source_text(
    source: &NamedSource,
    request_path: &str,
    max_bytes: usize,
) -> Result<SourceTextRead> {
    match source.kind.as_str() {
        "ftp" => read_ftp_text(source, request_path, max_bytes),
        "sftp" => read_sftp_text(source, request_path, max_bytes),
        "samba" => read_samba_text(source, request_path, max_bytes),
        other => Err(anyhow!(
            "source `{}` has unsupported kind `{other}`; expected one of sftp/ftp/samba",
            source.name
        )),
    }
}

fn copy_named_source_file(
    source: &NamedSource,
    source_path: &str,
    target_path: &Path,
) -> Result<SourceCopyResult> {
    match source.kind.as_str() {
        "ftp" => copy_ftp_file(source, source_path, target_path),
        "sftp" => copy_sftp_file(source, source_path, target_path),
        "samba" => copy_samba_file(source, source_path, target_path),
        other => Err(anyhow!(
            "source `{}` has unsupported kind `{other}`; expected one of sftp/ftp/samba",
            source.name
        )),
    }
}

#[cfg(feature = "remote-ftp")]
fn list_ftp_dir(source: &NamedSource, request_path: &str) -> Result<SourceDirListing> {
    let resolved = resolve_named_remote_path(source, request_path)?;
    with_ftp_client(source, |client| {
        let entries = client
            .list_dir(Path::new(&resolved))
            .map_err(|err| anyhow!("FTP list_dir failed for `{resolved}`: {err}"))?;
        let listing_entries = map_remotefs_entries(entries);
        Ok(build_named_listing(&resolved, listing_entries))
    })
}

#[cfg(feature = "remote-ftp")]
fn read_ftp_text(
    source: &NamedSource,
    request_path: &str,
    max_bytes: usize,
) -> Result<SourceTextRead> {
    let resolved = resolve_named_remote_path(source, request_path)?;
    with_ftp_client(source, |client| {
        let stat_size = client
            .stat(Path::new(&resolved))
            .ok()
            .map(|entry| entry.metadata().size as usize);
        let mut stream = client
            .open(Path::new(&resolved))
            .map_err(|err| anyhow!("FTP open failed for `{resolved}`: {err}"))?;
        let (bytes, truncated_from_read) = read_limited_bytes(&mut stream, max_bytes)
            .with_context(|| format!("failed reading FTP file `{resolved}`"))?;
        client
            .on_read(stream)
            .map_err(|err| anyhow!("FTP finalize read failed for `{resolved}`: {err}"))?;
        Ok(build_text_read_result(
            &resolved,
            bytes,
            stat_size,
            truncated_from_read,
            max_bytes,
        ))
    })
}

#[cfg(feature = "remote-ftp")]
fn copy_ftp_file(
    source: &NamedSource,
    source_path: &str,
    target_path: &Path,
) -> Result<SourceCopyResult> {
    with_ftp_client(source, |client| {
        if let Some(parent) = target_path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("failed creating target directory {}", parent.display())
            })?;
        }
        let mut stream = client
            .open(Path::new(source_path))
            .map_err(|err| anyhow!("FTP open failed for `{source_path}`: {err}"))?;
        let mut out = fs::File::create(target_path)
            .with_context(|| format!("failed creating target file {}", target_path.display()))?;
        let copied = std::io::copy(&mut stream, &mut out).with_context(|| {
            format!(
                "failed copying FTP file `{source_path}` to {}",
                target_path.display()
            )
        })?;
        client
            .on_read(stream)
            .map_err(|err| anyhow!("FTP finalize read failed for `{source_path}`: {err}"))?;
        Ok(SourceCopyResult {
            source_path: source_path.to_string(),
            target_path: target_path.to_path_buf(),
            bytes_copied: copied,
        })
    })
}

#[cfg(feature = "remote-ftp")]
fn with_ftp_client<T, F>(source: &NamedSource, op: F) -> Result<T>
where
    F: FnOnce(&mut FtpFs) -> Result<T>,
{
    let host = source.host.trim();
    if host.is_empty() {
        return Err(anyhow!("source `{}` has empty host", source.name));
    }
    let port = source.port.unwrap_or(21);
    let mut client = FtpFs::new(host, port);
    if !source.username.trim().is_empty() {
        client = client.username(source.username.trim());
    }
    if !source.password.trim().is_empty() {
        client = client.password(&source.password);
    }
    client
        .connect()
        .map_err(|err| anyhow!("failed connecting FTP source `{}`: {err}", source.name))?;

    let result = op(&mut client);
    let disconnect_result = client.disconnect();
    if let Err(err) = disconnect_result {
        if result.is_ok() {
            return Err(anyhow!(
                "FTP disconnect failed for source `{}`: {err}",
                source.name
            ));
        }
    }
    result
}

#[cfg(not(feature = "remote-ftp"))]
fn list_ftp_dir(source: &NamedSource, _request_path: &str) -> Result<SourceDirListing> {
    Err(anyhow!(
        "source `{}` is ftp but ftp support is disabled in this build; rebuild with `--features remote-ftp`",
        source.name
    ))
}

#[cfg(not(feature = "remote-ftp"))]
fn read_ftp_text(
    source: &NamedSource,
    _request_path: &str,
    _max_bytes: usize,
) -> Result<SourceTextRead> {
    Err(anyhow!(
        "source `{}` is ftp but ftp support is disabled in this build; rebuild with `--features remote-ftp`",
        source.name
    ))
}

#[cfg(not(feature = "remote-ftp"))]
fn copy_ftp_file(
    source: &NamedSource,
    _source_path: &str,
    _target_path: &Path,
) -> Result<SourceCopyResult> {
    Err(anyhow!(
        "source `{}` is ftp but ftp support is disabled in this build; rebuild with `--features remote-ftp`",
        source.name
    ))
}

#[cfg(feature = "remote-sftp")]
fn list_sftp_dir(source: &NamedSource, request_path: &str) -> Result<SourceDirListing> {
    let resolved = resolve_named_remote_path(source, request_path)?;
    with_sftp_client(source, |sftp| {
        let entries = sftp
            .readdir(Path::new(&resolved))
            .with_context(|| format!("SFTP readdir failed for `{resolved}`"))?;
        let mut mapped = Vec::new();
        for (entry_path, stat) in entries {
            let name = entry_path
                .file_name()
                .and_then(|part| part.to_str())
                .unwrap_or_default()
                .to_string();
            if name.is_empty() || name == "." || name == ".." {
                continue;
            }
            let normalized = normalize_remote_path(&entry_path.to_string_lossy());
            let is_dir = stat
                .perm
                .map(sftp_perm_is_dir)
                .unwrap_or_else(|| sftp.opendir(&entry_path).is_ok());
            let size_bytes = if is_dir { None } else { stat.size };
            mapped.push(NamedListEntry {
                name,
                path: normalized,
                is_dir,
                size_bytes,
            });
        }
        Ok(build_named_listing(&resolved, mapped))
    })
}

#[cfg(feature = "remote-sftp")]
fn read_sftp_text(
    source: &NamedSource,
    request_path: &str,
    max_bytes: usize,
) -> Result<SourceTextRead> {
    let resolved = resolve_named_remote_path(source, request_path)?;
    with_sftp_client(source, |sftp| {
        let stat_size = sftp
            .stat(Path::new(&resolved))
            .ok()
            .and_then(|entry| entry.size.map(|value| value as usize));
        let mut file = sftp
            .open(Path::new(&resolved))
            .with_context(|| format!("SFTP open failed for `{resolved}`"))?;
        let (bytes, truncated_from_read) = read_limited_bytes(&mut file, max_bytes)
            .with_context(|| format!("failed reading SFTP file `{resolved}`"))?;
        Ok(build_text_read_result(
            &resolved,
            bytes,
            stat_size,
            truncated_from_read,
            max_bytes,
        ))
    })
}

#[cfg(feature = "remote-sftp")]
fn copy_sftp_file(
    source: &NamedSource,
    source_path: &str,
    target_path: &Path,
) -> Result<SourceCopyResult> {
    with_sftp_client(source, |sftp| {
        if let Some(parent) = target_path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("failed creating target directory {}", parent.display())
            })?;
        }
        let mut file = sftp
            .open(Path::new(source_path))
            .with_context(|| format!("SFTP open failed for `{source_path}`"))?;
        let mut out = fs::File::create(target_path)
            .with_context(|| format!("failed creating target file {}", target_path.display()))?;
        let copied = std::io::copy(&mut file, &mut out).with_context(|| {
            format!(
                "failed copying SFTP file `{source_path}` to {}",
                target_path.display()
            )
        })?;
        Ok(SourceCopyResult {
            source_path: source_path.to_string(),
            target_path: target_path.to_path_buf(),
            bytes_copied: copied,
        })
    })
}

#[cfg(feature = "remote-sftp")]
fn with_sftp_client<T, F>(source: &NamedSource, op: F) -> Result<T>
where
    F: FnOnce(&Sftp) -> Result<T>,
{
    let host = source.host.trim();
    if host.is_empty() {
        return Err(anyhow!("source `{}` has empty host", source.name));
    }
    let username = source.username.trim();
    if username.is_empty() {
        return Err(anyhow!(
            "source `{}` (sftp) requires a username",
            source.name
        ));
    }
    let port = source.port.unwrap_or(22);

    let tcp = TcpStream::connect((host, port))
        .with_context(|| format!("failed connecting to SFTP source `{}`", source.name))?;
    let _ = tcp.set_read_timeout(Some(Duration::from_secs(60)));
    let _ = tcp.set_write_timeout(Some(Duration::from_secs(60)));

    let mut session = Session::new().context("failed creating ssh session")?;
    session.set_tcp_stream(tcp);
    session
        .handshake()
        .with_context(|| format!("SFTP handshake failed for source `{}`", source.name))?;

    if source.password.trim().is_empty() {
        session.userauth_agent(username).with_context(|| {
            format!(
                "SFTP agent auth failed for source `{}` and user `{username}`",
                source.name
            )
        })?;
    } else {
        session
            .userauth_password(username, &source.password)
            .with_context(|| format!("SFTP password auth failed for source `{}`", source.name))?;
    }

    if !session.authenticated() {
        return Err(anyhow!(
            "SFTP authentication failed for source `{}`",
            source.name
        ));
    }

    let sftp = session
        .sftp()
        .with_context(|| format!("failed starting SFTP subsystem for `{}`", source.name))?;
    op(&sftp)
}

#[cfg(not(feature = "remote-sftp"))]
fn list_sftp_dir(source: &NamedSource, _request_path: &str) -> Result<SourceDirListing> {
    Err(anyhow!(
        "source `{}` is sftp but sftp support is disabled in this build; rebuild with `--features remote-sftp`",
        source.name
    ))
}

#[cfg(not(feature = "remote-sftp"))]
fn read_sftp_text(
    source: &NamedSource,
    _request_path: &str,
    _max_bytes: usize,
) -> Result<SourceTextRead> {
    Err(anyhow!(
        "source `{}` is sftp but sftp support is disabled in this build; rebuild with `--features remote-sftp`",
        source.name
    ))
}

#[cfg(not(feature = "remote-sftp"))]
fn copy_sftp_file(
    source: &NamedSource,
    _source_path: &str,
    _target_path: &Path,
) -> Result<SourceCopyResult> {
    Err(anyhow!(
        "source `{}` is sftp but sftp support is disabled in this build; rebuild with `--features remote-sftp`",
        source.name
    ))
}

#[cfg(feature = "remote-samba")]
fn list_samba_dir(source: &NamedSource, request_path: &str) -> Result<SourceDirListing> {
    let resolved = resolve_named_remote_path(source, request_path)?;
    with_samba_client(source, |client| {
        let entries = client
            .list_dir(Path::new(&resolved))
            .map_err(|err| anyhow!("Samba list_dir failed for `{resolved}`: {err}"))?;
        let listing_entries = map_remotefs_entries(entries);
        Ok(build_named_listing(&resolved, listing_entries))
    })
}

#[cfg(not(feature = "remote-samba"))]
fn list_samba_dir(source: &NamedSource, _request_path: &str) -> Result<SourceDirListing> {
    Err(anyhow!(
        "source `{}` is samba but samba support is disabled in this build; rebuild with `--features remote-samba`",
        source.name
    ))
}

#[cfg(feature = "remote-samba")]
fn read_samba_text(
    source: &NamedSource,
    request_path: &str,
    max_bytes: usize,
) -> Result<SourceTextRead> {
    let resolved = resolve_named_remote_path(source, request_path)?;
    with_samba_client(source, |client| {
        let stat_size = client
            .stat(Path::new(&resolved))
            .ok()
            .map(|entry| entry.metadata().size as usize);
        let sink = SharedWriteBuffer::default();
        let sink_clone = sink.clone();
        client
            .open_file(Path::new(&resolved), Box::new(sink_clone))
            .map_err(|err| anyhow!("Samba read failed for `{resolved}`: {err}"))?;
        let bytes = sink.snapshot();
        let truncated_from_read = bytes.len() > max_bytes;
        let truncated_bytes = if truncated_from_read {
            bytes[..max_bytes].to_vec()
        } else {
            bytes
        };
        Ok(build_text_read_result(
            &resolved,
            truncated_bytes,
            stat_size,
            truncated_from_read,
            max_bytes,
        ))
    })
}

#[cfg(not(feature = "remote-samba"))]
fn read_samba_text(
    source: &NamedSource,
    _request_path: &str,
    _max_bytes: usize,
) -> Result<SourceTextRead> {
    Err(anyhow!(
        "source `{}` is samba but samba support is disabled in this build; rebuild with `--features remote-samba`",
        source.name
    ))
}

#[cfg(feature = "remote-samba")]
fn copy_samba_file(
    source: &NamedSource,
    source_path: &str,
    target_path: &Path,
) -> Result<SourceCopyResult> {
    with_samba_client(source, |client| {
        if let Some(parent) = target_path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("failed creating target directory {}", parent.display())
            })?;
        }
        let out = fs::File::create(target_path)
            .with_context(|| format!("failed creating target file {}", target_path.display()))?;
        let copied = client
            .open_file(Path::new(source_path), Box::new(out))
            .map_err(|err| anyhow!("Samba copy failed for `{source_path}`: {err}"))?;
        Ok(SourceCopyResult {
            source_path: source_path.to_string(),
            target_path: target_path.to_path_buf(),
            bytes_copied: copied,
        })
    })
}

#[cfg(not(feature = "remote-samba"))]
fn copy_samba_file(
    source: &NamedSource,
    _source_path: &str,
    _target_path: &Path,
) -> Result<SourceCopyResult> {
    Err(anyhow!(
        "source `{}` is samba but samba support is disabled in this build; rebuild with `--features remote-samba`",
        source.name
    ))
}

#[cfg(feature = "remote-samba")]
fn with_samba_client<T, F>(source: &NamedSource, op: F) -> Result<T>
where
    F: FnOnce(&mut SmbFs) -> Result<T>,
{
    let host = source.host.trim();
    if host.is_empty() {
        return Err(anyhow!("source `{}` has empty host", source.name));
    }

    let server = if host.starts_with("smb://") {
        host.to_string()
    } else if let Some(port) = source.port {
        format!("smb://{host}:{port}")
    } else {
        format!("smb://{host}")
    };

    let share = source.location.trim();
    if share.is_empty() {
        return Err(anyhow!(
            "source `{}` (samba) requires Path/Share in configuration",
            source.name
        ));
    }
    let share = if share.starts_with('/') {
        share.to_string()
    } else {
        format!("/{share}")
    };

    let (username, workgroup) = parse_samba_identity(&source.username);
    let mut credentials = SmbCredentials::default().server(server).share(share);
    if !username.is_empty() {
        credentials = credentials.username(username);
    }
    if !source.password.is_empty() {
        credentials = credentials.password(&source.password);
    }
    if let Some(workgroup) = workgroup.filter(|value| !value.is_empty()) {
        credentials = credentials.workgroup(workgroup);
    }

    let mut client = SmbFs::try_new(credentials, SmbOptions::default())
        .with_context(|| format!("failed constructing Samba client for `{}`", source.name))?;
    client
        .connect()
        .map_err(|err| anyhow!("failed connecting Samba source `{}`: {err}", source.name))?;

    op(&mut client)
}

#[cfg(feature = "remote-samba")]
fn parse_samba_identity(raw_username: &str) -> (String, Option<String>) {
    let trimmed = raw_username.trim();
    if trimmed.is_empty() {
        return (String::new(), None);
    }
    if let Some((workgroup, username)) = trimmed.split_once('\\') {
        return (
            username.trim().to_string(),
            Some(workgroup.trim().to_string()),
        );
    }
    if let Some((workgroup, username)) = trimmed.split_once('/') {
        return (
            username.trim().to_string(),
            Some(workgroup.trim().to_string()),
        );
    }
    (trimmed.to_string(), None)
}

#[cfg(any(feature = "remote-ftp", feature = "remote-samba"))]
fn map_remotefs_entries(entries: Vec<remotefs::File>) -> Vec<NamedListEntry> {
    entries
        .into_iter()
        .filter_map(|entry| {
            let name = entry.name();
            if name.is_empty() || name == "." || name == ".." {
                return None;
            }
            let path = normalize_remote_path(&entry.path().to_string_lossy());
            let is_dir = entry.metadata().is_dir();
            let size_bytes = if is_dir {
                None
            } else {
                Some(entry.metadata().size)
            };
            Some(NamedListEntry {
                name,
                path,
                is_dir,
                size_bytes,
            })
        })
        .collect::<Vec<_>>()
}

#[cfg(any(feature = "remote-ftp", feature = "remote-sftp"))]
fn read_limited_bytes<R: Read>(reader: &mut R, max_bytes: usize) -> Result<(Vec<u8>, bool)> {
    let mut buf = Vec::new();
    let mut limited = reader.take((max_bytes as u64).saturating_add(1));
    limited
        .read_to_end(&mut buf)
        .context("stream read failed while applying max_bytes")?;
    let truncated = buf.len() > max_bytes;
    if truncated {
        buf.truncate(max_bytes);
    }
    Ok((buf, truncated))
}

#[cfg(any(
    feature = "remote-ftp",
    feature = "remote-sftp",
    feature = "remote-samba"
))]
fn build_text_read_result(
    path: &str,
    bytes: Vec<u8>,
    size_hint: Option<usize>,
    truncated_from_read: bool,
    max_bytes: usize,
) -> SourceTextRead {
    let bytes_returned = bytes.len();
    let bytes_total = size_hint.unwrap_or_else(|| {
        if truncated_from_read {
            max_bytes.saturating_add(1)
        } else {
            bytes_returned
        }
    });
    let truncated = size_hint
        .map(|size| size > max_bytes)
        .unwrap_or(truncated_from_read);
    let text = String::from_utf8_lossy(&bytes).to_string();

    SourceTextRead {
        path: path.to_string(),
        bytes_total,
        bytes_returned,
        truncated,
        text,
    }
}

#[cfg(any(
    feature = "remote-ftp",
    feature = "remote-sftp",
    feature = "remote-samba"
))]
fn build_named_listing(path: &str, mut entries: Vec<NamedListEntry>) -> SourceDirListing {
    entries.sort_by_key(|entry| entry.name.to_ascii_lowercase());
    let mut listing = SourceDirListing {
        path: path.to_string(),
        parent: remote_parent(path),
        directories: Vec::new(),
        files: Vec::new(),
    };
    for entry in entries.into_iter().take(400) {
        if entry.is_dir {
            listing.directories.push(json!({
                "name": entry.name,
                "path": entry.path
            }));
            continue;
        }
        listing.files.push(json!({
            "name": entry.name,
            "path": entry.path,
            "size_bytes": entry.size_bytes.unwrap_or(0)
        }));
    }
    listing
}

fn resolve_named_remote_path(source: &NamedSource, request_path: &str) -> Result<String> {
    let root = named_source_root(source);
    let raw = request_path.trim();
    let request = if raw.is_empty() { "." } else { raw };
    let normalized_request = normalize_remote_path(request);

    if root == "." {
        return Ok(normalized_request);
    }
    if root == "/" {
        let rel = normalized_request
            .trim_start_matches('/')
            .trim_start_matches('.');
        return if rel.is_empty() {
            Ok("/".to_string())
        } else {
            Ok(normalize_remote_path(&format!("/{rel}")))
        };
    }

    let rel = if normalized_request == "." {
        String::new()
    } else {
        normalized_request
            .trim_start_matches('/')
            .trim_start_matches('.')
            .to_string()
    };
    let candidate = if rel.is_empty() {
        root.clone()
    } else {
        join_remote_paths(&root, &rel)
    };

    if !is_within_remote_root(&candidate, &root) {
        return Err(anyhow!(
            "path escapes configured source root `{}`: `{}`",
            root,
            request_path
        ));
    }
    Ok(candidate)
}

fn named_source_root(source: &NamedSource) -> String {
    let raw = source.location.trim();
    if raw.is_empty() {
        ".".to_string()
    } else {
        normalize_remote_path(raw)
    }
}

fn normalize_remote_path(raw: &str) -> String {
    let input = raw.trim().replace('\\', "/");
    let absolute = input.starts_with('/');
    let mut parts = Vec::new();
    for part in input.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                let _ = parts.pop();
            }
            segment => parts.push(segment.to_string()),
        }
    }

    if absolute {
        if parts.is_empty() {
            "/".to_string()
        } else {
            format!("/{}", parts.join("/"))
        }
    } else if parts.is_empty() {
        ".".to_string()
    } else {
        parts.join("/")
    }
}

fn join_remote_paths(base: &str, child: &str) -> String {
    let child = child.trim().trim_start_matches('/');
    if child.is_empty() || child == "." {
        return normalize_remote_path(base);
    }
    if base == "." {
        return normalize_remote_path(child);
    }
    if base == "/" {
        return normalize_remote_path(&format!("/{child}"));
    }
    normalize_remote_path(&format!("{}/{}", base.trim_end_matches('/'), child))
}

fn is_within_remote_root(path: &str, root: &str) -> bool {
    if root == "." || root == "/" {
        return true;
    }
    path == root || path.starts_with(&format!("{root}/"))
}

#[cfg(any(
    feature = "remote-ftp",
    feature = "remote-sftp",
    feature = "remote-samba"
))]
fn remote_parent(path: &str) -> Option<String> {
    let normalized = normalize_remote_path(path);
    if normalized == "." || normalized == "/" {
        return None;
    }
    if let Some((prefix, _)) = normalized.rsplit_once('/') {
        if prefix.is_empty() {
            return Some("/".to_string());
        }
        return Some(prefix.to_string());
    }
    Some(".".to_string())
}

#[cfg(feature = "remote-sftp")]
fn sftp_perm_is_dir(perm: u32) -> bool {
    (perm & 0o170000) == 0o040000
}

#[cfg(feature = "remote-samba")]
#[derive(Clone, Default)]
struct SharedWriteBuffer(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

#[cfg(feature = "remote-samba")]
impl SharedWriteBuffer {
    fn snapshot(&self) -> Vec<u8> {
        self.0.lock().map(|guard| guard.clone()).unwrap_or_default()
    }
}

#[cfg(feature = "remote-samba")]
impl std::io::Write for SharedWriteBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut guard = self
            .0
            .lock()
            .map_err(|_| std::io::Error::other("shared buffer lock poisoned"))?;
        guard.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct HtmlLinkEntry {
    text: String,
    href: String,
    url: String,
}

async fn fetch_web_page_html(
    url: &str,
    max_fetch_bytes: usize,
) -> Result<(reqwest::Url, String, bool)> {
    let parsed = reqwest::Url::parse(url).with_context(|| format!("invalid URL: {url}"))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(anyhow!("url must use http or https scheme"));
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(35))
        .user_agent("graboid-tools/0.1")
        .build()
        .context("failed creating web search client")?;
    let response = client
        .get(parsed)
        .header("accept", "text/html,application/xhtml+xml")
        .send()
        .await
        .context("web_search_links request failed")?;
    if !response.status().is_success() {
        return Err(anyhow!("request failed with status {}", response.status()));
    }

    let resolved_url = response.url().clone();
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if !content_type.contains("text/html") && !content_type.contains("application/xhtml+xml") {
        return Err(anyhow!(
            "URL did not return HTML content (content-type={content_type})"
        ));
    }

    let body = response
        .bytes()
        .await
        .context("failed reading HTML response body")?;
    let truncated = body.len() > max_fetch_bytes;
    let body_bytes = if truncated {
        &body[..max_fetch_bytes]
    } else {
        body.as_ref()
    };
    let html = String::from_utf8_lossy(body_bytes).to_string();
    Ok((resolved_url, html, truncated))
}

fn extract_html_title(html: &str) -> String {
    let Ok(title_re) = Regex::new(r#"(?is)<title[^>]*>(.*?)</title>"#) else {
        return String::new();
    };
    let Ok(tag_re) = Regex::new(r"(?is)<[^>]+>") else {
        return String::new();
    };
    let Some(captures) = title_re.captures(html) else {
        return String::new();
    };
    let Some(raw_title) = captures.get(1) else {
        return String::new();
    };
    tag_re
        .replace_all(raw_title.as_str(), "")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn extract_html_links(base_url: &reqwest::Url, html: &str) -> Vec<HtmlLinkEntry> {
    let Ok(anchor_re) = Regex::new(r#"(?is)<a\b[^>]*href\s*=\s*["']([^"']+)["'][^>]*>(.*?)</a>"#)
    else {
        return Vec::new();
    };
    let Ok(tag_re) = Regex::new(r"(?is)<[^>]+>") else {
        return Vec::new();
    };

    let mut links = Vec::new();
    let mut seen = HashSet::new();

    for capture in anchor_re.captures_iter(html) {
        let Some(href_match) = capture.get(1) else {
            continue;
        };
        let href = href_match.as_str().trim();
        if href.is_empty()
            || href.starts_with('#')
            || href.starts_with("javascript:")
            || href.starts_with("mailto:")
        {
            continue;
        }

        let resolved = if href.starts_with("magnet:") {
            href.to_string()
        } else if href.starts_with("http://") || href.starts_with("https://") {
            match reqwest::Url::parse(href) {
                Ok(value) => value.to_string(),
                Err(_) => continue,
            }
        } else {
            match base_url.join(href) {
                Ok(value) => value.to_string(),
                Err(_) => continue,
            }
        };

        if !resolved.starts_with("http://")
            && !resolved.starts_with("https://")
            && !resolved.starts_with("magnet:")
        {
            continue;
        }

        if !seen.insert(resolved.clone()) {
            continue;
        }

        let text = capture
            .get(2)
            .map(|group| group.as_str())
            .unwrap_or_default();
        let text = tag_re
            .replace_all(text, "")
            .replace('\n', " ")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");

        links.push(HtmlLinkEntry {
            text,
            href: href.to_string(),
            url: resolved,
        });
    }

    links
}

fn tokenize_query_terms(query: &str) -> Vec<String> {
    let mut terms = Vec::new();
    let mut seen = HashSet::new();
    for term in query
        .to_ascii_lowercase()
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .map(str::trim)
        .filter(|term| !term.is_empty())
    {
        if seen.insert(term.to_string()) {
            terms.push(term.to_string());
        }
    }
    if terms.is_empty() {
        let fallback = query.trim().to_ascii_lowercase();
        if !fallback.is_empty() {
            return vec![fallback];
        }
    }
    terms
}

fn link_matches_query(entry: &HtmlLinkEntry, query_terms: &[String], match_mode: &str) -> bool {
    if query_terms.is_empty() {
        return true;
    }
    let haystack = format!(
        "{} {} {}",
        entry.text.to_ascii_lowercase(),
        entry.href.to_ascii_lowercase(),
        entry.url.to_ascii_lowercase()
    );
    if match_mode == "any" {
        query_terms.iter().any(|term| haystack.contains(term))
    } else {
        query_terms.iter().all(|term| haystack.contains(term))
    }
}

fn format_torznab_text(
    query: &str,
    fresh: bool,
    results: &[torrent::TorznabSearchResult],
) -> String {
    if results.is_empty() {
        return format!("Torznab search returned 0 results for query `{query}` (fresh={fresh}).");
    }

    let mut lines = Vec::new();
    lines.push(format!(
        "Torznab search returned {} result(s) for query `{query}` (fresh={fresh}):",
        results.len()
    ));
    for (idx, item) in results.iter().take(12).enumerate() {
        let seeders = item
            .seeders
            .map(|value| value.to_string())
            .unwrap_or_else(|| "-".to_string());
        let indexer = item.indexer.as_deref().unwrap_or("-");
        lines.push(format!(
            "{}. {} | seeders={} | indexer={} | {}",
            idx + 1,
            item.title,
            seeders,
            indexer,
            item.download_url
        ));
    }
    if results.len() > 12 {
        lines.push(format!("... {} more result(s) omitted", results.len() - 12));
    }
    lines.join("\n")
}

fn jsonrpc_ok_response(id: Value, result: Value) -> Value {
    json!({
        "jsonrpc": JSONRPC_VERSION,
        "id": id,
        "result": result
    })
}

fn jsonrpc_error_response(id: Value, code: i64, message: &str, data: String) -> Value {
    json!({
        "jsonrpc": JSONRPC_VERSION,
        "id": id,
        "error": {
            "code": code,
            "message": message,
            "data": data
        }
    })
}

fn tool_ok_result(text: &str, structured: Value) -> Value {
    json!({
        "content": [
            {
                "type": "text",
                "text": text
            }
        ],
        "structuredContent": structured,
        "isError": false
    })
}

fn tool_error_result(message: &str) -> Value {
    json!({
        "content": [
            {
                "type": "text",
                "text": message
            }
        ],
        "isError": true
    })
}

async fn read_jsonrpc_message(reader: &mut BufReader<io::Stdin>) -> Result<Option<Value>> {
    let mut content_length: Option<usize> = None;

    loop {
        let mut line = String::new();
        let read = reader
            .read_line(&mut line)
            .await
            .context("failed reading MCP message header")?;
        if read == 0 {
            return Ok(None);
        }

        if line == "\r\n" || line == "\n" {
            break;
        }

        let header = line.trim();
        if let Some((name, value)) = header.split_once(':')
            && name.trim().eq_ignore_ascii_case("content-length")
        {
            content_length = value.trim().parse::<usize>().ok();
        }
    }

    let Some(length) = content_length else {
        return Err(anyhow!("MCP message missing Content-Length header"));
    };

    let mut body = vec![0_u8; length];
    reader
        .read_exact(&mut body)
        .await
        .context("failed reading MCP message body")?;

    let payload =
        serde_json::from_slice::<Value>(&body).context("failed decoding MCP JSON-RPC body")?;
    Ok(Some(payload))
}

async fn write_jsonrpc_message(writer: &mut BufWriter<io::Stdout>, payload: &Value) -> Result<()> {
    let body = serde_json::to_vec(payload).context("failed encoding MCP JSON-RPC payload")?;
    writer
        .write_all(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes())
        .await
        .context("failed writing MCP message header")?;
    writer
        .write_all(&body)
        .await
        .context("failed writing MCP message body")?;
    writer.flush().await.context("failed flushing MCP output")?;
    Ok(())
}
