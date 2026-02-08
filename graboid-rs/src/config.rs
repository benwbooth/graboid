use std::collections::{BTreeMap, HashMap, HashSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::{Map as JsonMap, Value as JsonValue};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Debug, Clone, Deserialize, Default)]
struct FileConfig {
    bind_addr: Option<String>,
    database_path: Option<String>,
    download_dir: Option<String>,
    download_retry_attempts: Option<usize>,
    download_max_parallel: Option<usize>,
    download_retry_backoff_sec: Option<f64>,
    download_allow_insecure: Option<bool>,
    jobs_max_concurrent: Option<usize>,
    claude_model: Option<String>,
    claude_cmd: Option<String>,
    api_key: Option<String>,
    chrome_debug_port: Option<u16>,
    #[serde(alias = "headless")]
    chrome_headless: Option<bool>,
    browser_mode: Option<String>,
    browser_use_mcp_command: Option<String>,
    browser_use_mcp_args: Option<String>,
    claude_timeout_seconds: Option<u64>,
    download_timeout_seconds: Option<u64>,
    ollama_host: Option<String>,
    torrent_client: Option<String>,
    qbittorrent_host: Option<String>,
    qbittorrent_port: Option<u16>,
    qbittorrent_username: Option<String>,
    qbittorrent_password: Option<String>,
    transmission_host: Option<String>,
    transmission_port: Option<u16>,
    transmission_username: Option<String>,
    transmission_password: Option<String>,
    deluge_host: Option<String>,
    deluge_port: Option<u16>,
    deluge_username: Option<String>,
    deluge_password: Option<String>,
    rtorrent_url: Option<String>,
    aria2_host: Option<String>,
    aria2_port: Option<u16>,
    aria2_secret: Option<String>,
    source_mode: Option<String>,
    source_endpoints: Option<Vec<String>>,
    source_sftp_host: Option<String>,
    source_sftp_port: Option<u16>,
    source_sftp_username: Option<String>,
    source_sftp_password: Option<String>,
    source_ftp_host: Option<String>,
    source_ftp_port: Option<u16>,
    source_ftp_username: Option<String>,
    source_ftp_password: Option<String>,
    source_samba_host: Option<String>,
    source_samba_share: Option<String>,
    source_samba_username: Option<String>,
    source_samba_password: Option<String>,
    local_read_whitelist: Option<Vec<String>>,
    local_write_whitelist: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct ApiConfig {
    api_key: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct RootConfig {
    #[serde(default, flatten)]
    top: FileConfig,
    rust: Option<FileConfig>,
    graboid_rs: Option<FileConfig>,
    api: Option<ApiConfig>,
}

#[derive(Debug, Clone, Copy)]
enum ConfigFieldValue {
    String(&'static str),
    Integer(i64),
    Float(f64),
    Bool(bool),
    StringList(&'static [&'static str]),
}

#[derive(Debug, Clone, Copy)]
enum FormFieldMode {
    Text,
    Checkbox,
    Lines,
    Constant,
    Skip,
}

#[derive(Debug, Clone, Copy)]
struct ConfigFieldSpec {
    key: &'static str,
    value: ConfigFieldValue,
    form_mode: FormFieldMode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamedSource {
    pub name: String,
    pub kind: String,
    pub host: String,
    pub port: Option<u16>,
    pub location: String,
    pub username: String,
    pub password: String,
}

const EMPTY_STRING_LIST: &[&str] = &[];

const CONFIG_FIELD_SPECS: &[ConfigFieldSpec] = &[
    ConfigFieldSpec {
        key: "bind_addr",
        value: ConfigFieldValue::String("0.0.0.0:8000"),
        form_mode: FormFieldMode::Skip,
    },
    ConfigFieldSpec {
        key: "database_path",
        value: ConfigFieldValue::String("./graboid-rs-data/jobs.db"),
        form_mode: FormFieldMode::Skip,
    },
    ConfigFieldSpec {
        key: "download_dir",
        value: ConfigFieldValue::String("./downloads"),
        form_mode: FormFieldMode::Text,
    },
    ConfigFieldSpec {
        key: "download_retry_attempts",
        value: ConfigFieldValue::Integer(2),
        form_mode: FormFieldMode::Text,
    },
    ConfigFieldSpec {
        key: "download_max_parallel",
        value: ConfigFieldValue::Integer(4),
        form_mode: FormFieldMode::Text,
    },
    ConfigFieldSpec {
        key: "download_retry_backoff_sec",
        value: ConfigFieldValue::Float(2.0),
        form_mode: FormFieldMode::Text,
    },
    ConfigFieldSpec {
        key: "download_allow_insecure",
        value: ConfigFieldValue::Bool(true),
        form_mode: FormFieldMode::Checkbox,
    },
    ConfigFieldSpec {
        key: "jobs_max_concurrent",
        value: ConfigFieldValue::Integer(2),
        form_mode: FormFieldMode::Skip,
    },
    ConfigFieldSpec {
        key: "claude_model",
        value: ConfigFieldValue::String("sonnet"),
        form_mode: FormFieldMode::Skip,
    },
    ConfigFieldSpec {
        key: "claude_cmd",
        value: ConfigFieldValue::String("claude"),
        form_mode: FormFieldMode::Skip,
    },
    ConfigFieldSpec {
        key: "api_key",
        value: ConfigFieldValue::String(""),
        form_mode: FormFieldMode::Skip,
    },
    ConfigFieldSpec {
        key: "chrome_debug_port",
        value: ConfigFieldValue::Integer(9222),
        form_mode: FormFieldMode::Skip,
    },
    ConfigFieldSpec {
        key: "headless",
        value: ConfigFieldValue::Bool(true),
        form_mode: FormFieldMode::Checkbox,
    },
    ConfigFieldSpec {
        key: "browser_mode",
        value: ConfigFieldValue::String("chrome"),
        form_mode: FormFieldMode::Constant,
    },
    ConfigFieldSpec {
        key: "browser_use_mcp_command",
        value: ConfigFieldValue::String("uvx"),
        form_mode: FormFieldMode::Skip,
    },
    ConfigFieldSpec {
        key: "browser_use_mcp_args",
        value: ConfigFieldValue::String("browser-use[mcp]"),
        form_mode: FormFieldMode::Skip,
    },
    ConfigFieldSpec {
        key: "claude_timeout_seconds",
        value: ConfigFieldValue::Integer(900),
        form_mode: FormFieldMode::Skip,
    },
    ConfigFieldSpec {
        key: "download_timeout_seconds",
        value: ConfigFieldValue::Integer(180),
        form_mode: FormFieldMode::Skip,
    },
    ConfigFieldSpec {
        key: "ollama_host",
        value: ConfigFieldValue::String("http://localhost:11434"),
        form_mode: FormFieldMode::Skip,
    },
    ConfigFieldSpec {
        key: "llm_provider",
        value: ConfigFieldValue::String("claude_code"),
        form_mode: FormFieldMode::Text,
    },
    ConfigFieldSpec {
        key: "llm_model",
        value: ConfigFieldValue::String("sonnet"),
        form_mode: FormFieldMode::Text,
    },
    ConfigFieldSpec {
        key: "torrent_client",
        value: ConfigFieldValue::String("embedded"),
        form_mode: FormFieldMode::Text,
    },
    ConfigFieldSpec {
        key: "qbittorrent_host",
        value: ConfigFieldValue::String("localhost"),
        form_mode: FormFieldMode::Text,
    },
    ConfigFieldSpec {
        key: "qbittorrent_port",
        value: ConfigFieldValue::Integer(8080),
        form_mode: FormFieldMode::Text,
    },
    ConfigFieldSpec {
        key: "qbittorrent_username",
        value: ConfigFieldValue::String("admin"),
        form_mode: FormFieldMode::Text,
    },
    ConfigFieldSpec {
        key: "qbittorrent_password",
        value: ConfigFieldValue::String("adminadmin"),
        form_mode: FormFieldMode::Text,
    },
    ConfigFieldSpec {
        key: "transmission_host",
        value: ConfigFieldValue::String("localhost"),
        form_mode: FormFieldMode::Text,
    },
    ConfigFieldSpec {
        key: "transmission_port",
        value: ConfigFieldValue::Integer(9091),
        form_mode: FormFieldMode::Text,
    },
    ConfigFieldSpec {
        key: "transmission_username",
        value: ConfigFieldValue::String(""),
        form_mode: FormFieldMode::Text,
    },
    ConfigFieldSpec {
        key: "transmission_password",
        value: ConfigFieldValue::String(""),
        form_mode: FormFieldMode::Text,
    },
    ConfigFieldSpec {
        key: "deluge_host",
        value: ConfigFieldValue::String("localhost"),
        form_mode: FormFieldMode::Text,
    },
    ConfigFieldSpec {
        key: "deluge_port",
        value: ConfigFieldValue::Integer(58846),
        form_mode: FormFieldMode::Text,
    },
    ConfigFieldSpec {
        key: "deluge_username",
        value: ConfigFieldValue::String("localclient"),
        form_mode: FormFieldMode::Text,
    },
    ConfigFieldSpec {
        key: "deluge_password",
        value: ConfigFieldValue::String("deluge"),
        form_mode: FormFieldMode::Text,
    },
    ConfigFieldSpec {
        key: "rtorrent_url",
        value: ConfigFieldValue::String(""),
        form_mode: FormFieldMode::Text,
    },
    ConfigFieldSpec {
        key: "aria2_host",
        value: ConfigFieldValue::String("localhost"),
        form_mode: FormFieldMode::Text,
    },
    ConfigFieldSpec {
        key: "aria2_port",
        value: ConfigFieldValue::Integer(6800),
        form_mode: FormFieldMode::Text,
    },
    ConfigFieldSpec {
        key: "aria2_secret",
        value: ConfigFieldValue::String(""),
        form_mode: FormFieldMode::Text,
    },
    ConfigFieldSpec {
        key: "source_mode",
        value: ConfigFieldValue::String("web"),
        form_mode: FormFieldMode::Text,
    },
    ConfigFieldSpec {
        key: "source_endpoints",
        value: ConfigFieldValue::StringList(EMPTY_STRING_LIST),
        form_mode: FormFieldMode::Lines,
    },
    ConfigFieldSpec {
        key: "source_sftp_host",
        value: ConfigFieldValue::String(""),
        form_mode: FormFieldMode::Text,
    },
    ConfigFieldSpec {
        key: "source_sftp_port",
        value: ConfigFieldValue::Integer(22),
        form_mode: FormFieldMode::Text,
    },
    ConfigFieldSpec {
        key: "source_sftp_username",
        value: ConfigFieldValue::String(""),
        form_mode: FormFieldMode::Text,
    },
    ConfigFieldSpec {
        key: "source_sftp_password",
        value: ConfigFieldValue::String(""),
        form_mode: FormFieldMode::Text,
    },
    ConfigFieldSpec {
        key: "source_ftp_host",
        value: ConfigFieldValue::String(""),
        form_mode: FormFieldMode::Text,
    },
    ConfigFieldSpec {
        key: "source_ftp_port",
        value: ConfigFieldValue::Integer(21),
        form_mode: FormFieldMode::Text,
    },
    ConfigFieldSpec {
        key: "source_ftp_username",
        value: ConfigFieldValue::String(""),
        form_mode: FormFieldMode::Text,
    },
    ConfigFieldSpec {
        key: "source_ftp_password",
        value: ConfigFieldValue::String(""),
        form_mode: FormFieldMode::Text,
    },
    ConfigFieldSpec {
        key: "source_samba_host",
        value: ConfigFieldValue::String(""),
        form_mode: FormFieldMode::Text,
    },
    ConfigFieldSpec {
        key: "source_samba_share",
        value: ConfigFieldValue::String(""),
        form_mode: FormFieldMode::Text,
    },
    ConfigFieldSpec {
        key: "source_samba_username",
        value: ConfigFieldValue::String(""),
        form_mode: FormFieldMode::Text,
    },
    ConfigFieldSpec {
        key: "source_samba_password",
        value: ConfigFieldValue::String(""),
        form_mode: FormFieldMode::Text,
    },
    ConfigFieldSpec {
        key: "path_mappings",
        value: ConfigFieldValue::StringList(EMPTY_STRING_LIST),
        form_mode: FormFieldMode::Lines,
    },
    ConfigFieldSpec {
        key: "local_read_whitelist",
        value: ConfigFieldValue::StringList(EMPTY_STRING_LIST),
        form_mode: FormFieldMode::Lines,
    },
    ConfigFieldSpec {
        key: "local_write_whitelist",
        value: ConfigFieldValue::StringList(EMPTY_STRING_LIST),
        form_mode: FormFieldMode::Lines,
    },
    ConfigFieldSpec {
        key: "log_level",
        value: ConfigFieldValue::String("INFO"),
        form_mode: FormFieldMode::Text,
    },
];

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub bind_addr: String,
    pub database_path: String,
    pub download_dir: String,
    pub download_retry_attempts: usize,
    pub download_max_parallel: usize,
    pub download_retry_backoff_sec: f64,
    pub download_allow_insecure: bool,
    pub jobs_max_concurrent: usize,
    pub claude_model: String,
    pub claude_cmd: String,
    pub api_key: String,
    pub chrome_debug_port: u16,
    pub chrome_headless: bool,
    pub browser_mode: String,
    pub browser_use_mcp_command: String,
    pub browser_use_mcp_args: String,
    pub claude_timeout_seconds: u64,
    pub download_timeout_seconds: u64,
    pub username: String,
    pub password: String,
    pub session_secret: String,
    pub session_max_age_seconds: i64,
    pub ollama_host: String,
    pub torrent_client: String,
    pub qbittorrent_host: String,
    pub qbittorrent_port: u16,
    pub qbittorrent_username: String,
    pub qbittorrent_password: String,
    pub transmission_host: String,
    pub transmission_port: u16,
    pub transmission_username: String,
    pub transmission_password: String,
    pub deluge_host: String,
    pub deluge_port: u16,
    pub deluge_username: String,
    pub deluge_password: String,
    pub rtorrent_url: String,
    pub aria2_host: String,
    pub aria2_port: u16,
    pub aria2_secret: String,
    pub source_mode: String,
    pub source_endpoints: Vec<String>,
    pub source_sftp_host: String,
    pub source_sftp_port: u16,
    pub source_sftp_username: String,
    pub source_sftp_password: String,
    pub source_ftp_host: String,
    pub source_ftp_port: u16,
    pub source_ftp_username: String,
    pub source_ftp_password: String,
    pub source_samba_host: String,
    pub source_samba_share: String,
    pub source_samba_username: String,
    pub source_samba_password: String,
    pub local_read_whitelist: Vec<String>,
    pub local_write_whitelist: Vec<String>,
    pub config_path: PathBuf,
}

impl Default for AppConfig {
    fn default() -> Self {
        let username = env::var("GRABOID_USERNAME").unwrap_or_else(|_| "admin".to_string());
        let password = env::var("GRABOID_PASSWORD").unwrap_or_else(|_| "adminadmin".to_string());

        Self {
            bind_addr: "0.0.0.0:8000".to_string(),
            database_path: "./graboid-rs-data/jobs.db".to_string(),
            download_dir: "./downloads".to_string(),
            download_retry_attempts: 2,
            download_max_parallel: 4,
            download_retry_backoff_sec: 2.0,
            download_allow_insecure: true,
            jobs_max_concurrent: 2,
            claude_model: "sonnet".to_string(),
            claude_cmd: "claude".to_string(),
            api_key: String::new(),
            chrome_debug_port: 9222,
            chrome_headless: true,
            browser_mode: "chrome".to_string(),
            browser_use_mcp_command: "uvx".to_string(),
            browser_use_mcp_args: "browser-use[mcp]".to_string(),
            claude_timeout_seconds: 900,
            download_timeout_seconds: 180,
            username: username.clone(),
            password: password.clone(),
            session_secret: build_default_session_secret(&username, &password),
            session_max_age_seconds: 60 * 60 * 24 * 7,
            ollama_host: "http://localhost:11434".to_string(),
            torrent_client: "embedded".to_string(),
            qbittorrent_host: "localhost".to_string(),
            qbittorrent_port: 8080,
            qbittorrent_username: "admin".to_string(),
            qbittorrent_password: "adminadmin".to_string(),
            transmission_host: "localhost".to_string(),
            transmission_port: 9091,
            transmission_username: String::new(),
            transmission_password: String::new(),
            deluge_host: "localhost".to_string(),
            deluge_port: 58846,
            deluge_username: "localclient".to_string(),
            deluge_password: "deluge".to_string(),
            rtorrent_url: String::new(),
            aria2_host: "localhost".to_string(),
            aria2_port: 6800,
            aria2_secret: String::new(),
            source_mode: "web".to_string(),
            source_endpoints: Vec::new(),
            source_sftp_host: String::new(),
            source_sftp_port: 22,
            source_sftp_username: String::new(),
            source_sftp_password: String::new(),
            source_ftp_host: String::new(),
            source_ftp_port: 21,
            source_ftp_username: String::new(),
            source_ftp_password: String::new(),
            source_samba_host: String::new(),
            source_samba_share: String::new(),
            source_samba_username: String::new(),
            source_samba_password: String::new(),
            local_read_whitelist: Vec::new(),
            local_write_whitelist: Vec::new(),
            config_path: PathBuf::from("config.toml"),
        }
    }
}

macro_rules! apply_opt_fields {
    ($target:expr, $source:expr, [$($field:ident),+ $(,)?]) => {
        $(
            set_opt(&mut $target.$field, $source.$field);
        )+
    };
}

impl AppConfig {
    pub fn load() -> Self {
        let mut cfg = Self::default();

        let config_path = find_config_file().unwrap_or_else(|| config_search_paths()[0].clone());
        cfg.config_path = config_path.clone();

        let root = load_root_config(&config_path).unwrap_or_default();
        let RootConfig {
            top,
            rust,
            graboid_rs,
            api,
        } = root;

        cfg.apply_file(top);
        if let Some(section) = graboid_rs.or(rust) {
            cfg.apply_file(section);
        }

        if cfg.api_key.is_empty() {
            if let Some(api_key) = api.and_then(|entry| entry.api_key) {
                cfg.api_key = api_key;
            }
        }

        cfg.apply_env();

        if cfg.api_key.is_empty() {
            cfg.api_key = generate_api_key();
            let _ = persist_api_key(&cfg.config_path, &cfg.api_key);
        }

        cfg
    }

    fn apply_file(&mut self, file_cfg: FileConfig) {
        set_opt_usize_min(
            &mut self.download_retry_attempts,
            file_cfg.download_retry_attempts,
            1,
        );
        set_opt_usize_min(
            &mut self.download_max_parallel,
            file_cfg.download_max_parallel,
            1,
        );
        set_opt_f64_min(
            &mut self.download_retry_backoff_sec,
            file_cfg.download_retry_backoff_sec,
            0.0,
        );
        set_opt_usize_min(
            &mut self.jobs_max_concurrent,
            file_cfg.jobs_max_concurrent,
            1,
        );
        set_opt_u64_min(
            &mut self.claude_timeout_seconds,
            file_cfg.claude_timeout_seconds,
            30,
        );
        set_opt_u64_min(
            &mut self.download_timeout_seconds,
            file_cfg.download_timeout_seconds,
            10,
        );
        apply_opt_fields!(
            self,
            file_cfg,
            [
                bind_addr,
                database_path,
                download_dir,
                download_allow_insecure,
                claude_model,
                claude_cmd,
                api_key,
                chrome_debug_port,
                chrome_headless,
                browser_mode,
                browser_use_mcp_command,
                browser_use_mcp_args,
                ollama_host,
                torrent_client,
                qbittorrent_host,
                qbittorrent_port,
                qbittorrent_username,
                qbittorrent_password,
                transmission_host,
                transmission_port,
                transmission_username,
                transmission_password,
                deluge_host,
                deluge_port,
                deluge_username,
                deluge_password,
                rtorrent_url,
                aria2_host,
                aria2_port,
                aria2_secret,
                source_mode,
                source_endpoints,
                source_sftp_host,
                source_sftp_port,
                source_sftp_username,
                source_sftp_password,
                source_ftp_host,
                source_ftp_port,
                source_ftp_username,
                source_ftp_password,
                source_samba_host,
                source_samba_share,
                source_samba_username,
                source_samba_password,
                local_read_whitelist,
                local_write_whitelist
            ]
        );
    }

    fn apply_env(&mut self) {
        let env_cfg = FileConfig::from_env();
        self.apply_file(env_cfg);

        if let Some(v) = env_string("GRABOID_USERNAME") {
            self.username = v;
        }
        if let Some(v) = env_string("GRABOID_PASSWORD") {
            self.password = v;
        }
        if let Some(v) = env_string("GRABOID_SESSION_SECRET") {
            self.session_secret = v;
        } else {
            self.session_secret = build_default_session_secret(&self.username, &self.password);
        }
    }

    pub fn database_path(&self) -> PathBuf {
        PathBuf::from(&self.database_path)
    }

    pub fn download_dir(&self) -> PathBuf {
        PathBuf::from(&self.download_dir)
    }

    pub fn named_sources(&self) -> Vec<NamedSource> {
        let mut parsed = parse_named_sources(&self.source_endpoints);
        if parsed.is_empty() {
            parsed = legacy_named_sources(self);
        }
        ensure_unique_named_source_names(parsed)
    }
}

pub fn parse_named_source_line(raw: &str) -> Option<NamedSource> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    let parts = if trimmed.contains('\t') {
        trimmed.split('\t').collect::<Vec<_>>()
    } else if trimmed.contains('|') {
        trimmed.split('|').collect::<Vec<_>>()
    } else {
        return None;
    };
    if parts.len() < 3 {
        return None;
    }

    let mut fields = parts
        .into_iter()
        .map(str::trim)
        .map(str::to_string)
        .collect::<Vec<_>>();
    fields.resize(7, String::new());

    let kind = normalize_named_source_kind(&fields[1])?;
    let host = fields[2].trim().to_string();
    if host.is_empty() {
        return None;
    }

    let port = fields[3]
        .trim()
        .parse::<u16>()
        .ok()
        .or_else(|| default_named_source_port(&kind));
    let name = if fields[0].trim().is_empty() {
        format!("{kind}-{host}")
    } else {
        fields[0].trim().to_string()
    };

    Some(NamedSource {
        name,
        kind,
        host,
        port,
        location: fields[4].trim().to_string(),
        username: fields[5].trim().to_string(),
        password: fields[6].to_string(),
    })
}

pub fn parse_named_sources(lines: &[String]) -> Vec<NamedSource> {
    lines
        .iter()
        .filter_map(|line| parse_named_source_line(line))
        .collect::<Vec<_>>()
}

pub fn encode_named_source_line(source: &NamedSource) -> String {
    let port = source
        .port
        .map(|value| value.to_string())
        .unwrap_or_default();
    [
        sanitize_named_source_cell(&source.name),
        sanitize_named_source_cell(&source.kind),
        sanitize_named_source_cell(&source.host),
        sanitize_named_source_cell(&port),
        sanitize_named_source_cell(&source.location),
        sanitize_named_source_cell(&source.username),
        sanitize_named_source_cell(&source.password),
    ]
    .join("\t")
}

fn sanitize_named_source_cell(value: &str) -> String {
    value.replace(['\t', '\r', '\n'], " ").trim().to_string()
}

fn normalize_named_source_kind(value: &str) -> Option<String> {
    let normalized = value.trim().to_ascii_lowercase();
    let kind = match normalized.as_str() {
        "sftp" => "sftp",
        "ftp" => "ftp",
        "samba" | "smb" => "samba",
        _ => return None,
    };
    Some(kind.to_string())
}

fn default_named_source_port(kind: &str) -> Option<u16> {
    match kind {
        "sftp" => Some(22),
        "ftp" => Some(21),
        "samba" => Some(445),
        _ => None,
    }
}

fn legacy_named_sources(cfg: &AppConfig) -> Vec<NamedSource> {
    let mut sources = Vec::new();

    if !cfg.source_sftp_host.trim().is_empty() {
        sources.push(NamedSource {
            name: "default-sftp".to_string(),
            kind: "sftp".to_string(),
            host: cfg.source_sftp_host.trim().to_string(),
            port: Some(cfg.source_sftp_port),
            location: String::new(),
            username: cfg.source_sftp_username.clone(),
            password: cfg.source_sftp_password.clone(),
        });
    }

    if !cfg.source_ftp_host.trim().is_empty() {
        sources.push(NamedSource {
            name: "default-ftp".to_string(),
            kind: "ftp".to_string(),
            host: cfg.source_ftp_host.trim().to_string(),
            port: Some(cfg.source_ftp_port),
            location: String::new(),
            username: cfg.source_ftp_username.clone(),
            password: cfg.source_ftp_password.clone(),
        });
    }

    if !cfg.source_samba_host.trim().is_empty() {
        sources.push(NamedSource {
            name: "default-samba".to_string(),
            kind: "samba".to_string(),
            host: cfg.source_samba_host.trim().to_string(),
            port: Some(445),
            location: cfg.source_samba_share.clone(),
            username: cfg.source_samba_username.clone(),
            password: cfg.source_samba_password.clone(),
        });
    }

    sources
}

fn ensure_unique_named_source_names(mut sources: Vec<NamedSource>) -> Vec<NamedSource> {
    let mut seen = HashSet::new();
    for source in &mut sources {
        let base = source.name.trim();
        let candidate = if base.is_empty() {
            format!("{}-{}", source.kind, source.host)
        } else {
            base.to_string()
        };

        if seen.insert(candidate.to_ascii_lowercase()) {
            source.name = candidate;
            continue;
        }

        let mut suffix = 2usize;
        loop {
            let suffixed = format!("{candidate}-{suffix}");
            if seen.insert(suffixed.to_ascii_lowercase()) {
                source.name = suffixed;
                break;
            }
            suffix += 1;
        }
    }

    sources
}

impl FileConfig {
    fn from_env() -> Self {
        let mut values = JsonMap::new();
        for spec in CONFIG_FIELD_SPECS {
            let Some(raw) = read_env_for_key(spec.key) else {
                continue;
            };
            let Some(parsed) = parse_raw_to_json(&raw, spec.value) else {
                continue;
            };
            values.insert(spec.key.to_string(), parsed);
        }

        serde_json::from_value::<FileConfig>(JsonValue::Object(values)).unwrap_or_default()
    }
}

pub fn config_search_paths() -> Vec<PathBuf> {
    let mut paths = vec![PathBuf::from("config.toml"), PathBuf::from("graboid.toml")];
    if let Some(home) = dirs_home() {
        paths.push(home.join(".config").join("graboid").join("config.toml"));
    }
    paths
}

pub fn find_config_file() -> Option<PathBuf> {
    config_search_paths().into_iter().find(|path| path.exists())
}

pub fn load_config_flat_json(path: &Path) -> JsonMap<String, JsonValue> {
    let table = load_toml_table(path).unwrap_or_default();
    table
        .into_iter()
        .map(|(k, v)| (k, toml_to_json(v)))
        .collect::<JsonMap<_, _>>()
}

pub fn build_flat_config_from_form(form: &HashMap<String, String>) -> BTreeMap<String, JsonValue> {
    let mut flat = BTreeMap::new();

    for spec in CONFIG_FIELD_SPECS {
        let value = match spec.form_mode {
            FormFieldMode::Skip => continue,
            FormFieldMode::Constant => default_json_value(spec.value),
            FormFieldMode::Checkbox => JsonValue::Bool(form.contains_key(spec.key)),
            FormFieldMode::Lines => JsonValue::Array(
                parse_list_lines(form.get(spec.key).map(String::as_str))
                    .into_iter()
                    .map(JsonValue::String)
                    .collect::<Vec<_>>(),
            ),
            FormFieldMode::Text => form
                .get(spec.key)
                .and_then(|raw| parse_raw_to_json(raw, spec.value))
                .unwrap_or_else(|| default_json_value(spec.value)),
        };

        flat.insert(spec.key.to_string(), value);
    }

    let claude_model = form
        .get("llm_model")
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .unwrap_or("sonnet")
        .to_string();
    flat.insert("claude_model".to_string(), JsonValue::String(claude_model));

    flat
}

pub fn persist_flat_config(path: &Path, flat: &BTreeMap<String, JsonValue>) -> Result<()> {
    let mut table = load_toml_table(path).unwrap_or_default();

    for (key, value) in flat {
        table.insert(key.clone(), json_to_toml(value));
    }

    let encoded = toml::to_string(&table).context("failed encoding toml")?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed creating config dir {parent:?}"))?;
    }
    fs::write(path, encoded).with_context(|| format!("failed writing config to {path:?}"))?;
    Ok(())
}

pub fn persist_api_key(path: &Path, api_key: &str) -> Result<()> {
    let mut table = load_toml_table(path).unwrap_or_default();

    let mut api = table
        .remove("api")
        .and_then(|v| v.as_table().cloned())
        .unwrap_or_default();
    api.insert(
        "api_key".to_string(),
        toml::Value::String(api_key.to_string()),
    );
    table.insert("api".to_string(), toml::Value::Table(api));

    let encoded = toml::to_string(&table).context("failed encoding toml")?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed creating config dir {parent:?}"))?;
    }
    fs::write(path, encoded).with_context(|| format!("failed writing config to {path:?}"))?;
    Ok(())
}

pub fn generate_api_key() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

fn load_toml_table(path: &Path) -> Result<toml::value::Table> {
    if !path.exists() {
        return Ok(Default::default());
    }
    let raw = fs::read_to_string(path).with_context(|| format!("failed reading {path:?}"))?;
    let value = toml::from_str::<toml::Value>(&raw).context("failed parsing toml")?;
    Ok(value.as_table().cloned().unwrap_or_default())
}

fn build_default_session_secret(username: &str, password: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("graboid:{username}:{password}:session"));
    let bytes = hasher.finalize();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn dirs_home() -> Option<PathBuf> {
    env::var("HOME").ok().map(PathBuf::from)
}

fn load_root_config(path: &Path) -> Result<RootConfig> {
    if !path.exists() {
        return Ok(RootConfig::default());
    }
    let raw = fs::read_to_string(path).with_context(|| format!("failed reading {path:?}"))?;
    toml::from_str::<RootConfig>(&raw).context("failed parsing config as root structure")
}

fn env_string(key: &str) -> Option<String> {
    env::var(key).ok()
}

fn read_env_for_key(key: &str) -> Option<String> {
    let suffix = env_suffix_for_key(key);
    let primary = format!("GRABOID_{suffix}");
    if let Ok(value) = env::var(&primary) {
        return Some(value);
    }

    let legacy = format!("GRABOID_RS_{suffix}");
    env::var(&legacy).ok()
}

fn env_suffix_for_key(key: &str) -> String {
    key.chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect::<String>()
}

fn parse_bool_text(raw: &str) -> Option<bool> {
    let normalized = raw.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

fn parse_list_lines(raw: Option<&str>) -> Vec<String> {
    raw.map(|value| {
        value
            .lines()
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .map(str::to_string)
            .collect::<Vec<_>>()
    })
    .unwrap_or_default()
}

fn parse_list_env(raw: &str) -> Vec<String> {
    raw.split(';')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>()
}

fn parse_raw_to_json(raw: &str, field_type: ConfigFieldValue) -> Option<JsonValue> {
    match field_type {
        ConfigFieldValue::String(_) => Some(JsonValue::String(raw.to_string())),
        ConfigFieldValue::Integer(_) => raw
            .trim()
            .parse::<i64>()
            .ok()
            .map(|value| JsonValue::Number(value.into())),
        ConfigFieldValue::Float(_) => raw
            .trim()
            .parse::<f64>()
            .ok()
            .and_then(serde_json::Number::from_f64)
            .map(JsonValue::Number),
        ConfigFieldValue::Bool(_) => parse_bool_text(raw).map(JsonValue::Bool),
        ConfigFieldValue::StringList(_) => Some(JsonValue::Array(
            parse_list_env(raw)
                .into_iter()
                .map(JsonValue::String)
                .collect::<Vec<_>>(),
        )),
    }
}

fn default_json_value(field_type: ConfigFieldValue) -> JsonValue {
    match field_type {
        ConfigFieldValue::String(value) => JsonValue::String(value.to_string()),
        ConfigFieldValue::Integer(value) => JsonValue::Number(value.into()),
        ConfigFieldValue::Float(value) => serde_json::Number::from_f64(value)
            .map(JsonValue::Number)
            .unwrap_or(JsonValue::Null),
        ConfigFieldValue::Bool(value) => JsonValue::Bool(value),
        ConfigFieldValue::StringList(values) => JsonValue::Array(
            values
                .iter()
                .map(|value| JsonValue::String((*value).to_string()))
                .collect::<Vec<_>>(),
        ),
    }
}

fn set_opt<T>(dst: &mut T, value: Option<T>) {
    if let Some(v) = value {
        *dst = v;
    }
}

fn set_opt_usize_min(dst: &mut usize, value: Option<usize>, min: usize) {
    if let Some(v) = value {
        *dst = v.max(min);
    }
}

fn set_opt_u64_min(dst: &mut u64, value: Option<u64>, min: u64) {
    if let Some(v) = value {
        *dst = v.max(min);
    }
}

fn set_opt_f64_min(dst: &mut f64, value: Option<f64>, min: f64) {
    if let Some(v) = value {
        *dst = v.max(min);
    }
}

fn toml_to_json(value: toml::Value) -> JsonValue {
    match value {
        toml::Value::String(v) => JsonValue::String(v),
        toml::Value::Integer(v) => JsonValue::Number(v.into()),
        toml::Value::Float(v) => serde_json::Number::from_f64(v)
            .map(JsonValue::Number)
            .unwrap_or(JsonValue::Null),
        toml::Value::Boolean(v) => JsonValue::Bool(v),
        toml::Value::Array(values) => {
            JsonValue::Array(values.into_iter().map(toml_to_json).collect::<Vec<_>>())
        }
        toml::Value::Table(table) => JsonValue::Object(
            table
                .into_iter()
                .map(|(k, v)| (k, toml_to_json(v)))
                .collect::<JsonMap<_, _>>(),
        ),
        toml::Value::Datetime(v) => JsonValue::String(v.to_string()),
    }
}

fn json_to_toml(value: &JsonValue) -> toml::Value {
    match value {
        JsonValue::Null => toml::Value::String(String::new()),
        JsonValue::Bool(v) => toml::Value::Boolean(*v),
        JsonValue::Number(v) => {
            if let Some(i) = v.as_i64() {
                toml::Value::Integer(i)
            } else if let Some(f) = v.as_f64() {
                toml::Value::Float(f)
            } else {
                toml::Value::String(v.to_string())
            }
        }
        JsonValue::String(v) => toml::Value::String(v.clone()),
        JsonValue::Array(values) => {
            toml::Value::Array(values.iter().map(json_to_toml).collect::<Vec<_>>())
        }
        JsonValue::Object(map) => toml::Value::Table(
            map.iter()
                .map(|(k, v)| (k.clone(), json_to_toml(v)))
                .collect::<toml::value::Table>(),
        ),
    }
}
