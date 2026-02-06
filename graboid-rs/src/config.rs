use std::collections::BTreeMap;
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
            config_path: PathBuf::from("config.toml"),
        }
    }
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
        set_opt(&mut self.bind_addr, file_cfg.bind_addr);
        set_opt(&mut self.database_path, file_cfg.database_path);
        set_opt(&mut self.download_dir, file_cfg.download_dir);
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
        set_opt(
            &mut self.download_allow_insecure,
            file_cfg.download_allow_insecure,
        );
        set_opt_usize_min(
            &mut self.jobs_max_concurrent,
            file_cfg.jobs_max_concurrent,
            1,
        );
        set_opt(&mut self.claude_model, file_cfg.claude_model);
        set_opt(&mut self.claude_cmd, file_cfg.claude_cmd);
        set_opt(&mut self.api_key, file_cfg.api_key);
        set_opt(&mut self.chrome_debug_port, file_cfg.chrome_debug_port);
        set_opt(&mut self.chrome_headless, file_cfg.chrome_headless);
        set_opt(&mut self.browser_mode, file_cfg.browser_mode);
        set_opt(
            &mut self.browser_use_mcp_command,
            file_cfg.browser_use_mcp_command,
        );
        set_opt(
            &mut self.browser_use_mcp_args,
            file_cfg.browser_use_mcp_args,
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
        set_opt(&mut self.ollama_host, file_cfg.ollama_host);
        set_opt(&mut self.torrent_client, file_cfg.torrent_client);
        set_opt(&mut self.qbittorrent_host, file_cfg.qbittorrent_host);
        set_opt(&mut self.qbittorrent_port, file_cfg.qbittorrent_port);
        set_opt(
            &mut self.qbittorrent_username,
            file_cfg.qbittorrent_username,
        );
        set_opt(
            &mut self.qbittorrent_password,
            file_cfg.qbittorrent_password,
        );
        set_opt(&mut self.transmission_host, file_cfg.transmission_host);
        set_opt(&mut self.transmission_port, file_cfg.transmission_port);
        set_opt(
            &mut self.transmission_username,
            file_cfg.transmission_username,
        );
        set_opt(
            &mut self.transmission_password,
            file_cfg.transmission_password,
        );
        set_opt(&mut self.deluge_host, file_cfg.deluge_host);
        set_opt(&mut self.deluge_port, file_cfg.deluge_port);
        set_opt(&mut self.deluge_username, file_cfg.deluge_username);
        set_opt(&mut self.deluge_password, file_cfg.deluge_password);
        set_opt(&mut self.rtorrent_url, file_cfg.rtorrent_url);
        set_opt(&mut self.aria2_host, file_cfg.aria2_host);
        set_opt(&mut self.aria2_port, file_cfg.aria2_port);
        set_opt(&mut self.aria2_secret, file_cfg.aria2_secret);
    }

    fn apply_env(&mut self) {
        let env_cfg = FileConfig {
            bind_addr: env_string("GRABOID_RS_BIND_ADDR"),
            database_path: env_string("GRABOID_RS_DATABASE_PATH"),
            download_dir: env_string("GRABOID_RS_DOWNLOAD_DIR"),
            download_retry_attempts: env_parse("GRABOID_RS_DOWNLOAD_RETRY_ATTEMPTS"),
            download_max_parallel: env_parse("GRABOID_RS_DOWNLOAD_MAX_PARALLEL"),
            download_retry_backoff_sec: env_parse("GRABOID_RS_DOWNLOAD_RETRY_BACKOFF_SEC"),
            download_allow_insecure: env_parse("GRABOID_RS_DOWNLOAD_ALLOW_INSECURE"),
            jobs_max_concurrent: env_parse("GRABOID_RS_JOBS_MAX_CONCURRENT"),
            claude_model: env_string("GRABOID_RS_CLAUDE_MODEL"),
            claude_cmd: env_string("GRABOID_RS_CLAUDE_CMD"),
            api_key: env_string("GRABOID_RS_API_KEY"),
            chrome_debug_port: env_parse("GRABOID_RS_CHROME_DEBUG_PORT"),
            chrome_headless: env_parse("GRABOID_RS_CHROME_HEADLESS"),
            browser_mode: env_string("GRABOID_RS_BROWSER_MODE"),
            browser_use_mcp_command: env_string("GRABOID_RS_BROWSER_USE_MCP_COMMAND"),
            browser_use_mcp_args: env_string("GRABOID_RS_BROWSER_USE_MCP_ARGS"),
            claude_timeout_seconds: env_parse("GRABOID_RS_CLAUDE_TIMEOUT_SECONDS"),
            download_timeout_seconds: env_parse("GRABOID_RS_DOWNLOAD_TIMEOUT_SECONDS"),
            ollama_host: env_string("GRABOID_RS_OLLAMA_HOST"),
            torrent_client: env_string("GRABOID_RS_TORRENT_CLIENT"),
            qbittorrent_host: env_string("GRABOID_RS_QBITTORRENT_HOST"),
            qbittorrent_port: env_parse("GRABOID_RS_QBITTORRENT_PORT"),
            qbittorrent_username: env_string("GRABOID_RS_QBITTORRENT_USERNAME"),
            qbittorrent_password: env_string("GRABOID_RS_QBITTORRENT_PASSWORD"),
            transmission_host: env_string("GRABOID_RS_TRANSMISSION_HOST"),
            transmission_port: env_parse("GRABOID_RS_TRANSMISSION_PORT"),
            transmission_username: env_string("GRABOID_RS_TRANSMISSION_USERNAME"),
            transmission_password: env_string("GRABOID_RS_TRANSMISSION_PASSWORD"),
            deluge_host: env_string("GRABOID_RS_DELUGE_HOST"),
            deluge_port: env_parse("GRABOID_RS_DELUGE_PORT"),
            deluge_username: env_string("GRABOID_RS_DELUGE_USERNAME"),
            deluge_password: env_string("GRABOID_RS_DELUGE_PASSWORD"),
            rtorrent_url: env_string("GRABOID_RS_RTORRENT_URL"),
            aria2_host: env_string("GRABOID_RS_ARIA2_HOST"),
            aria2_port: env_parse("GRABOID_RS_ARIA2_PORT"),
            aria2_secret: env_string("GRABOID_RS_ARIA2_SECRET"),
        };
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

fn env_parse<T>(key: &str) -> Option<T>
where
    T: std::str::FromStr,
{
    env::var(key).ok().and_then(|v| v.parse::<T>().ok())
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
