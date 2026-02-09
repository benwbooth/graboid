use std::collections::HashSet;
use std::path::{Component, Path, PathBuf};

use crate::config::AppConfig;

#[derive(Clone, Copy)]
enum AccessKind {
    Read,
    Write,
}

#[derive(Clone, Debug)]
pub struct LocalPathPolicy {
    read_roots: Vec<PathBuf>,
    write_roots: Vec<PathBuf>,
}

impl LocalPathPolicy {
    pub fn from_config(cfg: &AppConfig) -> Self {
        let default_root = normalize_absolute_path(&cfg.download_dir());
        Self::from_whitelists(
            &cfg.local_read_whitelist,
            &cfg.local_write_whitelist,
            Some(default_root.clone()),
            Some(default_root),
        )
    }

    pub fn from_whitelists(
        read_whitelist: &[String],
        write_whitelist: &[String],
        read_fallback: Option<PathBuf>,
        write_fallback: Option<PathBuf>,
    ) -> Self {
        let read_roots = build_roots(read_whitelist, read_fallback, AccessKind::Read);
        let write_roots = build_roots(write_whitelist, write_fallback, AccessKind::Write);

        Self {
            read_roots,
            write_roots,
        }
    }

    pub fn from_allowlists(read_whitelist: &[String], write_whitelist: &[String]) -> Self {
        Self::from_whitelists(read_whitelist, write_whitelist, None, None)
    }

    pub fn write_roots(&self) -> &[PathBuf] {
        &self.write_roots
    }

    pub fn read_roots(&self) -> &[PathBuf] {
        &self.read_roots
    }

    pub fn is_read_allowed<P: AsRef<Path>>(&self, path: P) -> bool {
        self.is_allowed(path.as_ref(), AccessKind::Read)
    }

    pub fn is_write_allowed<P: AsRef<Path>>(&self, path: P) -> bool {
        self.is_allowed(path.as_ref(), AccessKind::Write)
    }

    fn is_allowed(&self, path: &Path, access: AccessKind) -> bool {
        let resolved = match access {
            AccessKind::Read => resolve_read_target(path),
            AccessKind::Write => resolve_write_target(path),
        };

        let roots = match access {
            AccessKind::Read => &self.read_roots,
            AccessKind::Write => &self.write_roots,
        };

        roots.iter().any(|root| resolved.starts_with(root))
    }
}

fn build_roots(raw: &[String], fallback: Option<PathBuf>, access: AccessKind) -> Vec<PathBuf> {
    let mut roots = raw
        .iter()
        .map(|entry| entry.trim())
        .filter(|entry| !entry.is_empty())
        .map(Path::new)
        .map(normalize_absolute_path)
        .collect::<Vec<_>>();

    if roots.is_empty() {
        if let Some(default_root) = fallback {
            roots.push(default_root);
        }
    }

    let mut dedup = Vec::new();
    let mut seen = HashSet::new();
    for root in roots {
        let resolved = match access {
            AccessKind::Read => resolve_read_target(&root),
            AccessKind::Write => resolve_write_target(&root),
        };
        if seen.insert(resolved.clone()) {
            dedup.push(resolved);
        }
    }

    dedup
}

fn resolve_read_target(path: &Path) -> PathBuf {
    let absolute = normalize_absolute_path(path);
    canonicalize_existing(&absolute).unwrap_or(absolute)
}

fn resolve_write_target(path: &Path) -> PathBuf {
    let absolute = normalize_absolute_path(path);
    if absolute.exists() {
        return canonicalize_existing(&absolute).unwrap_or(absolute);
    }

    let mut anchor = absolute.clone();
    while !anchor.exists() {
        if !anchor.pop() {
            return absolute;
        }
    }

    let resolved_anchor = canonicalize_existing(&anchor).unwrap_or(anchor.clone());
    let suffix = absolute.strip_prefix(&anchor).unwrap_or(Path::new(""));
    normalize_components(&resolved_anchor.join(suffix))
}

fn canonicalize_existing(path: &Path) -> Option<PathBuf> {
    std::fs::canonicalize(path)
        .ok()
        .map(|canonical| normalize_components(&canonical))
}

fn normalize_absolute_path(path: &Path) -> PathBuf {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(path)
    };
    normalize_components(&absolute)
}

fn normalize_components(path: &Path) -> PathBuf {
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

#[cfg(test)]
mod tests {
    use super::LocalPathPolicy;
    use crate::config::AppConfig;

    #[test]
    fn write_allowlist_blocks_parent_escape() {
        let mut cfg = AppConfig::default();
        cfg.local_write_whitelist = vec!["/tmp/graboid-policy/allowed".to_string()];
        cfg.local_read_whitelist = vec!["/tmp/graboid-policy/allowed".to_string()];

        let policy = LocalPathPolicy::from_config(&cfg);

        assert!(policy.is_write_allowed("/tmp/graboid-policy/allowed/output/file.bin"));
        assert!(!policy.is_write_allowed("/tmp/graboid-policy/allowed/../outside/file.bin"));
        assert!(!policy.is_read_allowed("/tmp/graboid-policy/allowed/../outside/file.bin"));
    }
}
