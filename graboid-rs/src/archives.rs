use std::fs::File;
use std::io;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail};
use bzip2::read::BzDecoder;
use flate2::read::GzDecoder;
use globset::{Glob, GlobSet, GlobSetBuilder};
use tar::Archive;
use tokio::task;
use walkdir::WalkDir;
use xz2::read::XzDecoder;
use zip::read::ZipArchive;
use zstd::stream::read::Decoder as ZstdDecoder;

pub fn is_archive(path: &Path) -> bool {
    let name = path
        .file_name()
        .map(|v| v.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();

    name.ends_with(".zip")
        || name.ends_with(".tar")
        || name.ends_with(".tar.gz")
        || name.ends_with(".tgz")
        || name.ends_with(".tar.bz2")
        || name.ends_with(".tbz2")
        || name.ends_with(".tar.xz")
        || name.ends_with(".txz")
        || name.ends_with(".tar.zst")
        || name.ends_with(".tzst")
        || name.ends_with(".gz")
        || name.ends_with(".bz2")
        || name.ends_with(".xz")
        || name.ends_with(".zst")
        || name.ends_with(".7z")
        || name.ends_with(".rar")
}

pub fn default_extract_dir(path: &Path) -> PathBuf {
    let parent = path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    parent.join(strip_archive_suffix(path))
}

pub async fn extract_archive(
    archive_path: PathBuf,
    output_dir: PathBuf,
    patterns: Vec<String>,
) -> Result<Vec<PathBuf>> {
    task::spawn_blocking(move || extract_archive_sync(&archive_path, &output_dir, &patterns))
        .await
        .context("archive extraction task failed")?
}

fn extract_archive_sync(
    archive_path: &Path,
    output_dir: &Path,
    patterns: &[String],
) -> Result<Vec<PathBuf>> {
    std::fs::create_dir_all(output_dir)
        .with_context(|| format!("failed creating extraction dir {}", output_dir.display()))?;

    let matcher = build_pattern_matcher(patterns)?;
    let name = archive_path
        .file_name()
        .map(|v| v.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();

    if name.ends_with(".zip") {
        return extract_zip(archive_path, output_dir, matcher.as_ref());
    }
    if name.ends_with(".tar")
        || name.ends_with(".tar.gz")
        || name.ends_with(".tgz")
        || name.ends_with(".tar.bz2")
        || name.ends_with(".tbz2")
        || name.ends_with(".tar.xz")
        || name.ends_with(".txz")
        || name.ends_with(".tar.zst")
        || name.ends_with(".tzst")
    {
        return extract_tar(archive_path, output_dir, matcher.as_ref());
    }
    if name.ends_with(".zst")
        || name.ends_with(".gz")
        || name.ends_with(".bz2")
        || name.ends_with(".xz")
    {
        return extract_single_compressed(archive_path, output_dir, matcher.as_ref());
    }
    if name.ends_with(".7z") || name.ends_with(".rar") {
        return extract_with_external_tool(archive_path, output_dir, matcher.as_ref());
    }

    bail!("unsupported archive format: {}", archive_path.display())
}

fn extract_zip(
    archive_path: &Path,
    output_dir: &Path,
    matcher: Option<&GlobSet>,
) -> Result<Vec<PathBuf>> {
    let file = File::open(archive_path)
        .with_context(|| format!("failed opening zip archive {}", archive_path.display()))?;
    let mut archive = ZipArchive::new(file).context("failed reading zip archive")?;

    let mut extracted = Vec::new();
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).context("failed reading zip entry")?;
        if entry.is_dir() {
            continue;
        }

        let Some(rel_path) = entry.enclosed_name() else {
            continue;
        };
        if !matches_filter(&rel_path, matcher) {
            continue;
        }

        let dest = output_dir.join(&rel_path);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed creating {}", parent.display()))?;
        }
        let mut out =
            File::create(&dest).with_context(|| format!("failed creating {}", dest.display()))?;
        io::copy(&mut entry, &mut out)
            .with_context(|| format!("failed extracting {}", rel_path.display()))?;
        extracted.push(dest);
    }

    Ok(extracted)
}

fn extract_tar(
    archive_path: &Path,
    output_dir: &Path,
    matcher: Option<&GlobSet>,
) -> Result<Vec<PathBuf>> {
    let name = archive_path
        .file_name()
        .map(|v| v.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();

    if name.ends_with(".tar.gz") || name.ends_with(".tgz") {
        let file = File::open(archive_path)
            .with_context(|| format!("failed opening archive {}", archive_path.display()))?;
        let decoder = GzDecoder::new(file);
        return extract_tar_stream(Archive::new(decoder), output_dir, matcher);
    }
    if name.ends_with(".tar.bz2") || name.ends_with(".tbz2") {
        let file = File::open(archive_path)
            .with_context(|| format!("failed opening archive {}", archive_path.display()))?;
        let decoder = BzDecoder::new(file);
        return extract_tar_stream(Archive::new(decoder), output_dir, matcher);
    }
    if name.ends_with(".tar.xz") || name.ends_with(".txz") {
        let file = File::open(archive_path)
            .with_context(|| format!("failed opening archive {}", archive_path.display()))?;
        let decoder = XzDecoder::new(file);
        return extract_tar_stream(Archive::new(decoder), output_dir, matcher);
    }
    if name.ends_with(".tar.zst") || name.ends_with(".tzst") {
        let file = File::open(archive_path)
            .with_context(|| format!("failed opening archive {}", archive_path.display()))?;
        let decoder = ZstdDecoder::new(file).context("failed initializing zstd decoder")?;
        return extract_tar_stream(Archive::new(decoder), output_dir, matcher);
    }

    let file = File::open(archive_path)
        .with_context(|| format!("failed opening archive {}", archive_path.display()))?;
    extract_tar_stream(Archive::new(file), output_dir, matcher)
}

fn extract_single_compressed(
    archive_path: &Path,
    output_dir: &Path,
    matcher: Option<&GlobSet>,
) -> Result<Vec<PathBuf>> {
    let name = archive_path
        .file_name()
        .map(|v| v.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();

    if name.ends_with(".zst") {
        let file = File::open(archive_path)
            .with_context(|| format!("failed opening archive {}", archive_path.display()))?;
        let decoder = ZstdDecoder::new(file).context("failed initializing zstd decoder")?;
        return extract_single_compressed_stream(decoder, archive_path, output_dir, matcher);
    }
    if name.ends_with(".gz") {
        let file = File::open(archive_path)
            .with_context(|| format!("failed opening archive {}", archive_path.display()))?;
        let decoder = GzDecoder::new(file);
        return extract_single_compressed_stream(decoder, archive_path, output_dir, matcher);
    }
    if name.ends_with(".bz2") {
        let file = File::open(archive_path)
            .with_context(|| format!("failed opening archive {}", archive_path.display()))?;
        let decoder = BzDecoder::new(file);
        return extract_single_compressed_stream(decoder, archive_path, output_dir, matcher);
    }
    if name.ends_with(".xz") {
        let file = File::open(archive_path)
            .with_context(|| format!("failed opening archive {}", archive_path.display()))?;
        let decoder = XzDecoder::new(file);
        return extract_single_compressed_stream(decoder, archive_path, output_dir, matcher);
    }

    bail!(
        "unsupported single-file compressed format: {}",
        archive_path.display()
    )
}

fn extract_single_compressed_stream<R: io::Read>(
    mut decoder: R,
    archive_path: &Path,
    output_dir: &Path,
    matcher: Option<&GlobSet>,
) -> Result<Vec<PathBuf>> {
    let output_name = strip_single_compression_suffix(archive_path);
    let rel_path = PathBuf::from(output_name);
    if !matches_filter(&rel_path, matcher) {
        return Ok(Vec::new());
    }

    let dest = output_dir.join(&rel_path);
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed creating {}", parent.display()))?;
    }

    let mut out =
        File::create(&dest).with_context(|| format!("failed creating {}", dest.display()))?;
    io::copy(&mut decoder, &mut out)
        .with_context(|| format!("failed extracting {}", rel_path.display()))?;

    Ok(vec![dest])
}

fn extract_tar_stream<R: io::Read>(
    mut archive: Archive<R>,
    output_dir: &Path,
    matcher: Option<&GlobSet>,
) -> Result<Vec<PathBuf>> {
    let mut extracted = Vec::new();
    for entry in archive.entries().context("failed reading tar entries")? {
        let mut entry = entry.context("failed reading tar entry")?;
        if entry.header().entry_type().is_dir() {
            continue;
        }

        let Ok(path) = entry.path() else {
            continue;
        };
        let Some(rel_path) = sanitize_relative_path(path.as_ref()) else {
            continue;
        };
        if !matches_filter(&rel_path, matcher) {
            continue;
        }

        let dest = output_dir.join(&rel_path);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed creating {}", parent.display()))?;
        }

        entry
            .unpack(&dest)
            .with_context(|| format!("failed extracting {}", rel_path.display()))?;
        if dest.is_file() {
            extracted.push(dest);
        }
    }

    Ok(extracted)
}

fn extract_with_external_tool(
    archive_path: &Path,
    output_dir: &Path,
    matcher: Option<&GlobSet>,
) -> Result<Vec<PathBuf>> {
    let seven_zip = which::which("7z").ok().or_else(|| which::which("7za").ok());
    if let Some(bin) = seven_zip {
        let status = std::process::Command::new(bin)
            .arg("x")
            .arg("-y")
            .arg(format!("-o{}", output_dir.display()))
            .arg(archive_path)
            .status()
            .context("failed spawning 7z")?;
        if !status.success() {
            bail!("7z extraction failed for {}", archive_path.display());
        }
        return collect_extracted_files(output_dir, matcher);
    }

    if archive_path
        .file_name()
        .map(|v| v.to_string_lossy().to_ascii_lowercase().ends_with(".rar"))
        .unwrap_or(false)
    {
        if let Ok(bin) = which::which("unrar") {
            let status = std::process::Command::new(bin)
                .arg("x")
                .arg("-o+")
                .arg(archive_path)
                .arg(output_dir)
                .status()
                .context("failed spawning unrar")?;
            if !status.success() {
                bail!("unrar extraction failed for {}", archive_path.display());
            }
            return collect_extracted_files(output_dir, matcher);
        }
    }

    bail!(
        "no extractor available for {} (requires 7z or unrar)",
        archive_path.display()
    )
}

fn collect_extracted_files(output_dir: &Path, matcher: Option<&GlobSet>) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for entry in WalkDir::new(output_dir) {
        let entry = entry.context("failed walking extracted files")?;
        if !entry.file_type().is_file() {
            continue;
        }

        let rel_path = entry
            .path()
            .strip_prefix(output_dir)
            .unwrap_or(entry.path())
            .to_path_buf();
        if !matches_filter(&rel_path, matcher) {
            continue;
        }
        files.push(entry.path().to_path_buf());
    }
    files.sort();
    files.dedup();
    Ok(files)
}

fn sanitize_relative_path(path: &Path) -> Option<PathBuf> {
    if path.is_absolute() {
        return None;
    }

    let mut sanitized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => sanitized.push(part),
            Component::CurDir => {}
            _ => return None,
        }
    }

    if sanitized.as_os_str().is_empty() {
        None
    } else {
        Some(sanitized)
    }
}

fn build_pattern_matcher(patterns: &[String]) -> Result<Option<GlobSet>> {
    let mut builder = GlobSetBuilder::new();
    let mut added = 0usize;

    for raw in patterns {
        let pattern = raw.trim();
        if pattern.is_empty() {
            continue;
        }
        if let Ok(glob) = Glob::new(pattern) {
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
            .context("failed compiling archive patterns")?,
    ))
}

fn matches_filter(path: &Path, matcher: Option<&GlobSet>) -> bool {
    let Some(matcher) = matcher else {
        return true;
    };

    if matcher.is_match(path) {
        return true;
    }

    path.file_name()
        .map(|name| matcher.is_match(name))
        .unwrap_or(false)
}

fn strip_archive_suffix(path: &Path) -> String {
    let name = path
        .file_name()
        .map(|v| v.to_string_lossy().to_string())
        .unwrap_or_else(|| "extracted".to_string());
    let lower = name.to_ascii_lowercase();

    for suffix in [
        ".tar.zst", ".tzst", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz", ".tar",
        ".zip", ".7z", ".rar", ".zst", ".gz", ".bz2", ".xz",
    ] {
        if lower.ends_with(suffix) {
            let keep = name.len().saturating_sub(suffix.len());
            let trimmed = name[..keep].trim().to_string();
            let decoded = sanitize_output_name(&decode_percent_escapes(&trimmed));
            return if decoded.is_empty() {
                "extracted".to_string()
            } else {
                decoded
            };
        }
    }

    path.file_stem()
        .map(|v| v.to_string_lossy().to_string())
        .map(|v| sanitize_output_name(&decode_percent_escapes(&v)))
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| "extracted".to_string())
}

fn strip_single_compression_suffix(path: &Path) -> String {
    let name = path
        .file_name()
        .map(|v| v.to_string_lossy().to_string())
        .unwrap_or_else(|| "extracted".to_string());
    let lower = name.to_ascii_lowercase();
    for suffix in [".zst", ".gz", ".bz2", ".xz"] {
        if lower.ends_with(suffix) {
            let keep = name.len().saturating_sub(suffix.len());
            let trimmed = name[..keep].trim().to_string();
            let decoded = sanitize_output_name(&decode_percent_escapes(&trimmed));
            return if decoded.is_empty() {
                "extracted".to_string()
            } else {
                decoded
            };
        }
    }
    sanitize_output_name(&decode_percent_escapes(&name))
}

fn sanitize_output_name(value: &str) -> String {
    value
        .chars()
        .map(|ch| match ch {
            '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
            _ => ch,
        })
        .collect()
}

fn decode_percent_escapes(input: &str) -> String {
    fn hex(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }

    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut idx = 0;
    let mut changed = false;

    while idx < bytes.len() {
        if bytes[idx] == b'%' && idx + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex(bytes[idx + 1]), hex(bytes[idx + 2])) {
                out.push((hi << 4) | lo);
                idx += 3;
                changed = true;
                continue;
            }
        }
        out.push(bytes[idx]);
        idx += 1;
    }

    if !changed {
        return input.to_string();
    }

    String::from_utf8(out).unwrap_or_else(|_| input.to_string())
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::{default_extract_dir, strip_archive_suffix, strip_single_compression_suffix};

    #[test]
    fn strip_archive_suffix_decodes_percent_escapes() {
        assert_eq!(
            strip_archive_suffix(Path::new("Internet%20Archive%20Pack.zip")),
            "Internet Archive Pack"
        );
    }

    #[test]
    fn strip_single_suffix_decodes_percent_escapes() {
        assert_eq!(
            strip_single_compression_suffix(Path::new("Sample%20File.chd.zst")),
            "Sample File.chd"
        );
    }

    #[test]
    fn default_extract_dir_uses_decoded_name() {
        assert_eq!(
            default_extract_dir(Path::new("/tmp/NES%20Complete%20Set.7z")),
            PathBuf::from("/tmp/NES Complete Set")
        );
    }
}
