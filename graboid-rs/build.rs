use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    let mut hash = git_rev_short();
    if git_is_dirty() {
        hash.push('*');
    }

    let epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    println!("cargo:rustc-env=BUILD_HASH={hash}");
    println!("cargo:rustc-env=BUILD_EPOCH={epoch}");

    // Support both workspace-root and crate-local git metadata paths.
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/index");
    println!("cargo:rerun-if-changed=.git/refs/heads");
    println!("cargo:rerun-if-changed=../.git/HEAD");
    println!("cargo:rerun-if-changed=../.git/index");
    println!("cargo:rerun-if-changed=../.git/refs/heads");
}

fn git_rev_short() -> String {
    Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|out| out.status.success())
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string())
        .filter(|hash| !hash.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

fn git_is_dirty() -> bool {
    Command::new("git")
        .args(["status", "--porcelain", "-uno"])
        .output()
        .ok()
        .filter(|out| out.status.success())
        .map(|out| !String::from_utf8_lossy(&out.stdout).trim().is_empty())
        .unwrap_or(false)
}
