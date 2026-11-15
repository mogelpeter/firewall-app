//! Update check against the GitHub releases of this project, and the installer hand-off.
//! The installer is downloaded into the admin-only data folder and its SHA-256 (as stated by
//! GitHub for the asset) is verified before it is started.

use std::io::{Read, Write};
use std::path::PathBuf;

use sha2::{Digest, Sha256};

const API: &str = "https://api.github.com/repos/mogelpeter/firewall-app/releases/latest";
const DOWNLOAD_PREFIX: &str = "https://github.com/mogelpeter/firewall-app/releases/download/";
const ASSET: &str = "FirewallManager-Setup.exe";
pub const CURRENT: &str = env!("CARGO_PKG_VERSION");

#[derive(Clone, Debug)]
pub struct Update {
    pub version: String,
    pub url: String,
    pub sha256: String,
    pub notes_url: String,
}

fn parse(v: &str) -> Option<(u32, u32, u32)> {
    let mut it = v.trim().trim_start_matches('v').split('.');
    Some((it.next()?.parse().ok()?, it.next()?.parse().ok()?, it.next()?.parse().ok()?))
}

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(20))
        .user_agent("FirewallManager-updater")
        .build()
}

/// `Ok(None)` = up to date.
pub fn check() -> Result<Option<Update>, String> {
    let v: serde_json::Value = agent()
        .get(API)
        .set("Accept", "application/vnd.github+json")
        .call()
        .map_err(|e| e.to_string())?
        .into_json()
        .map_err(|e| e.to_string())?;
    let tag = v["tag_name"].as_str().ok_or("no tag")?;
    let (new, cur) = (parse(tag).ok_or("bad tag")?, parse(CURRENT).ok_or("bad version")?);
    if new <= cur {
        return Ok(None);
    }
    let asset = v["assets"]
        .as_array()
        .and_then(|a| a.iter().find(|a| a["name"] == ASSET))
        .ok_or("release has no installer")?;
    let url = asset["browser_download_url"].as_str().ok_or("no url")?.to_string();
    if !url.starts_with(DOWNLOAD_PREFIX) {
        return Err("unexpected download location".into());
    }
    let sha256 = asset["digest"]
        .as_str()
        .and_then(|d| d.strip_prefix("sha256:"))
        .ok_or("release has no checksum")?
        .to_lowercase();
    Ok(Some(Update {
        version: tag.trim_start_matches('v').to_string(),
        url,
        sha256,
        notes_url: v["html_url"].as_str().unwrap_or("").to_string(),
    }))
}

fn update_dir() -> Result<PathBuf, String> {
    let d = crate::fw::secure_dir().ok_or("data folder not available")?.join("update");
    std::fs::create_dir_all(&d).map_err(|e| e.to_string())?;
    Ok(d)
}

/// Removes leftovers of an earlier update.
pub fn cleanup() {
    if let Ok(d) = update_dir() {
        let _ = std::fs::remove_dir_all(d);
    }
}

/// Downloads, verifies and starts the installer silently. The caller should exit afterwards.
pub fn install(u: &Update, progress: impl Fn(u64, u64)) -> Result<(), String> {
    let dir = update_dir()?;
    let file = dir.join(ASSET);
    let resp = agent().get(&u.url).call().map_err(|e| e.to_string())?;
    let total: u64 = resp.header("Content-Length").and_then(|s| s.parse().ok()).unwrap_or(0);
    let mut r = resp.into_reader();
    let mut out = std::fs::File::create(&file).map_err(|e| e.to_string())?;
    let (mut h, mut buf, mut done) = (Sha256::new(), [0u8; 64 * 1024], 0u64);
    loop {
        let n = r.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
        out.write_all(&buf[..n]).map_err(|e| e.to_string())?;
        done += n as u64;
        progress(done, total);
    }
    drop(out);
    let got: String = h.finalize().iter().map(|b| format!("{b:02x}")).collect();
    if got != u.sha256 {
        let _ = std::fs::remove_file(&file);
        return Err("download does not match the published checksum, update refused".into());
    }
    std::process::Command::new(&file)
        .args(["/SILENT", "/NORESTART", "/CLOSEAPPLICATIONS"])
        .spawn()
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_compare() {
        assert!(parse("v2.10.0") > parse("2.9.9"));
        assert_eq!(parse("junk"), None);
    }
}
