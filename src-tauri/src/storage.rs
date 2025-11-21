use anyhow::{Context, Result};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Mutex;

pub fn resolve_client_root() -> Result<PathBuf> {
    let mut dir = env::current_dir()?;
    for _ in 0..5 {
        if dir.join("package.json").exists() && dir.join("src-tauri").exists() {
            return Ok(dir);
        }
        if !dir.pop() {
            break;
        }
    }

    if let Ok(mut exe_dir) = env::current_exe() {
        for _ in 0..7 {
            if exe_dir.join("package.json").exists() && exe_dir.join("src-tauri").exists() {
                return Ok(exe_dir);
            }
            if !exe_dir.pop() {
                break;
            }
        }
    }

    env::current_dir().map_err(Into::into)
}

pub fn ensure_dir(path: &Path) -> Result<PathBuf> {
    if !path.exists() {
        fs::create_dir_all(path).with_context(|| format!("无法创建目录: {}", path.display()))?;
    }
    Ok(path.to_path_buf())
}

pub fn create_dir(path: &str) -> Result<PathBuf> {
    let buf = PathBuf::from(path);
    ensure_dir(&buf)
}

pub fn get_app_data_dir() -> Result<PathBuf> {
    let root = resolve_client_root()?;
    let dir = root.join("data");
    ensure_dir(&dir)
}

pub fn get_app_config_dir() -> Result<PathBuf> {
    let dir = get_app_data_dir()?.join("config");
    ensure_dir(&dir)
}

pub async fn write_file(path: &str, contents: &str, lock: &Arc<Mutex<()>>) -> Result<()> {
    let path_buf = PathBuf::from(path);
    if let Some(parent) = path_buf.parent() {
        ensure_dir(parent)?;
    }
    let _guard = lock.lock().await;
    tokio::fs::write(&path_buf, contents)
        .await
        .with_context(|| format!("写入文件失败: {}", path_buf.display()))
}

pub async fn read_file(path: &Path, lock: &Arc<Mutex<()>>) -> Result<Option<String>> {
    let _guard = lock.lock().await;
    if !path.exists() {
        return Ok(None);
    }
    let content = tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("读取文件失败: {}", path.display()))?;
    if content.trim().is_empty() {
        Ok(None)
    } else {
        Ok(Some(content))
    }
}
