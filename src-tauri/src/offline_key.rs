use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::{engine::general_purpose, Engine as _};
use chrono::{DateTime, Utc};
use once_cell::sync::Lazy;
use rand::rngs::OsRng;
use rand::RngCore;
use rsa::pkcs8::DecodePrivateKey;
use rsa::{Oaep, RsaPrivateKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;
use std::convert::TryFrom;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::Mutex;

use crate::config::{FileWriteLock, OFFLINE_KEY_ENV_NAME};
use crate::device;

const OFFLINE_RSA_PRIVATE_KEY: &str = r"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDVKT08cxtJyhsx
l9A0+6o7PR5EN12E/gaVXSInY/g9GgTeCcaXBm7FifosFCaVGcvmjJrhxTaNsp/7
VM+S7jJVfmIYuVnwhhGdis5iJlG8fL2ekG1c1HtShxK7vcrhv8lDrc3zEIbX1v6r
9sy4T8gZH8peg6dnzmMKHRPhXGscr2SIHn3xsdkP/kCY+4mOsRLdV0IESho0BsNC
W4smTp4lx9zZKM9Q6DNF62B/2Gd4v+vTixogouQVbSJspTg/AbRx+snZbvX1Fe2d
I1pFvosWO/rh/K2Wt4PW9KUoQOQXt1WUWIQv5+4FQI82zcRR0BuUf4bfPnUy64ms
b8cfUA+1AgMBAAECggEAAP1hTitPG/u3iLR3KIeQfq0dmpZ8ED8KS0T2xtgktxUT
1IwKlui1NIv2rROflgu/DcZe0EDhtJhPlz79EX71W3x+mZBvR0x8dJ1QfzTZy5El
a+5m4MIpj1V1tgzoeYf4K5yV+RzgWuUmCiCZc9Crqo509We+vI5JX1g2zPMqgSAe
CEQnPPvXPIPrMeo8fHJuW7OLytuGCzIogYY9vdPeTde7tBn/5FOz9tNhqSxNR1Ru
2vNvgBsacWNZ0x5aeXLj698RMNm92Ny/ytOdvcYRBtt7677FKZ3GpnDMeB8uHyKF
3MHm0n1uaXpYJzaYrAPLNFoPt4uWp9uCtCHY5YhbQQKBgQDt/XGFepU/moQXTpKE
aVKxXtqbqvgEJBdlq9xZ6Z4I3yvVxiVNC08ponHwGUI8XJ/ATR56DiKfIrEyx72o
RL39AoFaQ6XHwTnk1wgZ2M10HZksFX4SLCYewWesoOwzPYwVu6kLBDZINIw4qdzv
Et23dLsec3bjDEwgdlVIuBdxlQKBgQDlSsmcO3qUroLwkHSKq5d6lGZA0HWEADcm
fqb/B4fAtTsG7aaw7mFIiEbkvzG4MdH+lpx+6pOCZPPEwI6RmIjgb9mxpv5Wy0XL
SOPxYsAjlhdYfZ88ZTueyTBDnd1k1VbLKhC4hNuCEgMI3LfVJv/3GXp0gJu5bGAB
6kQgFHTdoQKBgBQyoEHNx4DgYjmAJ5spPSVkgXUYq3fegEXWshrHYuwp1JSN/nht
b0h/SuAvpJlu2vf9E4sUTAfpb9R5czUmsGEap1O7zgQH+BvdzAg1iCpEoM1G/a4Z
JRsTGvNhrOokXREzHgObVegG3aepcuCvXzXEqGTLM9nNH2DZ6h8D0KmJAoGBAMpZ
Ucragrcruspp8S9fdvLqe8K/NLYlKoaCRwXRs2/RgCIBIJYMCTZlbYr5X/tZnCS8
7abjhQIR7T65YBgFMOZATzGEWfhms1VPIjooF8BP+JJTam92N0NN8ZX6fyM5UrtA
iDkOplkHZD4x6tnk7Qc4KOUfik384k1OXIijBO+BAoGBANmeLjg9ZQicQgNFHUF2
IHXWLXk7UXEGIGc94fpBs3XJv3Gs33STpdrUZ7HpMxeaNyKT7o3h0gMRfCAWdE+Y
6+0pcY3LO8xt47mM0fJ4rmO3UtPtRFCB4zfl5LLRXTxMWlDGGeMpkXnTDyepdUer
ngynrceK8F5b7rIPg7tmoFji
-----END PRIVATE KEY-----";
const OFFLINE_AES_KEY_B64: &str = "94/AR7dd8gIstLEXp3LCs865DptiMKlh8nLjjDEcO40=";
const OFFLINE_KEY_SEPARATOR: &str = "|||";

static PRIVATE_KEY: Lazy<RsaPrivateKey> = Lazy::new(|| {
    RsaPrivateKey::from_pkcs8_pem(OFFLINE_RSA_PRIVATE_KEY)
        .expect("failed to parse offline RSA private key")
});

static AES_KEY: Lazy<[u8; 32]> = Lazy::new(|| {
    let bytes = general_purpose::STANDARD
        .decode(OFFLINE_AES_KEY_B64)
        .expect("failed to decode offline AES key");
    bytes
        .try_into()
        .expect("invalid offline AES key length: expected 32 bytes")
});

/// 离线许可证载荷数据结构
/// 使用 Deserialize 自动处理 JSON 反序列化
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfflineLicensePayload {
    pub user_id: u32,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub email: String,
    pub device_id: String,
    pub expires_at: String,
    pub issued_at: String,
}

#[derive(Debug, Error)]
enum OfflineKeyError {
    #[error("离线密钥格式无效")]
    InvalidFormat,
    #[error("离线密钥数据无效: {0}")]
    InvalidData(String),
    #[error("离线密钥加解密失败: {0}")]
    Crypto(String),
    #[error("文件操作失败: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfflineKeyValidationResult {
    pub is_valid: bool,
    pub reason: Option<String>,
    pub expires_at: Option<String>,
    pub payload: Option<OfflineLicensePayload>,
}

/// 从环境变量指定的文件验证离线密钥
pub async fn validate_from_env(lock: &Arc<Mutex<()>>) -> OfflineKeyValidationResult {
    match try_validate_from_env(lock).await {
        Ok(result) => result,
        Err(error) => {
            // 简化错误处理，只返回错误信息
            OfflineKeyValidationResult {
                is_valid: false,
                reason: Some(error.to_string()),
                expires_at: None,
                payload: None,
            }
        }
    }
}

async fn try_validate_from_env(
    lock: &Arc<Mutex<()>>,
) -> Result<OfflineKeyValidationResult, OfflineKeyError> {
    let env_path = match std::env::var(OFFLINE_KEY_ENV_NAME) {
        Ok(value) => PathBuf::from(value),
        Err(_) => {
            return Ok(build_invalid_result(
                format!("环境变量 {OFFLINE_KEY_ENV_NAME} 未设置"),
                None,
                None,
            ));
        }
    };

    if !env_path.exists() {
        return Ok(build_invalid_result("离线密钥文件不存在", None, None));
    }

    let raw = read_file_with_lock(&env_path, lock).await?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(build_invalid_result("离线密钥文件为空", None, None));
    }

    let (rsa_part, aes_part) = split_offline_key(trimmed)?;
    let payload = decrypt_license_payload(&rsa_part)?;
    let server_time = decrypt_server_time(&aes_part)?;

    let expires_at = chrono::DateTime::parse_from_rfc3339(&payload.expires_at)
        .map_err(|_| OfflineKeyError::InvalidData("离线密钥到期时间无效".into()))?
        .with_timezone(&Utc);

    let now = Utc::now();
    if now > expires_at {
        return Ok(build_invalid_result(
            "离线密钥已过期",
            Some(payload.expires_at.clone()),
            Some(payload),
        ));
    }

    let device_id = device::get_device_id()
        .map_err(|err| OfflineKeyError::InvalidData(format!("无法获取设备标识: {err}")))?;
    if payload.device_id != device_id {
        return Ok(build_invalid_result(
            "当前设备与离线密钥绑定设备不一致",
            Some(payload.expires_at.clone()),
            Some(payload),
        ));
    }

    if now < server_time {
        return Ok(build_invalid_result(
            "检测到离线密钥时间被回滚，请重新获取",
            Some(payload.expires_at.clone()),
            Some(payload),
        ));
    }

    let updated_aes_part = encrypt_current_time(now)?;
    let updated_raw = combine_offline_key(&rsa_part, &updated_aes_part);
    write_file_with_lock(&env_path, updated_raw.as_bytes(), lock).await?;

    log_validation_success(&payload);

    Ok(OfflineKeyValidationResult {
        is_valid: true,
        reason: None,
        expires_at: Some(payload.expires_at.clone()),
        payload: Some(payload),
    })
}

async fn read_file_with_lock(
    path: &Path,
    lock: &Arc<Mutex<()>>,
) -> Result<String, OfflineKeyError> {
    let _guard = lock.lock().await;
    let content = tokio::fs::read_to_string(path).await?;
    Ok(content)
}

async fn write_file_with_lock(
    path: &Path,
    content: &[u8],
    lock: &Arc<Mutex<()>>,
) -> Result<(), OfflineKeyError> {
    let _guard = lock.lock().await;
    tokio::fs::write(path, content).await?;
    Ok(())
}

fn split_offline_key(raw: &str) -> Result<(String, String), OfflineKeyError> {
    let parts: Vec<&str> = raw.split(OFFLINE_KEY_SEPARATOR).collect();
    if parts.len() != 2 || parts.iter().any(|part| part.trim().is_empty()) {
        return Err(OfflineKeyError::InvalidFormat);
    }
    Ok((parts[0].to_string(), parts[1].to_string()))
}

fn decrypt_license_payload(encoded: &str) -> Result<OfflineLicensePayload, OfflineKeyError> {
    let private_key = &*PRIVATE_KEY;
    let encrypted = general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| OfflineKeyError::InvalidData("RSA 密文格式无效".into()))?;
    let padding = Oaep::new::<Sha256>();
    let decrypted = private_key
        .decrypt(padding, &encrypted)
        .map_err(|err| OfflineKeyError::Crypto(format!("RSA 解密失败: {err}")))?;
    
    // 调试：打印解密后的 JSON
    if let Ok(json_str) = std::str::from_utf8(&decrypted) {
        println!("解密后的 payload JSON: {}", json_str);
    }
    
    // 直接使用 serde 反序列化
    serde_json::from_slice(&decrypted)
        .map_err(|err| OfflineKeyError::InvalidData(format!("JSON 反序列化失败: {}", err)))
}

fn decrypt_server_time(encoded: &str) -> Result<DateTime<Utc>, OfflineKeyError> {
    let combined = general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| OfflineKeyError::InvalidData("时间密文格式无效".into()))?;
    if combined.len() <= 12 {
        return Err(OfflineKeyError::InvalidData("离线时间数据损坏".into()));
    }
    let (nonce, ciphertext) = combined.split_at(12);
    let nonce_bytes: [u8; 12] = nonce
        .try_into()
        .map_err(|_| OfflineKeyError::InvalidData("离线时间数据损坏".into()))?;
    let nonce = Nonce::from(nonce_bytes);
    let cipher = Aes256Gcm::new_from_slice(&AES_KEY[..])
        .map_err(|err| OfflineKeyError::Crypto(format!("AES 密钥初始化失败: {err}")))?;
    let plaintext = cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|err| OfflineKeyError::Crypto(format!("AES 解密失败: {err}")))?;
    let time_str = String::from_utf8(plaintext)
        .map_err(|_| OfflineKeyError::InvalidData("服务器时间格式无效".into()))?;
    DateTime::parse_from_rfc3339(&time_str)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|_| OfflineKeyError::InvalidData("服务器时间格式无效".into()))
}

fn encrypt_current_time(now: DateTime<Utc>) -> Result<String, OfflineKeyError> {
    let cipher = Aes256Gcm::new_from_slice(&AES_KEY[..])
        .map_err(|err| OfflineKeyError::Crypto(format!("AES 密钥初始化失败: {err}")))?;
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce_len = nonce_bytes.len();
    let nonce = Nonce::from(nonce_bytes);
    let ciphertext = cipher
        .encrypt(&nonce, now.to_rfc3339().as_bytes())
        .map_err(|err| OfflineKeyError::Crypto(format!("AES 加密失败: {err}")))?;
    let mut combined = Vec::with_capacity(nonce_len + ciphertext.len());
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&ciphertext);
    Ok(general_purpose::STANDARD.encode(combined))
}

fn combine_offline_key(rsa_part: &str, aes_part: &str) -> String {
    format!("{rsa_part}{OFFLINE_KEY_SEPARATOR}{aes_part}")
}

fn build_invalid_result(
    reason: String,
    expires_at: Option<String>,
    payload: Option<OfflineLicensePayload>,
) -> OfflineKeyValidationResult {
    OfflineKeyValidationResult {
        is_valid: false,
        reason: Some(reason),
        expires_at,
        payload,
    }
}

fn log_validation_success(payload: &OfflineLicensePayload) {
    println!(
        "离线密钥验证成功: 用户 {} ({}) 设备 {} 过期时间 {}",
        payload.user_id, payload.username, payload.device_id, payload.expires_at
    );
}

/// Tauri 命令：验证离线密钥
#[tauri::command]
pub async fn validate_offline_key() -> OfflineKeyValidationResult {
    let lock = Arc::new(Mutex::new(()));
    validate_from_env(&lock).await
}

/// Tauri 命令：获取设备 ID
#[tauri::command]
pub fn get_device_id() -> Result<String, String> {
    device::get_device_id().map_err(|e| e.to_string())
}
