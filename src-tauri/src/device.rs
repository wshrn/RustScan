use anyhow::{anyhow, Result};
use get_if_addrs::{get_if_addrs, IfAddr};
use machine_uid::get as get_machine_uid;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DeviceInfo {
    pub device_id: String,
    pub device_name: String,
    pub os: String,
    pub arch: String,
    pub hostname: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

pub fn get_device_id() -> Result<String> {
    generate_device_id()
}

fn generate_device_id() -> Result<String> {
    if let Ok(machine_id) = get_machine_uid() {
        let hashed = hash_identifier(machine_id.as_bytes());
        if let Some(id) = hashed {
            return Ok(id);
        }
    }

    let mut hasher = Sha256::new();

    if let Ok(hostname) = hostname::get() {
        hasher.update(hostname.to_string_lossy().as_bytes());
    }

    if let Ok(interfaces) = get_if_addrs() {
        for interface in interfaces {
            match interface.addr {
                IfAddr::V4(ifv4) => {
                    hasher.update(ifv4.ip.octets());
                    hasher.update(ifv4.netmask.octets());
                    if let Some(broadcast) = ifv4.broadcast {
                        hasher.update(broadcast.octets());
                    }
                }
                IfAddr::V6(ifv6) => {
                    hasher.update(ifv6.ip.octets());
                    hasher.update(ifv6.netmask.octets());
                    if let Some(broadcast) = ifv6.broadcast {
                        hasher.update(broadcast.octets());
                    }
                }
            }
        }
    }

    hasher.update(std::env::consts::OS.as_bytes());
    hasher.update(std::env::consts::ARCH.as_bytes());

    let fingerprint = hasher.finalize();
    let fingerprint_hex = format!("{:x}", fingerprint);

    if let Some(id) = shorten_hex(fingerprint_hex) {
        return Ok(id);
    }

    let uuid = Uuid::new_v4();
    hash_identifier(uuid.as_bytes()).ok_or_else(|| anyhow!("无法生成设备ID"))
}

fn get_device_name() -> Result<String> {
    if let Ok(hostname) = hostname::get() {
        return Ok(hostname.to_string_lossy().to_string());
    }

    if let Ok(name) = std::env::var("COMPUTERNAME") {
        return Ok(name);
    }

    if let Ok(name) = std::env::var("HOSTNAME") {
        return Ok(name);
    }

    Ok("Unknown Device".to_string())
}

fn hash_identifier(data: &[u8]) -> Option<String> {
    if data.is_empty() {
        return None;
    }

    let mut hasher = Sha256::new();
    hasher.update(data);
    let hex = format!("{:x}", hasher.finalize());
    shorten_hex(hex)
}

fn shorten_hex(hex: String) -> Option<String> {
    if hex.is_empty() {
        return None;
    }

    let id: String = hex.chars().take(32).collect();
    if id.is_empty() {
        None
    } else {
        Some(id)
    }
}

pub fn get_device_info() -> Result<DeviceInfo> {
    let device_id = get_device_id()?;
    let device_name = get_device_name()?;
    
    Ok(DeviceInfo {
        device_id,
        device_name,
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        hostname: hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "Unknown".to_string()),
        created_at: chrono::Utc::now(),
    })
}
