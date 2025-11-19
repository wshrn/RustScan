use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusLine {
    pub ok: bool,
    pub message: String,
    #[serde(default)]
    pub detail: Option<String>,
    #[serde(default)]
    pub current_mirror: Option<String>,
}

impl StatusLine {
    fn ok(message: impl Into<String>) -> Self {
        Self {
            ok: true,
            message: message.into(),
            detail: None,
            current_mirror: None,
        }
    }

    fn error(message: impl Into<String>, detail: impl Into<Option<String>>) -> Self {
        Self {
            ok: false,
            message: message.into(),
            detail: detail.into(),
            current_mirror: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MirrorCandidate {
    pub label: String,
    pub value: String,
    #[serde(default)]
    pub trusted_hosts: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PythonEnvStatus {
    pub python_present: StatusLine,
    pub python_env_var: StatusLine,
    pub path_configured: StatusLine,
    pub scripts_configured: StatusLine,
    pub pip_mirror_configured: StatusLine,
    pub python_path: Option<String>,
    pub scripts_path: Option<String>,
    pub mirror_candidates: Vec<MirrorCandidate>,
}

#[tauri::command]
pub async fn get_python_environment_status() -> Result<PythonEnvStatus, String> {
    Ok(mock_status())
}

#[tauri::command]
pub async fn initialize_python_environment(
    payload: HashMap<String, String>,
) -> Result<PythonEnvStatus, String> {
    let mut status = mock_status();
    if let Some(mirror) = payload.get("mirror") {
        status.pip_mirror_configured = StatusLine {
            ok: true,
            message: format!("镜像已切换到 {mirror}"),
            detail: None,
            current_mirror: Some(mirror.clone()),
        };
    }
    Ok(status)
}

fn mock_status() -> PythonEnvStatus {
    PythonEnvStatus {
        python_present: StatusLine::ok("Python 3.11 已安装"),
        python_env_var: StatusLine::ok("PYTHONHOME 已配置"),
        path_configured: StatusLine::ok("运行时目录已写入 PATH"),
        scripts_configured: StatusLine::ok("Scripts 目录已写入 PATH"),
        pip_mirror_configured: StatusLine {
            ok: true,
            message: String::from("已启用国内镜像"),
            detail: None,
            current_mirror: Some(String::from("https://pypi.tuna.tsinghua.edu.cn/simple")),
        },
        python_path: Some(String::from("C:/Python311/python.exe")),
        scripts_path: Some(String::from("C:/Python311/Scripts")),
        mirror_candidates: vec![
            MirrorCandidate {
                label: String::from("清华大学 TUNA"),
                value: String::from("https://pypi.tuna.tsinghua.edu.cn/simple"),
                trusted_hosts: vec![String::from("pypi.tuna.tsinghua.edu.cn")],
            },
            MirrorCandidate {
                label: String::from("中国科技大学"),
                value: String::from("https://pypi.mirrors.ustc.edu.cn/simple"),
                trusted_hosts: vec![String::from("pypi.mirrors.ustc.edu.cn")],
            },
        ],
    }
}
