use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct PythonEnvironmentStatus {
    pub ready: bool,
    pub message: String,
}

#[tauri::command]
pub async fn get_python_environment_status() -> Result<PythonEnvironmentStatus, String> {
    Ok(PythonEnvironmentStatus {
        ready: true,
        message: "Python 环境检查已跳过，前端启动后可继续集成".to_string(),
    })
}

#[tauri::command]
pub async fn initialize_python_environment() -> Result<PythonEnvironmentStatus, String> {
    get_python_environment_status().await
}
