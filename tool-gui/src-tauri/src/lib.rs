mod config;
mod device;
mod offline_key;
mod python_env;
mod storage;

use config::FileWriteLock;
use tauri::Manager;
use std::process;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(FileWriteLock::default())
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            offline_key::validate_offline_key,
            offline_key::get_device_id,
            python_env::get_python_environment_status,
            python_env::initialize_python_environment,
            config::tool_read_theme,
            config::save_config,
            config::sync_theme_env
        ])
        .setup(|app| {
            let handle = app.handle();
            config::ensure_config_dir(&handle)?;

            let lock_state: tauri::State<'_, FileWriteLock> = app.state();
            let lock = lock_state.0.clone();
            drop(lock_state);

            let validation = tauri::async_runtime::block_on(async {
                offline_key::validate_from_env(&lock).await
            });

            if !validation.is_valid {
                let reason = validation
                    .reason
                    .unwrap_or_else(|| String::from("离线密钥认证失败"));
                eprintln!("离线密钥认证失败：{reason}");
                process::exit(1);
            }
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running application");
}
