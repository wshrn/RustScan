use std::fs;
use std::io::Write;
use std::path::Path;

fn main() {
    if let Err(err) = ensure_icon() {
        println!("cargo:warning=failed to prepare icon: {err}");
    }
    tauri_build::build();
}

fn ensure_icon() -> Result<(), Box<dyn std::error::Error>> {
    const ICON_URLS: &[&str] = &[
        "https://www.python.org/static/favicon.ico",
        "https://raw.githubusercontent.com/python/cpython/main/Misc/python.ico",
    ];

    let icon_dir = Path::new("icons");
    fs::create_dir_all(icon_dir)?;
    let icon_path = icon_dir.join("app-icon.ico");

    for url in ICON_URLS {
        match download_icon(url, &icon_path) {
            Ok(()) => return Ok(()),
            Err(err) => {
                println!("cargo:warning=failed to download icon from {url}: {err}");
            }
        }
    }

    Err("all icon download mirrors failed".into())
}

fn download_icon(url: &str, destination: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let response = ureq::get(url).call()?;
    let status = response.status();
    if !(200..=299).contains(&status) {
        return Err(format!("download failed with status {}", status).into());
    }
    let mut reader = response.into_reader();
    let mut buf = Vec::new();
    std::io::copy(&mut reader, &mut buf)?;
    let mut file = fs::File::create(destination)?;
    file.write_all(&buf)?;
    Ok(())
}
