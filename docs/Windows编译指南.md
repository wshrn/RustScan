# Windows 编译指南

本文指导在 Windows 环境下从源码编译 RustScan。示例命令以 PowerShell 为例，CMD 用户可去掉开头的 `./`。

## 1. 准备工具链
1. 安装 [Visual Studio Build Tools](https://visualstudio.microsoft.com/downloads/) 或者桌面版 Visual Studio，勾选 **Desktop development with C++** 工作负载，确保系统具备 MSVC 编译器与 Windows SDK。
2. 安装 Rust 工具链：
   ```powershell
   winget install --id Rustlang.Rustup
   rustup default stable-x86_64-pc-windows-msvc
   ```
   如果已安装 Rust，可执行 `rustup update` 保持最新。
3. （可选）为了生成 32 位二进制，可额外安装 `i686-pc-windows-msvc` 目标：
   ```powershell
   rustup target add i686-pc-windows-msvc
   ```

## 2. 获取源码
将项目源码解压或同步到本地目录（例如 `C:\RustScan`），并进入该目录：
```powershell
Set-Location C:\RustScan
```

## 3. 编译项目
默认编译 64 位发布版：
```powershell
cargo build --release
```
生成的可执行文件位于 `target\release\rustscan.exe`。

如需调试版本，可执行：
```powershell
cargo build
```

若同时需要 32 位可执行文件，在添加目标后运行：
```powershell
cargo build --release --target i686-pc-windows-msvc
```
输出位于 `target\i686-pc-windows-msvc\release\rustscan.exe`。

## 4. 验证构建
```powershell
./target/release/rustscan.exe --version
```

若需运行自测，可使用：
```powershell
cargo test
```

## 5. 常见问题
- **链接或 SDK 缺失**：确认安装 Visual Studio C++ 工作负载，并在安装向导中勾选 "Windows 10/11 SDK"。
- **权限受限**：PowerShell 可能需要以管理员身份运行 `winget`/`rustup`。
- **网络受限**：企业环境下载依赖可能失败，可提前配置代理或离线源。
