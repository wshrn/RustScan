# RustScan GUI 编译与运行指南

本文说明如何在本地成功编译和运行基于 Tauri + Vue 的图形化界面，适用于 Windows（PowerShell）和类 Unix（bash/zsh）环境。

## 1. 环境准备

1. 安装 Rust（稳定版）
   - Windows：`winget install --id Rustlang.Rustup`
   - macOS/Homebrew：`brew install rustup-init && rustup-init -y`
   - Linux：`curl https://sh.rustup.rs -sSf | sh -s -- -y`
   - 完成后执行 `rustup default stable` 与 `rustup update`

2. 安装 Node.js 18+（建议 20 LTS）和包管理器（npm/pnpm/yarn 均可）。

3. 安装 Tauri 原生依赖
   - Windows：需要 **Visual Studio Build Tools**（含 Desktop development with C++ 工作负载）和 Windows 10/11 SDK。
   - macOS：`xcode-select --install`
   - Linux：确保安装 `pkg-config`、`openssl`、`webkit2gtk` 等依赖，详见 [Tauri 官方指南](https://tauri.app/v1/guides/getting-started/prerequisites)。

4. 准备离线密钥
   - 后端会在启动时读取环境变量 `keyzhigongfile` 指向的离线授权文件路径：
     - Windows：`$env:keyzhigongfile = "C:\\secure\\offline-license.key"`
     - Unix：`export keyzhigongfile="$HOME/.config/vattool/offline-license.key"`
   - 如需覆盖界面主题，可设置 `ZHIGONG_TOOLBOX_THEME` 为 `light` / `dark` / `auto`。

## 2. 拉取依赖

在项目根目录（包含 `app` 子目录）执行：

```bash
cd app
npm install
```

> 若使用国内/企业网络，可配置 npm 镜像或离线缓存。

## 3. 启动开发模式

```bash
npm run tauri dev
```

启动日志若提示找不到 `@tauri-apps/api`，请确认依赖已安装并使用了正确的导入路径（项目已改为 `@tauri-apps/api/tauri`）。

## 4. 生成发布版

```bash
npm run tauri build
```

- Windows 可执行文件位于 `app/src-tauri/target/release/`。
- macOS/Linux 生成的包位于 `app/src-tauri/target/release/` 对应子目录。

## 5. 常见问题

- **依赖解析失败**：删除 `app/node_modules` 后重新执行 `npm install`，确保使用支持 Tauri 1.6 的 Node 版本。
- **构建缺少 SDK/工具链**：按第 1 节安装对应平台要求的系统依赖。
- **主题未生效**：确认本地存储或 `ZHIGONG_TOOLBOX_THEME` 环境变量值为 `light` / `dark` / `auto`。
- **GTK 链接冲突 (`gtk-sys` links = "gtk-3")**：避免混用 Tauri 1.x 与插件 2.x。仓库已将 `tauri-plugin-opener` 固定到 `1.x` 以匹配 `tauri = "1"`，如自行调整依赖，请确保所有 Tauri 相关 crate 的主版本一致。

完成以上步骤后，可在本地稳定运行 GUI 并进入正式构建流程。
