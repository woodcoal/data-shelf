## 构建发布

DataShelf 是单一 Go 二进制。页面模板编译在程序内的 `pageTemplates` 常量中，发布包不需要额外模板、静态目录、DLL 或 `.so`。依赖版本由 `go.mod` 和 `go.sum` 固定，构建脚本使用 `-mod=readonly`，发现依赖漂移会直接失败。

### 从干净 checkout 构建

要求 Go 1.25 或更高版本，以及 Bash。Linux/macOS 机器可直接执行：

```bash
git clone https://github.com/woodcoal/data-shelf.git
cd data-shelf
./scripts/build-release.sh
```

脚本会依次下载并校验模块、以 `CGO_ENABLED=0` 运行测试、交叉编译并检查四个产物：

```text
dist/datashelf-linux-amd64
dist/datashelf-darwin-amd64
dist/datashelf-darwin-arm64
dist/datashelf-windows-amd64.exe
dist/SHA256SUMS
```

构建参数包含 `-trimpath`、`-buildvcs=false` 和空 Build ID，避免把本地路径、Git 状态或构建机标识写进产物。Linux 产物必须是静态 ELF；所有目标都关闭 CGO，因此不依赖第三方运行时 DLL/`.so`。macOS 仍会使用操作系统提供的系统库，这是平台本身的运行时，不需要额外安装运行库。

GitHub Actions 在每次 push/PR 上运行相同脚本并保存构建产物；推送 `v*` 标签会创建 GitHub Release：

```bash
git tag v0.1.0
git push origin v0.1.0
```

发布流程只使用 GitHub Actions 内置令牌，不把密钥或配置写入仓库。发布前可在下载端校验：

```bash
sha256sum -c SHA256SUMS
```

### 运行约定与风险

- 默认监听 `127.0.0.1:9090`，默认数据目录是 `~/Documents/data`；`-dir` 可显式指定其他目录。
- 日志写到标准输出和标准错误。直接运行时可重定向到文件；systemd、launchd 和 Windows 任务脚本分别提供系统日志或日志文件配置。
- LAN 访问必须显式设置 `-host 0.0.0.0`（或具体 LAN 地址），并同步配置防火墙。程序没有内置 TLS，暴露 LAN 时必须放在 HTTPS 反向代理后面；否则密码和资料可能被窃听。
- 默认 loopback 只适合本机访问，不应通过端口转发或公网反向代理暴露。
- `.env` 中的 `plain:` 密码只用于首次启动迁移，程序会替换为 Argon2id 哈希。不要把包含密码的 `.env`、日志或运行时配置提交到 Git。

## Linux systemd user service

以下示例假设使用 Linux amd64 产物。服务以当前用户运行，不需要 root，也不开放公网端口：

```bash
mkdir -p "$HOME/.local/bin" "$HOME/.config/systemd/user" "$HOME/Documents/data"
install -m 0755 dist/datashelf-linux-amd64 "$HOME/.local/bin/datashelf-linux-amd64"
install -m 0644 deploy/systemd/datashelf.service "$HOME/.config/systemd/user/datashelf.service"
systemctl --user daemon-reload
systemctl --user enable --now datashelf.service
systemctl --user status datashelf.service
```

查看和停止：

```bash
journalctl --user -u datashelf.service -f
systemctl --user stop datashelf.service
```

卸载服务（不会删除数据、二进制或日志）：

```bash
systemctl --user disable --now datashelf.service
rm "$HOME/.config/systemd/user/datashelf.service"
systemctl --user daemon-reload
```

若需要关机后仍由 systemd user manager 启动，可由管理员按需执行 `loginctl enable-linger <用户名>`；这会改变该用户的系统级生命周期，需明确评估后再启用。

## macOS launchd

以下示例假设 Apple Silicon；Intel Mac 将 plist 中的 `datashelf-darwin-arm64` 替换为 `datashelf-darwin-amd64`：

```bash
mkdir -p "$HOME/.local/bin" "$HOME/Library/LaunchAgents" "$HOME/Library/Logs/DataShelf" "$HOME/Documents/data"
install -m 0755 dist/datashelf-darwin-arm64 "$HOME/.local/bin/datashelf-darwin-arm64"
sed "s|__DATASHELF_HOME__|$HOME|g" \
  deploy/macos/cn.woodcoal.datashelf.plist.template \
  > "$HOME/Library/LaunchAgents/cn.woodcoal.datashelf.plist"
plutil -lint "$HOME/Library/LaunchAgents/cn.woodcoal.datashelf.plist"
launchctl bootstrap "gui/$(id -u)" "$HOME/Library/LaunchAgents/cn.woodcoal.datashelf.plist"
launchctl enable "gui/$(id -u)/cn.woodcoal.datashelf"
launchctl kickstart -k "gui/$(id -u)/cn.woodcoal.datashelf"
```

日志位于 `~/Library/Logs/DataShelf/stdout.log` 和 `stderr.log`，也可使用 `tail -f` 查看。停止并卸载：

```bash
launchctl bootout "gui/$(id -u)/cn.woodcoal.datashelf" 2>/dev/null || true
rm "$HOME/Library/LaunchAgents/cn.woodcoal.datashelf.plist"
```

## Windows 启动或后台任务

PowerShell 脚本使用系统自带的 Windows PowerShell，不需要 NSSM、DLL 或其他常驻运行时。先把 `datashelf-windows-amd64.exe` 和 `deploy/windows/datashelf-run.ps1` 放到同一个安装目录，例如 `%LOCALAPPDATA%\DataShelf`。脚本默认使用 `Documents\data`、`127.0.0.1:9090`，日志写入安装目录下的 `logs\`。

### 推荐：任务计划程序后台运行

在仓库根目录打开 PowerShell：

```powershell
$install = Join-Path $env:LOCALAPPDATA 'DataShelf'
New-Item -ItemType Directory -Force $install | Out-Null
Copy-Item .\dist\datashelf-windows-amd64.exe $install
Copy-Item .\deploy\windows\datashelf-run.ps1 $install
& .\deploy\windows\install-task.ps1 -InstallDir $install -Binary (Join-Path $install 'datashelf-windows-amd64.exe') -RunnerScript (Join-Path $install 'datashelf-run.ps1')
```

查看任务：`Get-ScheduledTask -TaskName DataShelf`。停止运行：`Stop-ScheduledTask -TaskName DataShelf`。卸载任务（不会删除数据、二进制或日志）：

```powershell
& .\deploy\windows\uninstall.ps1 -Mode Task
```

### 登录时启动

如果只需要当前用户登录后启动，可使用启动项快捷方式：

```powershell
& .\deploy\windows\install-startup.ps1 -InstallDir $install -Binary (Join-Path $install 'datashelf-windows-amd64.exe') -RunnerScript (Join-Path $install 'datashelf-run.ps1')
```

卸载快捷方式：

```powershell
& .\deploy\windows\uninstall.ps1 -Mode Startup
```

需要 LAN 访问时，在安装命令末尾显式增加 `-Lan`；这会绑定 `0.0.0.0`，必须配置 Windows 防火墙并在 HTTPS 反向代理后使用。不要直接把 `9090` 映射到公网。
