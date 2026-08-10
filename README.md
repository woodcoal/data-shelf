# DataShelf

DataShelf 是一个只读的本地资料架服务。数据根目录下每个第一层普通目录会成为一个独立应用；规范访问地址为 `/<应用目录名>/`。应用可公开访问，也可通过其私有 `.env` 设置名称、说明和密码。

## 启动

需要 Go 1.25 或更高版本：

```bash
# 默认将当前启动目录作为资料根
go run .

# 也可显式指定资料根；相对路径相对启动目录解析
go run . -dir /path/to/data
```

运行 `datashelf -h` 可获得完整中文帮助。默认监听 `127.0.0.1:9090`，可用参数：

- `-dir`：数据根目录。未给出时使用启动目录；相对路径相对启动目录解析。
- `-host`：监听地址；默认 `127.0.0.1`。非 loopback 地址会输出无 TLS 风险警告。
- `-port`：监听端口；默认 `9090`。
- `-title`：首页标题，优先于根 `.env` 的 `NAME`。

根配置固定为 `<数据根>/.env`，仅在启动时读取一次。它与子应用 `.env` 使用同一语法：UTF-8、最大 64 KiB、允许空行/注释，且只允许以下字段：

```dotenv
NAME='团队资料架'
DESCRIPTION='团队共享的只读资料'
PASSWORD='plain:首次设置的全局密码'
```

数据根优先级为显式 `-dir` > 启动目录；标题优先级为 `-title` > 根 `.env` 的 `NAME` > `DataShelf`。密码没有命令行参数，避免出现在 shell 历史或进程列表。根 `PASSWORD` 缺失时全局密码关闭；设置后，仅原本公开的应用需要使用根密码。带私有 `.env` 密码的应用仍只认自己的密码，损坏的私有配置也始终锁定，不能被根密码绕过。

旧版 `datashelf.env`（包含 `DATA_DIR`、`SITE_TITLE`、`GLOBAL_PASSWORD`）不再加载。为避免旧密码被静默忽略，启动目录或可执行文件目录发现该文件时服务会拒绝启动；请将 `SITE_TITLE` 迁移为根 `.env` 的 `NAME`，将 `GLOBAL_PASSWORD` 迁移为 `PASSWORD`，可增加 `DESCRIPTION`，并移除旧文件。数据根不再从配置文件设置。

受保护应用的 `.env` 示例：

```dotenv
NAME='项目资料'
DESCRIPTION='只读资料与演示'
PASSWORD='plain:首次设置的密码'
```

合法的 `plain:` 密码会在启动时迁移为版本化 Argon2id 哈希。根级或应用配置中密码字段为空、重复、未知字段、格式错误或迁移失败都会 fail-closed：根级配置会阻止启动，应用配置会锁定对应应用。根 `.env`、子 `.env`、`app.json`、隐藏文件、链接和非常规文件不会通过 HTTP 提供。

`/a/<应用名>/...` 是旧版地址，只对 GET/HEAD 安全地 308 重定向到规范地址；升级后旧 Cookie 不迁移，受保护应用需要重新登录。`a` 和 `_` 开头的一级目录为保留命名空间，不会作为应用公开。

## 内嵌界面

首页、目录列表、密码页和空状态模板位于 `web/pages.tmpl`，在构建时通过 `go:embed` 编译进二进制，因此运行时无需部署静态资源。模板接收的文件名、应用名称和描述均由 Go 的 `html/template` 自动转义；路径仍由服务端按 URL 路径段编码和校验。

后端为模板提供受控预览契约：`PreviewKind` 为 `none`、`image`、`pdf`、`text` 或 `markdown`，并提供服务端生成的 `PreviewURL`、`OpenURL`、`DownloadURL` 和图片专用的 `CanZoom`。`/_preview` 与 `/_download` 均先完成应用认证，再解析文件、MIME、Range 或条件请求；下载始终使用安全的 `Content-Disposition: attachment`。

一次登录会为应用页、`/_preview/<应用>/` 与 `/_download/<应用>/` 分别签发同一应用专用、`HttpOnly` 的路径限定会话 Cookie；不会使用站点根路径 Cookie，也不能授权其他应用。

`.md`/`.markdown` 仅在普通文件且不超过 1 MiB 时作为 Markdown 候选。服务端使用 Goldmark 渲染，禁用原始 HTML 和图片嵌入，移除脚本协议与危险链接；同应用相对链接会重写为受控规范 URL，外部 HTTP(S) 链接使用 `noopener noreferrer`。Markdown 预览是带严格 CSP 的完整沙箱文档，受保护响应保持 `private, no-store`。SVG、Office、压缩包和未知二进制仅可下载。

## 构建与测试

```bash
go test ./...
CGO_ENABLED=0 go build -trimpath -o datashelf .
```

如需局域网访问，请显式设置 `-host 0.0.0.0`，并在生产环境前置 HTTPS 反向代理。

跨平台构建、校验、systemd/launchd/Windows 常驻运行和卸载说明见
[`docs/RELEASE.md`](docs/RELEASE.md)。运行 `./scripts/build-release.sh` 会在
`dist/` 生成 Linux amd64、macOS amd64、macOS arm64 和 Windows amd64 四个
`datashelf-*` 产物及 `SHA256SUMS`。
