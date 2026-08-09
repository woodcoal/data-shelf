# DataShelf

DataShelf 是一个只读的本地资料架服务。数据根目录下的每个第一层普通目录会成为一个独立应用，可公开访问，也可通过该目录中的私有 `.env` 设置应用名称、说明和密码。

## 启动

需要 Go 1.25 或更高版本：

```bash
go run . -dir /path/to/data
```

默认监听 `127.0.0.1:9090`。可用参数：

- `-dir`：数据根目录；默认是用户文档目录下的 `data`。
- `-host`：监听地址；默认 `127.0.0.1`。非 loopback 地址会输出无 TLS 风险警告。
- `-port`：监听端口；默认 `9090`。
- `-title`：首页标题；默认 `DataShelf`。

受保护应用的 `.env` 示例：

```dotenv
NAME='项目资料'
DESCRIPTION='只读资料与演示'
PASSWORD='plain:首次设置的密码'
```

合法的 `plain:` 密码会在启动扫描时迁移为版本化 Argon2id 哈希。`.env`、`app.json`、隐藏文件、链接和非常规文件不会通过 HTTP 提供。

## 内嵌界面

首页、目录列表、密码页和空状态模板位于 `web/pages.tmpl`，在构建时通过 `go:embed` 编译进二进制，因此运行时无需部署静态资源。模板接收的文件名、应用名称和描述均由 Go 的 `html/template` 自动转义；路径仍由服务端按 URL 路径段编码和校验。未知格式保持附件下载，预留的 `preview-unavailable` 模板供后续显式预览路由使用。

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
