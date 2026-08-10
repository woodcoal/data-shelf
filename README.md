# DataShelf

DataShelf 是一个只读的本地资料架服务。数据根目录下每个第一层普通目录会成为一个独立应用；规范访问地址为 `/<应用目录名>/`。应用可公开访问，也可通过其私有 `.env` 设置名称、说明和密码。

## 启动

需要 Go 1.25 或更高版本：

```bash
go run . -dir /path/to/data
```

运行 `datashelf -h` 可获得完整中文帮助。默认监听 `127.0.0.1:9090`，可用参数：

- `-config`：根级配置文件。默认读取**可执行文件同目录**的 `datashelf.env`；显式指定时文件必须存在且是普通文件。
- `-dir`：数据根目录，优先于根级配置。
- `-host`：监听地址；默认 `127.0.0.1`。非 loopback 地址会输出无 TLS 风险警告。
- `-port`：监听端口；默认 `9090`。
- `-title`：首页标题，优先于根级配置。

根级配置只允许以下字段；相对 `DATA_DIR` 按配置文件所在目录解析：

```dotenv
DATA_DIR='./data'
SITE_TITLE='团队资料架'
GLOBAL_PASSWORD='plain:首次设置的全局密码'
```

配置优先级是 `-dir` / `-title` 显式参数 > `datashelf.env` > 内置默认值（`~/Documents/data`、`DataShelf`）。密码没有命令行参数，避免出现在 shell 历史或进程列表。`GLOBAL_PASSWORD` 缺失时全局密码关闭；设置后，仅原本公开的应用需要使用全局密码。带私有 `.env` 密码的应用仍只认自己的密码，损坏的私有配置也始终锁定，不能被全局密码绕过。

受保护应用的 `.env` 示例：

```dotenv
NAME='项目资料'
DESCRIPTION='只读资料与演示'
PASSWORD='plain:首次设置的密码'
```

合法的 `plain:` 密码会在启动时迁移为版本化 Argon2id 哈希。根级或应用配置中密码字段为空、重复、格式错误或迁移失败都会 fail-closed：根级配置会阻止启动，应用配置会锁定对应应用。`.env`、`app.json`、隐藏文件、链接和非常规文件不会通过 HTTP 提供。

`/a/<应用名>/...` 是旧版地址，只对 GET/HEAD 安全地 308 重定向到规范地址；升级后旧 Cookie 不迁移，受保护应用需要重新登录。`a` 和 `_` 开头的一级目录为保留命名空间，不会作为应用公开。

## 内嵌界面

首页、目录列表、密码页和空状态模板位于 `web/pages.tmpl`，在构建时通过 `go:embed` 编译进二进制，因此运行时无需部署静态资源。模板接收的文件名、应用名称和描述均由 Go 的 `html/template` 自动转义；路径仍由服务端按 URL 路径段编码和校验。

后端为模板提供受控预览契约：`PreviewKind` 为 `none`、`image`、`pdf` 或 `text`，`OpenMode` 为 `navigate`、`modal`、`external` 或 `download`，并提供仅允许安全格式的 `PreviewURL`。图片、PDF 和不超过 2 MiB 的文本类文件可使用该受控端点；HTML、JS、CSS 仅按纯文本交付，SVG 和未知二进制始终下载。预览端点与原文件访问使用同一认证检查，受保护响应不缓存。

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
