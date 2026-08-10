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
- `-title`：首页标题，优先于根 `.env` 的 `title`。

数据根及任意真实子目录均可放置 `.env`。配置按请求即时校验：UTF-8、最大 64 KiB、允许空行/注释，规范字段严格为小写：

```dotenv
title='团队资料架'
description='团队共享的只读资料'
password='plain:首次设置的全局密码'
```

数据根优先级为显式 `-dir` > 启动目录；标题优先级为 `-title` > 根 `.env` 的 `title` > `DataShelf`。标题与说明只作用于其所在目录；密码按最近有效祖先继承，子目录有效密码创建新的授权边界。空密码、重复/未知字段、大小写近似、链接、超限或读取错误都会锁定对应子树，绝不回退为公开。根与应用根仍提供一次 `NAME`/`DESCRIPTION`/`PASSWORD` 的迁移兼容；嵌套目录只接受小写字段。

旧版 `datashelf.env`（包含 `DATA_DIR`、`SITE_TITLE`、`GLOBAL_PASSWORD`）不再加载。为避免旧密码被静默忽略，启动目录或可执行文件目录发现该文件时服务会拒绝启动；请将 `SITE_TITLE` 迁移为根 `.env` 的 `title`，将 `GLOBAL_PASSWORD` 迁移为 `password`，可增加 `description`，并移除旧文件。数据根不再从配置文件设置。

受保护应用的 `.env` 示例：

```dotenv
title='项目资料'
description='只读资料与演示'
password='plain:首次设置的密码'
```

合法的根 `plain:` 密码会迁移为版本化 Argon2id 哈希。所有 `.env`、`app.json`、隐藏文件、链接和非常规文件都会统一返回 404；配置变化会在下一请求使受影响的授权失效。

`/a/<应用名>/...` 是旧版地址，只对 GET/HEAD 安全地 308 重定向到规范地址；升级后旧 Cookie 不迁移，受保护应用需要重新登录。`a` 和 `_` 开头的一级目录为保留命名空间，不会作为应用公开。

## 内嵌界面

首页、目录列表、密码页和空状态模板位于 `web/pages.tmpl`，在构建时通过 `go:embed` 编译进二进制，因此运行时无需部署静态资源。模板接收的文件名、应用名称和描述均由 Go 的 `html/template` 自动转义；路径仍由服务端按 URL 路径段编码和校验。

后端为模板提供受控预览契约：`PreviewKind` 为 `none`、`image`、`pdf`、`text` 或 `markdown`，并提供服务端生成的 `PreviewURL`、`OpenURL`、`DownloadURL` 和图片专用的 `CanZoom`。规范资源路由为 `/<应用>/_preview/...`、`/<应用>/_download/...`、`/<应用>/_html/...` 和 `/<应用>/_html-content/...`；历史根级预览/下载路由仅作安全 308。HTML 文件名始终进入受控外壳，预览动作只返回 `text/plain` 源码；不可信 HTML 在无脚本、无同源、无网络的双重 sandbox 内显示。

一次登录仅签发一个应用专用、`HttpOnly`、`Path=/<应用>/` 的会话 Cookie；它不能授权其他应用或越过更近的目录密码边界。

## 单文件分享

分享默认关闭。仅目标文件的直接父目录 `.env` 能定义分享，且分享不继承：`SHARE_<ID>_ENABLED`、`SCOPE='file'`、`PATH='单个文件名'`、32 字节 Base64URL `TOKEN`、绝对 `EXPIRES_AT`、独立 `PASSWORD`、`ALLOW_DOWNLOAD`。分享 URL 为 `/_s/<token>/`；令牌不包含路径或密码，分享 Cookie 只能访问绑定文件，不能升级为目录授权。配置、目标文件或目录密码边界变化会使旧分享会话失效。

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
