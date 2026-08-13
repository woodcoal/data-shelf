# DataShelf

DataShelf 是一个让本地资料可被远程安全访问与分享的只读资料架服务。管理员指定数据根目录并运行服务后，根目录下每个第一层普通目录都会成为一个可在浏览器打开的独立资料应用，规范访问地址为 `/<应用目录名>/`。

它适合将仍由本地磁盘管理的资料通过受控地址提供给远程浏览器查看：目录和文件可沿用已有的密码边界与分享机制对外开放；只读、按应用隔离的密码和受控 HTML 渲染是这一使用方式的安全约束，而非产品目的本身。

## 第一个示例：保留 Agent 生成的 HTML

将 Agent 生成的自包含 HTML 当作普通资料放进一个一级应用目录。例如，Agent 已生成 `report.html` 后：

```bash
mkdir -p ./data/agent-result
cp /path/to/report.html ./data/agent-result/
go run . -dir ./data
```

然后在浏览器打开 `http://127.0.0.1:9090/agent-result/`，点击 `report.html` 即可在 DataShelf 的受控 HTML 视图中查看；需要时也可使用该应用已有的分享能力。这个地址由 DataShelf 和资料目录提供，不依赖 Agent 为本次生成临时启动的服务继续运行。

这不是永久可用性承诺：机器可访问、DataShelf 进程仍在运行且 HTML 文件未被删除时，链接才可使用。若要让受控外部访问通过 HTTPS 进入本机 loopback 服务，请按[自管 HTTPS 反向代理指南](docs/RELEASE.md#自管-https-反向代理)部署；域名、证书、代理和公网暴露均由部署者负责。

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
password='首次设置的全局密码'
html_scripts='allow' # 可选；allow 为默认值，deny 会禁止 HTML 脚本
```

数据根优先级为显式 `-dir` > 启动目录；标题优先级为 `-title` > 根 `.env` 的 `title` > `DataShelf`。标题与说明只作用于其所在目录；密码按最近有效祖先继承，子目录有效密码创建新的授权边界。空密码、重复/未知字段、大小写近似、链接、超限或读取错误都会锁定对应子树，绝不回退为公开。根与应用根仍提供一次 `NAME`/`DESCRIPTION`/`PASSWORD` 的迁移兼容；嵌套目录只接受小写字段。

旧版 `datashelf.env`（包含 `DATA_DIR`、`SITE_TITLE`、`GLOBAL_PASSWORD`）不再加载。为避免旧密码被静默忽略，启动目录或可执行文件目录发现该文件时服务会拒绝启动；请将 `SITE_TITLE` 迁移为根 `.env` 的 `title`，将 `GLOBAL_PASSWORD` 迁移为 `password`，可增加 `description`，并移除旧文件。数据根不再从配置文件设置。

受保护应用的 `.env` 示例：

```dotenv
title='项目资料'
description='只读资料与演示'
password='首次设置的密码'
```

无前缀的首次密码会原子迁移为版本化 Argon2id `hash:`；`plain:` 只作为一周期兼容输入。`html_scripts` 与密码一样向下继承，子目录的显式值覆盖父目录。所有 `.env`、`app.json`、隐藏文件、链接和非常规文件都会统一返回 404；配置变化会在下一请求使受影响的授权失效。

`/a/<应用名>/...` 是旧版地址，只对 GET/HEAD 安全地 308 重定向到规范地址；升级后旧 Cookie 不迁移，受保护应用需要重新登录。`a` 和 `_` 开头的一级目录为保留命名空间，不会作为应用公开。

## 内嵌界面

首页、目录列表、密码页和空状态模板位于 `web/pages.tmpl`，交互脚本与样式分别位于 `web/assets/app.js`、`web/assets/app.css`；三者都在构建时通过 `go:embed` 编译进二进制，因此运行时无需部署静态资源。页面以带内容指纹的资源 URL 引用 JS/CSS，静态资源使用一年 immutable 缓存，页面仍为 `no-cache` 或受保护的 `private, no-store`。模板接收的文件名、应用名称和描述均由 Go 的 `html/template` 自动转义；路径仍由服务端按 URL 路径段编码和校验。

后端为模板提供受控预览契约：`PreviewKind` 为 `none`、`image`、`pdf`、`text` 或 `markdown`，`OpenKind` 为 `directory`、`file`、`html-render` 或 `download`。URL、缩放、图片前后邻项和分享可用状态都由服务端生成；客户端不得按扩展名、DOM 或路径自行推断。分享状态只包含可用性、是否需要密码、过期时间和下载许可，绝不包含令牌、密码、哈希、管理 ID 或文件路径。

受控资源位于应用前缀内：`/<应用>/_preview/<路径>`、`/<应用>/_download/<路径>`、`/<应用>/_html/<路径>` 和 `/<应用>/_html-content/<路径>`。一次登录会为应用页及受控资源签发同一应用专用、`HttpOnly` 的路径限定会话 Cookie；不会使用站点根路径 Cookie，也不能授权其他应用。旧版顶级 `/_preview/<应用>/` 和 `/_download/<应用>/` 仅作不读取文件的 308 兼容重定向。

目录即使含有 `index.html` 也始终显示目录列表；只有点击 `.html`/`.htm` 文件名才进入受控 HTML 外壳。默认 `html_scripts='allow'` 时，原始内容可在隔离 iframe 中执行脚本，但绝不授予 `allow-same-origin`；设置为 `deny` 会完全禁用脚本。预览操作始终读取固定 `text/plain` 源码，直接文件路由不会裸露同源可执行 HTML。

`.md`/`.markdown` 仅在普通文件且不超过 1 MiB 时作为 Markdown 候选。服务端使用 Goldmark 渲染，禁用原始 HTML 和图片嵌入，移除脚本协议与危险链接；同应用相对链接会重写为受控规范 URL，外部 HTTP(S) 链接使用 `noopener noreferrer`。Markdown 预览是带严格 CSP 的完整沙箱文档，受保护响应保持 `private, no-store`。SVG、Office、压缩包和未知二进制仅可下载。

## 构建与测试

```bash
go test ./...
CGO_ENABLED=0 go build -trimpath -o datashelf .
```

如需从其他设备或远程浏览器访问，请显式设置合适的 `-host`，并在生产环境前置 HTTPS 反向代理。非 loopback 监听会输出无 TLS 风险警告；请只通过受控网络地址暴露服务。

跨平台构建、校验、systemd/launchd/Windows 常驻运行和卸载说明见
[`docs/RELEASE.md`](docs/RELEASE.md)。运行 `./scripts/build-release.sh` 会在
`dist/` 生成 Linux amd64、macOS amd64、macOS arm64 和 Windows amd64 四个
`datashelf-v1.26.813-*` 产物及 `SHA256SUMS-v1.26.813`。

每次请求都会重新发现第一层应用目录；根目录不可读取时返回 503，而不会回退到陈旧列表。页面使用构建内嵌、内容指纹化的 `/_assets/` CSS/JS：指纹资源以一年 `immutable` 缓存和强 ETag 输出，二进制更新会生成新 URL；页面与受保护内容保持不可存储。

文件动态发现、`.env` 继承与密码迁移、HTML/分享渲染、静态资源缓存及
前后端能力边界见 [`docs/PREVIEW-CONFIG-CONTRACT.md`](docs/PREVIEW-CONFIG-CONTRACT.md)。

## 许可证

本项目采用 [MIT License](LICENSE)。
