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

## 构建与测试

```bash
go test ./...
CGO_ENABLED=0 go build -trimpath -o datashelf .
```

如需局域网访问，请显式设置 `-host 0.0.0.0`，并在生产环境前置 HTTPS 反向代理。
