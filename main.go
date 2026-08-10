package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("resolve home directory: %w", err)
	}
	defaultDir := filepath.Join(home, "Documents", "data")
	defaultTitle := "DataShelf"
	dir := flag.String("dir", "", "资料数据根目录（优先级高于配置文件）")
	host := flag.String("host", "127.0.0.1", "监听地址")
	port := flag.Int("port", 9090, "监听端口（1-65535）")
	title := flag.String("title", "", "资料架标题（优先级高于配置文件）")
	configPath := flag.String("config", "", "根级配置文件路径（默认：可执行文件同目录 datashelf.env）")
	flag.Usage = func() {
		fmt.Fprintln(flag.CommandLine.Output(), "DataShelf：只读本地资料架服务")
		fmt.Fprintln(flag.CommandLine.Output(), "\n用法：")
		fmt.Fprintln(flag.CommandLine.Output(), "  datashelf [-config 文件] [-dir 目录] [-host 地址] [-port 端口] [-title 标题]")
		fmt.Fprintln(flag.CommandLine.Output(), "\n参数：")
		flag.PrintDefaults()
		fmt.Fprintln(flag.CommandLine.Output(), "\n配置：")
		fmt.Fprintln(flag.CommandLine.Output(), "  默认读取可执行文件同目录的 datashelf.env；-config 指定的文件必须存在且是普通文件。")
		fmt.Fprintln(flag.CommandLine.Output(), "  支持 DATA_DIR、SITE_TITLE、GLOBAL_PASSWORD。-dir/-title 优先于配置，密码不提供命令行参数。")
		fmt.Fprintln(flag.CommandLine.Output(), "  GLOBAL_PASSWORD 使用 plain: 或 hash:；plain: 会迁移为 Argon2id 哈希。")
		fmt.Fprintln(flag.CommandLine.Output(), "\n目录与安全：")
		fmt.Fprintln(flag.CommandLine.Output(), "  数据根目录的每个普通一级目录是一个应用；.env 可设置该应用私有密码。")
		fmt.Fprintln(flag.CommandLine.Output(), "  公开应用会在全局密码开启时要求全局密码；私有应用始终只使用自己的密码。")
		fmt.Fprintln(flag.CommandLine.Output(), "  对局域网访问请在 HTTPS 反向代理后使用，密码和资料内容不会通过 HTTP 明文保护。")
	}
	flag.Parse()
	if *port < 1 || *port > 65535 {
		return errors.New("port must be between 1 and 65535")
	}
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve executable path: %w", err)
	}
	path := *configPath
	if path == "" {
		path = filepath.Join(filepath.Dir(executable), "datashelf.env")
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve configuration path: %w", err)
	}
	global, err := loadGlobalConfig(path, defaultDir, defaultTitle, *configPath != "")
	if err != nil {
		return err
	}
	if *dir != "" {
		global.DataDir = *dir
	}
	if *title != "" {
		global.SiteTitle = *title
	}
	logger := log.New(os.Stdout, "", log.LstdFlags)
	handler, err := newServerWithConfig(global.DataDir, global.SiteTitle, global, logger)
	if err != nil {
		return err
	}
	if !isLoopbackHost(*host) {
		logger.Printf("WARNING: LAN access has no built-in TLS; use an HTTPS reverse proxy")
	}
	address := net.JoinHostPort(*host, strconv.Itoa(*port))
	httpServer := &http.Server{
		Addr: address, Handler: requestLogger(logger, handler),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 5 * time.Minute, IdleTimeout: 60 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	logger.Printf("listening on http://%s", address)
	logger.Printf("data directory: %s", handler.root)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stop
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(ctx); err != nil {
			logger.Printf("shutdown: %v", err)
		}
	}()
	err = httpServer.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	if r.status != 0 {
		return
	}
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (r *statusRecorder) Write(data []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.ResponseWriter.Write(data)
}

func requestLogger(logger *log.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recorder := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(recorder, r)
		status := recorder.status
		if status == 0 {
			status = http.StatusOK
		}
		logger.Printf("%s %s %d", r.Method, r.URL.EscapedPath(), status)
	})
}
