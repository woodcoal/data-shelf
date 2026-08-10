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
	startupDir, err := filepath.Abs(".")
	if err != nil {
		return fmt.Errorf("resolve startup directory: %w", err)
	}
	defaultTitle := "DataShelf"
	dir := flag.String("dir", "", "资料数据根目录（默认：启动目录；相对路径相对启动目录）")
	host := flag.String("host", "127.0.0.1", "监听地址")
	port := flag.Int("port", 9090, "监听端口（1-65535）")
	title := flag.String("title", "", "资料架标题（优先级高于根 .env 的 NAME）")
	flag.Usage = func() {
		fmt.Fprintln(flag.CommandLine.Output(), "DataShelf：只读本地资料架服务")
		fmt.Fprintln(flag.CommandLine.Output(), "\n用法：")
		fmt.Fprintln(flag.CommandLine.Output(), "  datashelf [-dir 目录] [-host 地址] [-port 端口] [-title 标题]")
		fmt.Fprintln(flag.CommandLine.Output(), "\n参数：")
		flag.PrintDefaults()
		fmt.Fprintln(flag.CommandLine.Output(), "\n配置：")
		fmt.Fprintln(flag.CommandLine.Output(), "  数据根目录为显式 -dir 或启动目录；根 .env 固定在 <数据根>/.env，仅支持 NAME、DESCRIPTION、PASSWORD。")
		fmt.Fprintln(flag.CommandLine.Output(), "  -title 优先于根 .env 的 NAME；密码不提供命令行参数。PASSWORD 使用 plain: 或 hash:；plain: 会迁移为 Argon2id 哈希。")
		fmt.Fprintln(flag.CommandLine.Output(), "\n目录与安全：")
		fmt.Fprintln(flag.CommandLine.Output(), "  数据根目录的每个普通一级目录是一个应用；.env 可设置该应用私有密码。")
		fmt.Fprintln(flag.CommandLine.Output(), "  公开应用会在全局密码开启时要求全局密码；私有应用始终只使用自己的密码。")
		fmt.Fprintln(flag.CommandLine.Output(), "  对局域网访问请在 HTTPS 反向代理后使用，密码和资料内容不会通过 HTTP 明文保护。")
	}
	flag.Parse()
	if *port < 1 || *port > 65535 {
		return errors.New("port must be between 1 and 65535")
	}
	dataRoot, err := resolveDataRoot(startupDir, *dir)
	if err != nil {
		return err
	}
	if err := rejectLegacyConfig(startupDir); err != nil {
		return err
	}
	global, err := loadRootConfig(dataRoot, defaultTitle)
	if err != nil {
		return err
	}
	if *title != "" {
		global.SiteTitle = *title
	}
	logger := log.New(os.Stdout, "", log.LstdFlags)
	handler, err := newServerWithConfig(dataRoot, global.SiteTitle, global, logger)
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

func resolveDataRoot(startupDir, requested string) (string, error) {
	root := requested
	if root == "" {
		root = startupDir
	}
	if !filepath.IsAbs(root) {
		root = filepath.Join(startupDir, root)
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("resolve data directory: %w", err)
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("data directory must be an existing real directory")
	}
	return root, nil
}

func rejectLegacyConfig(startupDir string) error {
	dirs := map[string]struct{}{startupDir: {}}
	if executable, err := os.Executable(); err == nil {
		dirs[filepath.Dir(executable)] = struct{}{}
	}
	for dir := range dirs {
		path := filepath.Join(dir, "datashelf.env")
		if _, err := os.Lstat(path); err == nil {
			return errors.New("detected legacy datashelf.env; migrate NAME, DESCRIPTION and PASSWORD to <data-root>/.env, then remove datashelf.env")
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect legacy configuration: %w", err)
		}
	}
	return nil
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
