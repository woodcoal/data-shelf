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
	dir := flag.String("dir", defaultDir, "data root directory")
	host := flag.String("host", "127.0.0.1", "listen host")
	port := flag.Int("port", 9090, "listen port")
	title := flag.String("title", "DataShelf", "site title")
	flag.Parse()
	if *port < 1 || *port > 65535 {
		return errors.New("port must be between 1 and 65535")
	}
	logger := log.New(os.Stdout, "", log.LstdFlags)
	handler, err := newServer(*dir, *title, logger)
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
