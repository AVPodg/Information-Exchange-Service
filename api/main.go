package main

import (
	"context"
	"errors"
	"kaspersky_task/internal/config"
	"kaspersky_task/internal/handler"
	"kaspersky_task/internal/service"
	"kaspersky_task/internal/storage/postgres"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("load config error", "error", err)
		os.Exit(1)
	}

	var logLevel slog.Level

	switch cfg.Log.Level {
	case "info":
		logLevel = slog.LevelInfo
	case "warn":
		logLevel = slog.LevelWarn
	case "debug":
		logLevel = slog.LevelDebug
	case "error":
		logLevel = slog.LevelError
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel,
	}))
	slog.SetDefault(logger)

	ctx := context.Background()

	pgConfig, err := pgxpool.ParseConfig(cfg.Database.URL)
	if err != nil {
		slog.Error("config to postgres", "error", err)
		os.Exit(1)
	}

	pgConfig.MaxConns = cfg.Database.MaxConns
	pgConfig.MinConns = cfg.Database.MinConns

	pool, err := pgxpool.NewWithConfig(ctx, pgConfig)
	if err != nil {
		slog.Error("connect to postgres", "error", err)
		os.Exit(1)
	}

	defer pool.Close()

	if err = pool.Ping(ctx); err != nil {
		slog.Error("ping postgres", "error", err)
		os.Exit(1)
	}

	repository := postgres.NewRepository(pool)
	service := service.NewService(repository)
	handler := handler.NewHandler(service, cfg.HTTP.Timeout)

	mux := http.NewServeMux()

	mux.HandleFunc("GET /info/{md5}", handler.GetInfoByMD5)
	mux.HandleFunc("PUT /info/{md5}", handler.UpdateThreatApi)
	mux.HandleFunc("POST /info", handler.PostThreatApi)

	SignalCtx, stop := signal.NotifyContext(ctx, syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	quit := make(chan interface{}, 1)

	server := &http.Server{
		Addr:              ":" + cfg.HTTP.Port,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("http server error", "error", err)
			quit <- err
		}
	}()

	select {
	case <-SignalCtx.Done():
	case <-quit:
		os.Exit(1)
	}

	shutCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	if err := server.Shutdown(shutCtx); err != nil {
		slog.Error("graceful shutdown failed", "error", err)

		if err := server.Close(); err != nil {
			slog.Error("server close error", "error", err)
		}
	}
}
