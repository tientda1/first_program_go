package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"gologin/internal/config"
	"gologin/internal/db"
	"gologin/internal/handler"
	"gologin/internal/middleware"
	"gologin/internal/ratelimit"
	"gologin/internal/repository"
	"gologin/internal/service"
)

func main() {
	if err := run(); err != nil {
		slog.Error("server stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg := config.Load()

	pool, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()

	userRepo := repository.NewUserRepository(pool)
	sessionRepo := repository.NewSessionRepository(pool)

	authSvc, err := service.NewAuthService(cfg, userRepo, sessionRepo)
	if err != nil {
		return err
	}

	ipLimiter := ratelimit.New(cfg.RateLimitPerMin, cfg.RateLimitBurst, 10*time.Minute)
	userLimiter := ratelimit.New(cfg.RateLimitPerMin, cfg.RateLimitBurst, 10*time.Minute)
	ipLimiter.StartJanitor(ctx, 5*time.Minute)
	userLimiter.StartJanitor(ctx, 5*time.Minute)

	authHandler := handler.NewAuthHandler(authSvc, userLimiter, false)
	requireAuth := middleware.RequireAuth(authSvc.Authenticate)

	mux := http.NewServeMux()
	mux.Handle("POST /api/login", middleware.RateLimitByIP(ipLimiter)(http.HandlerFunc(authHandler.Login)))
	mux.Handle("POST /api/logout", requireAuth(http.HandlerFunc(authHandler.Logout)))
	mux.Handle("GET /api/me", requireAuth(http.HandlerFunc(authHandler.Me)))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go cleanupExpiredSessions(ctx, authSvc)

	errCh := make(chan error, 1)
	go func() {
		slog.Info("server listening", "addr", cfg.Addr, "bcrypt_cost", cfg.BcryptCost)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		slog.Info("shutdown signal received")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	return srv.Shutdown(shutdownCtx)
}

func cleanupExpiredSessions(ctx context.Context, svc *service.AuthService) {
	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			n, err := svc.DeleteExpiredSessions(ctx)
			if err != nil {
				slog.Error("cleanup expired sessions failed", "error", err)
				continue
			}
			if n > 0 {
				slog.Info("deleted expired sessions", "count", n)
			}
		}
	}
}
