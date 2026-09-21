package main

import (
	"context"
	"log/slog"
	"os"

	"golang.org/x/crypto/bcrypt"

	"gologin/internal/config"
	"gologin/internal/db"
)

func main() {
	cfg := config.Load()

	ctx := context.Background()
	pool, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		slog.Error("cannot open database", "error", err)
		os.Exit(1)
	}
	defer pool.Close()

	username := env("SEED_USERNAME", "alice")
	email := env("SEED_EMAIL", "alice@example.com")
	password := env("SEED_PASSWORD", "Password123!")

	hash, err := bcrypt.GenerateFromPassword([]byte(password), cfg.BcryptCost)
	if err != nil {
		slog.Error("cannot hash password", "error", err)
		os.Exit(1)
	}

	const q = `
INSERT INTO users (username, email, password_hash)
VALUES ($1, $2, $3)
ON CONFLICT (username) DO UPDATE
SET email           = EXCLUDED.email,
    password_hash   = EXCLUDED.password_hash,
    status          = 1,
    failed_attempts = 0,
    locked_until    = NULL,
    deleted_at      = NULL,
    updated_at      = now()`

	if _, err := pool.ExecContext(ctx, q, username, email, string(hash)); err != nil {
		slog.Error("cannot seed user", "error", err)
		os.Exit(1)
	}

	slog.Info("seeded user", "username", username, "email", email, "password", password, "bcrypt_cost", cfg.BcryptCost)
}

func env(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}
