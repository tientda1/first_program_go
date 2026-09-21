package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	Addr             string
	DatabaseURL      string
	BcryptCost       int
	SessionTTL       time.Duration
	MaxLoginAttempts int
	LockDuration     time.Duration
	RateLimitPerMin  int
	RateLimitBurst   int
}

func Load() Config {
	return Config{
		Addr:             env("ADDR", ":8080"),
		DatabaseURL:      env("DATABASE_URL", "postgres://postgres:postgres@localhost:5432/gologin?sslmode=disable"),
		BcryptCost:       envInt("BCRYPT_COST", 12),
		SessionTTL:       time.Duration(envInt("SESSION_TTL_HOURS", 24)) * time.Hour,
		MaxLoginAttempts: envInt("MAX_LOGIN_ATTEMPTS", 5),
		LockDuration:     time.Duration(envInt("LOCK_MINUTES", 15)) * time.Minute,
		RateLimitPerMin:  envInt("RATE_LIMIT_PER_MIN", 10),
		RateLimitBurst:   envInt("RATE_LIMIT_BURST", 5),
	}
}

func env(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) int {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}
