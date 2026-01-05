package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	Addr        string
	DatabaseURL string
	TokenTTL    time.Duration
}

func Load() Config {
	addr := envOrDefault("PORT", "8080")
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://grape:grape@localhost:5432/grape?sslmode=disable"
	}
	ttlHours := envOrDefault("TOKEN_TTL_HOURS", "24")
	ttlParsed, err := strconv.Atoi(ttlHours)
	if err != nil || ttlParsed <= 0 {
		ttlParsed = 24
	}
	return Config{
		Addr:        ":" + addr,
		DatabaseURL: dbURL,
		TokenTTL:    time.Duration(ttlParsed) * time.Hour,
	}
}

func envOrDefault(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value
}
