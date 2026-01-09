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
	SMSRUAPIID  string
	SMSSender   string
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
		SMSRUAPIID:  os.Getenv("SMS_RU_API_ID"),
		SMSSender:   os.Getenv("SMS_SENDER"),
	}
}

func envOrDefault(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value
}
