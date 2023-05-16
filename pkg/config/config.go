package config

import (
	"errors"
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	BaseURL        string `json:"BASE_URL"`
	StaticDir      string `json:"STATIC_DIR"`
	SessionSecret  string `json:"SESSION_SECRET"`
	VVIssuerURL    string `json:"VV_ISSUER_URL"`
	VVClientID     string `json:"VV_CLIENT_ID"`
	VVClientSecret string `json:"VV_CLIENT_SECRET"`

	// VVRedirectURL string `json:"VV_REDIRECT_URL"`
}

func New() (*Config, error) {
	err := godotenv.Load()
	if err != nil {
		return nil, err
	}

	cfg := &Config{
		BaseURL:        os.Getenv("BASE_URL"),
		StaticDir:      os.Getenv("STATIC_DIR"),
		SessionSecret:  os.Getenv("SESSION_SECRET"),
		VVIssuerURL:    os.Getenv("VV_ISSUER_URL"),
		VVClientID:     os.Getenv("VV_CLIENT_ID"),
		VVClientSecret: os.Getenv("VV_CLIENT_SECRET"),
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = "http://localhost:8090"
	}
	if cfg.StaticDir == "" {
		cfg.StaticDir = "./static/"
	}
	if cfg.SessionSecret == "" {
		cfg.SessionSecret = "secret"
	}

	if cfg.VVIssuerURL == "" {
		return nil, errors.New("env var VV_ISSUER_URL not found")
	}
	if cfg.VVClientID == "" {
		return nil, errors.New("env var VV_CLIENT_ID not found")
	}
	if cfg.VVClientSecret == "" {
		return nil, errors.New("env var VV_CLIENT_SECRET not found")
	}
	return cfg, nil
}
