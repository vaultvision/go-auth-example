package main

import (
	"context"
	"log"
	"net/http"
	"net/url"
	"os"

	"github.com/vaultvision/go-auth-example/pkg/config"
	"github.com/vaultvision/go-auth-example/pkg/handler"
)

func main() {
	if err := Run(context.Background(), os.Args...); err != nil {
		log.Fatal(err)
	}
	os.Exit(0)
}

func Run(ctx context.Context, args ...string) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	cfg, err := config.New()
	if err != nil {
		return err
	}
	log.Printf("config BASE_URL=%q", cfg.BaseURL)
	log.Printf("config STATIC_DIR=%q", cfg.StaticDir)
	log.Printf("config SESSION_SECRET.is_set=%v", cfg.SessionSecret != "")
	log.Printf("config VV_ISSUER_URL=%q", cfg.VVIssuerURL)
	log.Printf("config VV_CLIENT_ID=%q", cfg.VVClientID)
	log.Printf("config VV_CLIENT_SECRET.is_set=%v", cfg.VVClientSecret != "")

	hr, err := handler.New(ctx, cfg)
	if err != nil {
		return err
	}

	baseURL, err := url.Parse(cfg.BaseURL)
	if err != nil {
		return err
	}

	httpSrv := &http.Server{
		Addr:    baseURL.Host,
		Handler: hr,
	}
	if err != nil {
		return err
	}

	log.Printf("HTTP Server running at %v", baseURL)
	return httpSrv.ListenAndServe()
}
