package handler

import (
	"context"
	"testing"

	"github.com/vaultvision/go-auth-example/pkg/config"
)

func TestApp(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg, err := config.New()
	if err != nil {
		t.Fatalf("exp nil err; got %v", err)
	}
	if cfg == nil {
		t.Fatal("exp non-nil cfg")
	}
	cfg.StaticDir = "../../static"

	a, err := New(ctx, cfg)
	if err != nil {
		t.Fatalf("exp nil err; got %v", err)
	}
	if a == nil {
		t.Fatal("exp non-nil value")
	}
}
