package auth

import (
	"context"
	"testing"

	"github.com/vaultvision/go-auth-example/pkg/config"
)

func TestAuth(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg, err := config.New()
	if err != nil {
		t.Fatalf("exp nil err; got %v", err)
	}
	if cfg == nil {
		t.Fatal("exp non-nil value")
	}

	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("exp nil err; got %v", err)
	}
	if mgr == nil {
		t.Fatal("exp non-nil value")
	}

	pr, err := mgr.Load(ctx)
	if err != nil {
		t.Fatalf("exp nil err; got %v", err)
	}
	if pr == nil {
		t.Fatal("exp non-nil value")
	}
}
