package config

import (
	"testing"
)

func TestConfig(t *testing.T) {
	cfg, err := New()
	if err != nil {
		t.Fatalf("exp nil err; got %v", err)
	}
	if cfg == nil {
		t.Fatal("exp non-nil value")
	}
}
