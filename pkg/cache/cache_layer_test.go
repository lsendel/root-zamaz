package cache

import (
	"context"
	"testing"
	"time"
)

func TestCacheLayer_InMemoryOnly(t *testing.T) {
	cl, err := NewCacheLayer(nil, CacheConfig{TTL: time.Minute})
	if err != nil {
		t.Fatalf("failed to create cache layer: %v", err)
	}

	ctx := context.Background()
	key := "foo"
	val := []byte("bar")

	if err := cl.Set(ctx, key, val); err != nil {
		t.Fatalf("set error: %v", err)
	}

	got, err := cl.Get(ctx, key)
	if err != nil {
		t.Fatalf("get error: %v", err)
	}

	if string(got) != string(val) {
		t.Fatalf("expected %s, got %s", val, got)
	}

	if err := cl.Delete(ctx, key); err != nil {
		t.Fatalf("delete error: %v", err)
	}

	if _, err := cl.Get(ctx, key); err == nil {
		t.Fatalf("expected error after delete")
	}
}
