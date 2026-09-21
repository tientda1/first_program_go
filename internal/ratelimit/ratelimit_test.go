package ratelimit

import (
	"testing"
	"time"
)

func TestAllowWithinBurstThenReject(t *testing.T) {
	l := New(60, 3, time.Minute)

	for i := 1; i <= 3; i++ {
		if !l.Allow("ip:1.2.3.4") {
			t.Fatalf("request %d should be allowed within burst", i)
		}
	}
	if l.Allow("ip:1.2.3.4") {
		t.Fatal("request beyond burst should be rejected")
	}
}

func TestKeysHaveIsolatedBuckets(t *testing.T) {
	l := New(60, 1, time.Minute)

	if !l.Allow("ip:a") {
		t.Fatal("first request on key a should pass")
	}
	if l.Allow("ip:a") {
		t.Fatal("second request on key a should be limited")
	}
	if !l.Allow("ip:b") {
		t.Fatal("key b must have its own bucket")
	}
}

func TestTokensRefillOverTime(t *testing.T) {
	l := New(600, 1, time.Minute)

	if !l.Allow("k") {
		t.Fatal("first request should pass")
	}
	if l.Allow("k") {
		t.Fatal("second immediate request should be limited")
	}

	time.Sleep(150 * time.Millisecond)

	if !l.Allow("k") {
		t.Fatal("token should have refilled after waiting")
	}
}

func TestCleanupRemovesIdleBuckets(t *testing.T) {
	l := New(60, 1, time.Millisecond)

	l.Allow("stale")
	time.Sleep(10 * time.Millisecond)
	l.Cleanup()

	l.mu.Lock()
	remaining := len(l.buckets)
	l.mu.Unlock()

	if remaining != 0 {
		t.Fatalf("expected idle bucket to be removed, got %d", remaining)
	}
}
