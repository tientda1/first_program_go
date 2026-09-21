package ratelimit

import (
	"context"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type entry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

type Keyed struct {
	mu      sync.Mutex
	buckets map[string]*entry
	limit   rate.Limit
	burst   int
	ttl     time.Duration
}

func New(perMinute, burst int, ttl time.Duration) *Keyed {
	var l rate.Limit
	if perMinute > 0 {
		l = rate.Limit(float64(perMinute) / 60.0)
	}
	return &Keyed{
		buckets: make(map[string]*entry),
		limit:   l,
		burst:   burst,
		ttl:     ttl,
	}
}

func (k *Keyed) Allow(key string) bool {
	k.mu.Lock()
	e, ok := k.buckets[key]
	if !ok {
		e = &entry{limiter: rate.NewLimiter(k.limit, k.burst)}
		k.buckets[key] = e
	}
	e.lastSeen = time.Now()
	k.mu.Unlock()

	return e.limiter.Allow()
}

func (k *Keyed) Cleanup() {
	cutoff := time.Now().Add(-k.ttl)

	k.mu.Lock()
	defer k.mu.Unlock()

	for key, e := range k.buckets {
		if e.lastSeen.Before(cutoff) {
			delete(k.buckets, key)
		}
	}
}

func (k *Keyed) StartJanitor(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				k.Cleanup()
			}
		}
	}()
}
