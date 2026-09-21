package middleware

import (
	"net/http"

	"gologin/internal/httpx"
	"gologin/internal/ratelimit"
)

func RateLimitByIP(limiter *ratelimit.Keyed) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !limiter.Allow("ip:" + httpx.ClientIP(r)) {
				httpx.WriteError(w, http.StatusTooManyRequests, "too_many_requests", "quá nhiều yêu cầu, thử lại sau")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
