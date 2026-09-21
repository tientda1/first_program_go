package middleware

import (
	"context"
	"net/http"

	"gologin/internal/httpx"
	"gologin/internal/model"
)

type Authenticator func(ctx context.Context, token string) (*model.User, error)

type ctxKey int

const userCtxKey ctxKey = iota

func RequireAuth(authenticate Authenticator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := httpx.BearerToken(r)
			if token == "" {
				httpx.WriteError(w, http.StatusUnauthorized, "unauthorized", "thiếu token xác thực")
				return
			}

			user, err := authenticate(r.Context(), token)
			if err != nil {
				httpx.WriteError(w, http.StatusUnauthorized, "unauthorized", "phiên không hợp lệ hoặc đã hết hạn")
				return
			}

			ctx := context.WithValue(r.Context(), userCtxKey, user)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func UserFromContext(ctx context.Context) (*model.User, bool) {
	u, ok := ctx.Value(userCtxKey).(*model.User)
	return u, ok
}
