package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"gologin/internal/httpx"
	"gologin/internal/middleware"
	"gologin/internal/model"
	"gologin/internal/ratelimit"
	"gologin/internal/service"
)

type AuthHandler struct {
	svc          *service.AuthService
	loginByUser  *ratelimit.Keyed
	secureCookie bool
}

func NewAuthHandler(svc *service.AuthService, loginByUser *ratelimit.Keyed, secureCookie bool) *AuthHandler {
	return &AuthHandler{svc: svc, loginByUser: loginByUser, secureCookie: secureCookie}
}

type loginRequest struct {
	Identifier string `json:"identifier"`
	Password   string `json:"password"`
}

type loginResponse struct {
	Token     string           `json:"token"`
	ExpiresAt time.Time        `json:"expires_at"`
	User      model.PublicUser `json:"user"`
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_body", "dữ liệu gửi lên không hợp lệ")
		return
	}

	req.Identifier = strings.TrimSpace(req.Identifier)
	if req.Identifier == "" || req.Password == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_body", "thiếu tài khoản hoặc mật khẩu")
		return
	}

	if !h.loginByUser.Allow("user:" + strings.ToLower(req.Identifier)) {
		httpx.WriteError(w, http.StatusTooManyRequests, "too_many_requests", "quá nhiều lần thử, thử lại sau")
		return
	}

	res, err := h.svc.Login(r.Context(), req.Identifier, req.Password, httpx.ClientIP(r), r.UserAgent())
	switch {
	case errors.Is(err, service.ErrAccountDeleted):
		httpx.WriteError(w, http.StatusForbidden, "account_deleted", "tài khoản đã bị xoá")
		return
	case errors.Is(err, service.ErrAccountLocked):
		httpx.WriteError(w, http.StatusLocked, "account_locked", "tài khoản đang bị khoá")
		return
	case errors.Is(err, service.ErrInvalidCredentials):
		httpx.WriteError(w, http.StatusUnauthorized, "invalid_credentials", "sai tài khoản hoặc mật khẩu")
		return
	case err != nil:
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "có lỗi xảy ra")
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    res.Token,
		Path:     "/",
		HttpOnly: true,
		Secure:   h.secureCookie,
		SameSite: http.SameSiteLaxMode,
		Expires:  res.ExpiresAt,
	})

	httpx.WriteJSON(w, http.StatusOK, loginResponse{
		Token:     res.Token,
		ExpiresAt: res.ExpiresAt,
		User:      res.User,
	})
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	if err := h.svc.Logout(r.Context(), httpx.BearerToken(r)); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "có lỗi xảy ra")
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   h.secureCookie,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})

	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	user, ok := middleware.UserFromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized, "unauthorized", "chưa xác thực")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, user.Public())
}
