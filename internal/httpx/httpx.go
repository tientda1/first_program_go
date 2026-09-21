package httpx

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
)

type ErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if v == nil {
		return
	}
	_ = json.NewEncoder(w).Encode(v)
}

func WriteError(w http.ResponseWriter, status int, code, message string) {
	WriteJSON(w, status, ErrorBody{Code: code, Message: message})
}

// ClientIP chỉ tin RemoteAddr. X-Forwarded-For do client tự gửi nên nếu tin
// tuyệt đối, kẻ tấn công chỉ cần đổi header là vượt được rate limit.
// Muốn dùng XFF thì phải chỉ định rõ IP của reverse proxy tin cậy.
func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func BearerToken(r *http.Request) string {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if len(h) > len(prefix) && strings.EqualFold(h[:len(prefix)], prefix) {
		return strings.TrimSpace(h[len(prefix):])
	}
	if c, err := r.Cookie("session"); err == nil {
		return c.Value
	}
	return ""
}
