package observability

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

const RequestIDHeader = "X-Request-ID"

type requestIDContextKey struct{}

func RequestIDFromContext(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(requestIDContextKey{}).(string)
	return id, ok
}

func RequestLogging(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := newRequestID()
		if err != nil {
			logger.Error("request_id_generation_failed")
			writeError(w, http.StatusServiceUnavailable, "service_unavailable", "service is temporarily unavailable")
			return
		}
		w.Header().Set(RequestIDHeader, id)
		r.Header.Set(RequestIDHeader, id)
		ctx := context.WithValue(r.Context(), requestIDContextKey{}, id)
		r = r.WithContext(ctx)

		recorder := &statusRecorder{ResponseWriter: w}
		started := time.Now()
		defer func() {
			logger.Info("http_request",
				slog.String("request_id", id),
				slog.String("method", r.Method),
				slog.String("route", routeTemplate(r.URL.Path)),
				slog.Int("status", recorder.statusCode()),
				slog.Int64("duration_ms", time.Since(started).Milliseconds()),
			)
		}()
		next.ServeHTTP(recorder, r)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (w *statusRecorder) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusRecorder) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(body)
}

func (w *statusRecorder) statusCode() int {
	if w.status == 0 {
		return http.StatusOK
	}
	return w.status
}

func (w *statusRecorder) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func newRequestID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

func routeTemplate(path string) string {
	switch path {
	case "/healthz", "/readyz", "/records", "/api-keys", "/roles", "/audit-logs":
		return path
	}
	if strings.HasPrefix(path, "/records/") {
		return "/records/{id}"
	}
	if strings.HasPrefix(path, "/api-keys/") {
		suffix := strings.TrimPrefix(path, "/api-keys/")
		if strings.Contains(suffix, "/role") {
			return "/api-keys/{id}/role"
		}
		return "/api-keys/{id}"
	}
	return "unmatched"
}

type Pinger interface {
	Ping(context.Context) error
}

func NewReadinessHandler(pinger Pinger, timeout time.Duration) http.Handler {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()
		if err := pinger.Ping(ctx); err != nil {
			writeError(w, http.StatusServiceUnavailable, "not_ready", "service is temporarily unavailable")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(struct {
			Status string `json:"status"`
		}{Status: "ready"})
	})
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		Error struct {
			Code string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}{Error: struct {
		Code string `json:"code"`
		Message string `json:"message"`
	}{Code: code, Message: message}})
}

