package observability

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"log/slog"
)

func TestRequestLoggingGeneratesUniqueIDsAndRedactsSensitiveInput(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, nil))
	handler := RequestLogging(logger, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := RequestIDFromContext(r.Context())
		if !ok || id == "" || r.Header.Get(RequestIDHeader) != id {
			t.Errorf("request ID context/header mismatch: context=%q header=%q", id, r.Header.Get(RequestIDHeader))
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("ok"))
	}))

	secrets := []string{"bearer-secret-value", "private@example.test", "private-record-name", "db-password"}
	var ids []string
	for _, method := range []string{http.MethodPost, http.MethodGet} {
		req := httptest.NewRequest(method, "/records/123?email="+secrets[1]+"&db="+secrets[3], strings.NewReader(secrets[2]))
		req.Header.Set("Authorization", "Bearer "+secrets[0])
		req.Header.Set(RequestIDHeader, "caller-controlled")
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		id := res.Header().Get(RequestIDHeader)
		if len(id) != 32 || id == "caller-controlled" {
			t.Fatalf("generated request ID = %q, want fresh 128-bit hex ID", id)
		}
		ids = append(ids, id)
	}
	if ids[0] == ids[1] {
		t.Fatal("request IDs were reused")
	}
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("log lines = %d, want 2: %q", len(lines), output.String())
	}
	for i, line := range lines {
		var fields map[string]any
		if err := json.Unmarshal([]byte(line), &fields); err != nil {
			t.Fatalf("log is not JSON: %v", err)
		}
		if fields["msg"] != "http_request" || fields["method"] != []string{"POST", "GET"}[i] ||
			fields["route"] != "/records/{id}" || fields["status"] != float64(http.StatusCreated) ||
			fields["request_id"] != ids[i] {
			t.Errorf("unexpected request log fields: %#v", fields)
		}
		if _, ok := fields["duration_ms"]; !ok {
			t.Errorf("duration_ms missing: %#v", fields)
		}
	}
	logText := output.String()
	for _, secret := range secrets {
		if strings.Contains(logText, secret) {
			t.Errorf("log leaked sensitive value %q", secret)
		}
	}
}

type pingerFunc func(context.Context) error
func (f pingerFunc) Ping(ctx context.Context) error { return f(ctx) }

func TestReadinessSucceedsWithBoundedContext(t *testing.T) {
	called := false
	handler := NewReadinessHandler(pingerFunc(func(ctx context.Context) error {
		called = true
		if _, ok := ctx.Deadline(); !ok {
			t.Error("Ping context has no deadline")
		}
		return nil
	}), time.Second)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if !called || res.Code != http.StatusOK || !strings.Contains(res.Body.String(), "ready") {
		t.Fatalf("response=%d %q called=%v", res.Code, res.Body.String(), called)
	}
}

func TestReadinessFailureIsSafeAndMethodLimited(t *testing.T) {
	handler := NewReadinessHandler(pingerFunc(func(context.Context) error {
		return errors.New("postgres://user:database-password@host/db")
	}), time.Second)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if res.Code != http.StatusServiceUnavailable || !strings.Contains(res.Body.String(), "not_ready") ||
		strings.Contains(res.Body.String(), "database-password") || strings.Contains(res.Body.String(), "postgres://") {
		t.Fatalf("unsafe readiness response = %d %q", res.Code, res.Body.String())
	}
	method := httptest.NewRecorder()
	handler.ServeHTTP(method, httptest.NewRequest(http.MethodPost, "/readyz", nil))
	if method.Code != http.StatusMethodNotAllowed || method.Header().Get("Allow") != http.MethodGet {
		t.Fatalf("POST /readyz = %d Allow=%q", method.Code, method.Header().Get("Allow"))
	}
}
