package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/otisjosh/Joseph-Otitigbe/internal/postgres"
)

func TestNewServerSetsTimeoutsAndHeaderLimit(t *testing.T) {
	server := newServer(":8080", http.NotFoundHandler())
	if server.ReadHeaderTimeout != 5*time.Second {
		t.Errorf("ReadHeaderTimeout = %v, want 5s", server.ReadHeaderTimeout)
	}
	if server.ReadTimeout != 15*time.Second {
		t.Errorf("ReadTimeout = %v, want 15s", server.ReadTimeout)
	}
	if server.WriteTimeout != 30*time.Second {
		t.Errorf("WriteTimeout = %v, want 30s", server.WriteTimeout)
	}
	if server.IdleTimeout != 60*time.Second {
		t.Errorf("IdleTimeout = %v, want 60s", server.IdleTimeout)
	}
	if server.MaxHeaderBytes != 1<<20 {
		t.Errorf("MaxHeaderBytes = %d, want %d", server.MaxHeaderBytes, 1<<20)
	}
}

type failingPinger struct{}
func (failingPinger) Ping(context.Context) error { return errors.New("database URL contains password") }

func TestRoutesKeepHealthLightweightAndReadyzSafe(t *testing.T) {
	handler := routes(postgres.NewKeyStore(nil), postgres.NewStore(nil), failingPinger{}, newJSONLogger(io.Discard))
	health := httptest.NewRecorder()
	handler.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if health.Code != http.StatusOK || health.Body.Len() != 0 {
		t.Fatalf("health response = %d %q, want empty 200", health.Code, health.Body.String())
	}
	ready := httptest.NewRecorder()
	handler.ServeHTTP(ready, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if ready.Code != http.StatusServiceUnavailable || ready.Body.String() != "{\"error\":{\"code\":\"not_ready\",\"message\":\"service is temporarily unavailable\"}}\n" {
		t.Fatalf("ready response = %d %q, want safe 503 JSON", ready.Code, ready.Body.String())
	}
	if bytes.Contains(ready.Body.Bytes(), []byte("password")) {
		t.Fatal("readiness response exposed database error details")
	}
}
