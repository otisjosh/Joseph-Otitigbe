package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/otisjosh/Joseph-Otitigbe/internal/postgres"
)

func TestLoadDatabaseURLValidatesWithoutExposingInput(t *testing.T) {
	values := map[string]string{"DATABASE_URL": "not a postgres URL"}
	getenv := func(key string) string { return values[key] }

	if _, err := loadDatabaseURL(getenv); err == nil || err.Error() != "DATABASE_URL is invalid" {
		t.Fatalf("invalid DATABASE_URL error = %v, want safe configuration error", err)
	}
	if strings.Contains("DATABASE_URL is invalid", values["DATABASE_URL"]) {
		t.Fatal("configuration error exposed the supplied DATABASE_URL")
	}

	values["DATABASE_URL"] = "   "
	if _, err := loadDatabaseURL(getenv); err == nil || err.Error() != "DATABASE_URL is required" {
		t.Fatalf("missing DATABASE_URL error = %v, want required-setting error", err)
	}
	values["DATABASE_URL"] = "postgres://localhost:5432/atlas?sslmode=disable"
	if got, err := loadDatabaseURL(getenv); err != nil || got != values["DATABASE_URL"] {
		t.Fatalf("valid DATABASE_URL = %q, error = %v", got, err)
	}
}

func TestLoadListenAddressDefaultsAndValidates(t *testing.T) {
	values := map[string]string{}
	getenv := func(key string) string { return values[key] }
	if got, err := loadListenAddress(getenv); err != nil || got != ":8080" {
		t.Fatalf("default ATLAS_ADDR = %q, error = %v", got, err)
	}
	values["ATLAS_ADDR"] = "0.0.0.0:8080"
	if got, err := loadListenAddress(getenv); err != nil || got != values["ATLAS_ADDR"] {
		t.Fatalf("valid ATLAS_ADDR = %q, error = %v", got, err)
	}
	values["ATLAS_ADDR"] = "not-an-address"
	if _, err := loadListenAddress(getenv); err == nil || err.Error() != "ATLAS_ADDR must be a valid host:port address" {
		t.Fatalf("invalid ATLAS_ADDR error = %v, want safe configuration error", err)
	}
}

func TestServeHTTPDrainsRequestsBeforeClosingDatabase(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for shutdown test: %v", err)
	}
	handlerStarted := make(chan struct{})
	releaseHandler := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(releaseHandler) })

	server := newServer("", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(handlerStarted)
		<-releaseHandler
		w.WriteHeader(http.StatusNoContent)
	}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	databaseClosed := make(chan struct{})
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- serveHTTP(ctx, server, listener, func() { close(databaseClosed) }, newJSONLogger(io.Discard))
	}()

	requestDone := make(chan error, 1)
	go func() {
		response, err := http.Get("http://" + listener.Addr().String())
		if err != nil {
			requestDone <- err
			return
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusNoContent {
			requestDone <- errors.New("in-flight request returned an unexpected status")
			return
		}
		requestDone <- nil
	}()

	select {
	case <-handlerStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("request handler did not start")
	}
	cancel()
	select {
	case <-databaseClosed:
		t.Fatal("database closed before the active request drained")
	case <-time.After(25 * time.Millisecond):
	}

	releaseOnce.Do(func() { close(releaseHandler) })
	select {
	case err := <-requestDone:
		if err != nil {
			t.Fatalf("in-flight request failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("in-flight request did not finish")
	}
	select {
	case err := <-serveDone:
		if err != nil {
			t.Fatalf("serveHTTP() error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("HTTP server did not finish graceful shutdown")
	}
	select {
	case <-databaseClosed:
	case <-time.After(time.Second):
		t.Fatal("database close callback was not called")
	}
}

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

func TestSafeHTTPErrorWriterDoesNotLogDiagnosticContents(t *testing.T) {
	var output bytes.Buffer
	logger := newJSONLogger(&output)
	writer := safeHTTPErrorWriter{logger: logger}
	message := []byte("panic: Authorization: Bearer highly-sensitive-token")
	if _, err := writer.Write(message); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if !bytes.Contains(output.Bytes(), []byte("http_server_internal_error")) {
		t.Fatalf("safe error event missing: %s", output.String())
	}
	if bytes.Contains(output.Bytes(), []byte("highly-sensitive-token")) || bytes.Contains(output.Bytes(), []byte("Authorization")) {
		t.Fatalf("HTTP diagnostic contents leaked: %s", output.String())
	}
}
