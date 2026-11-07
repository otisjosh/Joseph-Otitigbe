package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestHealthChecksRemainAvailableWhenNormalConcurrencyIsFull(t *testing.T) {
	config := DefaultConfig()
	config.MaxConcurrentRequests = 1
	limiter := testLimiter(t, config)
	normalStarted := make(chan struct{})
	releaseNormal := make(chan struct{})
	handler := limiter.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/normal" {
			close(normalStarted)
			<-releaseNormal
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	normalDone := make(chan struct{})
	go func() {
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/normal", nil))
		close(normalDone)
	}()
	select {
	case <-normalStarted:
	case <-time.After(time.Second):
		t.Fatal("normal request did not occupy the concurrency slot")
	}

	for _, path := range []string{"/healthz", "/readyz"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusNoContent {
			t.Errorf("%s response = %d %q while normal capacity was full, want handler response", path, response.Code, response.Body.String())
		}
	}
	close(releaseNormal)
	select {
	case <-normalDone:
	case <-time.After(time.Second):
		t.Fatal("normal request did not finish")
	}
}

func TestReadinessChecksHaveSeparateBoundedCapacity(t *testing.T) {
	config := DefaultConfig()
	config.MaxConcurrentRequests = 1
	limiter := testLimiter(t, config)
	started := make(chan struct{}, maxConcurrentReadinessRequests)
	release := make(chan struct{})
	var startOnce sync.Once
	handler := limiter.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/readyz" {
			started <- struct{}{}
			<-release
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	var wg sync.WaitGroup
	responses := make(chan int, maxConcurrentReadinessRequests)
	for i := 0; i < maxConcurrentReadinessRequests; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/readyz", nil))
			responses <- response.Code
		}()
		<-started
	}

	overflow := httptest.NewRecorder()
	handler.ServeHTTP(overflow, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if overflow.Code != http.StatusServiceUnavailable || !containsJSONCode(overflow.Body.String(), "not_ready") {
		t.Fatalf("third concurrent readiness response = %d %q, want safe 503 not_ready", overflow.Code, overflow.Body.String())
	}
	if overflow.Header().Get("Retry-After") != "1" {
		t.Errorf("readiness overflow Retry-After = %q, want 1", overflow.Header().Get("Retry-After"))
	}

	health := httptest.NewRecorder()
	handler.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if health.Code != http.StatusNoContent {
		t.Fatalf("liveness response = %d while readiness slots were full, want 204", health.Code)
	}

	startOnce.Do(func() { close(release) })
	wg.Wait()
	close(responses)
	for status := range responses {
		if status != http.StatusNoContent {
			t.Errorf("admitted readiness response = %d, want 204", status)
		}
	}
}

func containsJSONCode(body, code string) bool {
	return strings.Contains(body, `"code":"`+code+`"`)
}
