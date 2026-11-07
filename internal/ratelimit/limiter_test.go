package ratelimit

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func testLimiter(t *testing.T, config Config) *Limiter {
	t.Helper()
	limiter, err := New(config)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return limiter
}

func TestRateLimitWindowRecoveryAndHeaders(t *testing.T) {
	config := DefaultConfig()
	config.RequestsPerAPIKey = 2
	config.RequestsPerIP = 2
	config.Window = time.Second
	config.MaxClients = 4
	limiter := testLimiter(t, config)
	now := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	limiter.now = func() time.Time { return now }

	for i := 0; i < 2; i++ {
		recorder := httptest.NewRecorder()
		if !limiter.AllowAPIKey(17, recorder) {
			t.Fatalf("request %d unexpectedly denied", i+1)
		}
		if recorder.Header().Get("RateLimit-Limit") != "2" {
			t.Fatalf("RateLimit-Limit = %q, want 2", recorder.Header().Get("RateLimit-Limit"))
		}
	}
	recorder := httptest.NewRecorder()
	if limiter.AllowAPIKey(17, recorder) {
		t.Fatal("third request should be rate limited")
	}
	if recorder.Code != http.StatusTooManyRequests || recorder.Header().Get("Retry-After") == "" {
		t.Fatalf("limited response = %d headers=%v, want 429 with Retry-After", recorder.Code, recorder.Header())
	}
	var body struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil || body.Error.Code != "rate_limited" {
		t.Fatalf("limited error body = %q, err=%v", recorder.Body.String(), err)
	}

	now = now.Add(time.Second)
	if !limiter.AllowAPIKey(17, httptest.NewRecorder()) {
		t.Fatal("key did not recover after the window expired")
	}
}

func TestIPLimiterUsesRemoteAddressAndRejectsForwardedHeaderInfluence(t *testing.T) {
	config := DefaultConfig()
	config.RequestsPerIP = 1
	config.Window = time.Minute
	limiter := testLimiter(t, config)
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !limiter.AllowRemoteAddr(r.RemoteAddr, w) {
			return
		}
		next.ServeHTTP(w, r)
	})

	first := httptest.NewRequest(http.MethodGet, "/protected", nil)
	first.RemoteAddr = "192.0.2.10:4000"
	first.Header.Set("X-Forwarded-For", "198.51.100.10")
	firstRecorder := httptest.NewRecorder()
	handler.ServeHTTP(firstRecorder, first)
	if firstRecorder.Code != http.StatusNoContent {
		t.Fatalf("first request = %d, want 204", firstRecorder.Code)
	}

	second := httptest.NewRequest(http.MethodGet, "/protected", nil)
	second.RemoteAddr = "192.0.2.10:5000"
	second.Header.Set("X-Forwarded-For", "203.0.113.20")
	secondRecorder := httptest.NewRecorder()
	handler.ServeHTTP(secondRecorder, second)
	if secondRecorder.Code != http.StatusTooManyRequests {
		t.Fatalf("second request with changed forwarding header = %d, want 429", secondRecorder.Code)
	}

	third := httptest.NewRequest(http.MethodGet, "/protected", nil)
	third.RemoteAddr = "192.0.2.11:4000"
	thirdRecorder := httptest.NewRecorder()
	handler.ServeHTTP(thirdRecorder, third)
	if thirdRecorder.Code != http.StatusNoContent {
		t.Fatalf("request from different RemoteAddr = %d, want 204", thirdRecorder.Code)
	}
}

func TestLimiterBoundsEntriesAndCleansExpiredEntries(t *testing.T) {
	config := DefaultConfig()
	config.RequestsPerAPIKey = 1
	config.RequestsPerIP = 1
	config.MaxClients = 2
	config.Window = time.Second
	limiter := testLimiter(t, config)
	now := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	limiter.now = func() time.Time { return now }

	if !limiter.AllowAPIKey(1, httptest.NewRecorder()) || !limiter.AllowAPIKey(2, httptest.NewRecorder()) {
		t.Fatal("initial clients should fit in the limiter table")
	}
	if limiter.AllowAPIKey(3, httptest.NewRecorder()) {
		t.Fatal("new client should be denied when the bounded table is full")
	}
	keys, _ := limiter.EntryCounts()
	if keys != 2 {
		t.Fatalf("key entry count = %d, want bound 2", keys)
	}
	now = now.Add(2 * time.Second)
	if !limiter.AllowAPIKey(3, httptest.NewRecorder()) {
		t.Fatal("new client should be accepted after expired entries are cleaned")
	}
	keys, _ = limiter.EntryCounts()
	if keys > config.MaxClients {
		t.Fatalf("key entry count = %d exceeds bound %d", keys, config.MaxClients)
	}

	limiter.AllowRemoteAddr("192.0.2.1:1000", httptest.NewRecorder())
	limiter.AllowRemoteAddr("192.0.2.2:1000", httptest.NewRecorder())
	limiter.AllowRemoteAddr("192.0.2.3:1000", httptest.NewRecorder())
	_, ips := limiter.EntryCounts()
	if ips > config.MaxClients {
		t.Fatalf("IP entry count = %d exceeds bound %d", ips, config.MaxClients)
	}
}

func TestDisabledAndReconfiguredLimits(t *testing.T) {
	config := DefaultConfig()
	config.RequestsPerAPIKey = 0
	config.RequestsPerIP = 0
	disabled := testLimiter(t, config)
	for i := 0; i < 20; i++ {
		if !disabled.AllowAPIKey(1, httptest.NewRecorder()) || !disabled.AllowRemoteAddr("192.0.2.1:1234", httptest.NewRecorder()) {
			t.Fatal("disabled identity limits rejected a request")
		}
	}
	keys, ips := disabled.EntryCounts()
	if keys != 0 || ips != 0 {
		t.Fatalf("disabled limiter allocated entries: keys=%d ips=%d", keys, ips)
	}

	config.RequestsPerAPIKey = 1
	reconfigured := testLimiter(t, config)
	if !reconfigured.AllowAPIKey(1, httptest.NewRecorder()) || reconfigured.AllowAPIKey(1, httptest.NewRecorder()) {
		t.Fatal("new limiter did not apply updated per-key limit")
	}
}

func TestGlobalConcurrencyLimit(t *testing.T) {
	config := DefaultConfig()
	config.MaxConcurrentRequests = 1
	limiter := testLimiter(t, config)
	started := make(chan struct{})
	var startedOnce sync.Once
	release := make(chan struct{})
	handler := limiter.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		startedOnce.Do(func() { close(started) })
		<-release
		w.WriteHeader(http.StatusNoContent)
	}))

	firstDone := make(chan struct{})
	go func() {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
		if recorder.Code != http.StatusNoContent {
			t.Errorf("first response = %d, want 204", recorder.Code)
		}
		close(firstDone)
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first request did not enter handler")
	}

	second := httptest.NewRecorder()
	handler.ServeHTTP(second, httptest.NewRequest(http.MethodGet, "/", nil))
	if second.Code != http.StatusTooManyRequests || second.Header().Get("Retry-After") != "1" {
		t.Fatalf("concurrent overflow response = %d headers=%v, want 429 Retry-After: 1", second.Code, second.Header())
	}
	close(release)
	select {
	case <-firstDone:
	case <-time.After(time.Second):
		t.Fatal("first request did not finish")
	}
	after := httptest.NewRecorder()
	handler.ServeHTTP(after, httptest.NewRequest(http.MethodGet, "/", nil))
	if after.Code != http.StatusNoContent {
		t.Fatalf("request after capacity release = %d, want 204", after.Code)
	}
}

func TestConcurrentLimiterAccessStaysBounded(t *testing.T) {
	config := DefaultConfig()
	config.RequestsPerAPIKey = 1000
	config.MaxClients = 8
	limiter := testLimiter(t, config)
	var wg sync.WaitGroup
	for i := int64(0); i < 100; i++ {
		wg.Add(1)
		go func(id int64) {
			defer wg.Done()
			limiter.AllowAPIKey(id, httptest.NewRecorder())
		}(i + 1)
	}
	wg.Wait()
	keys, _ := limiter.EntryCounts()
	if keys > config.MaxClients {
		t.Fatalf("concurrent key entry count = %d exceeds bound %d", keys, config.MaxClients)
	}
}

func TestLoadConfigDefaultsOverridesAndRejectsInvalidSettingsSafely(t *testing.T) {
	values := map[string]string{}
	getenv := func(key string) string { return values[key] }
	config, err := LoadConfig(getenv)
	if err != nil {
		t.Fatalf("LoadConfig(defaults) error = %v", err)
	}
	defaults := DefaultConfig()
	if config != defaults {
		t.Fatalf("default config = %+v, want %+v", config, defaults)
	}

	values["ATLAS_MAX_CONCURRENT_REQUESTS"] = "64"
	values["ATLAS_RATE_LIMIT_PER_KEY"] = "0"
	values["ATLAS_RATE_LIMIT_PER_IP"] = "25"
	values["ATLAS_RATE_LIMIT_WINDOW"] = "30s"
	values["ATLAS_RATE_LIMIT_MAX_CLIENTS"] = "500"
	config, err = LoadConfig(getenv)
	if err != nil || config.MaxConcurrentRequests != 64 || config.RequestsPerAPIKey != 0 || config.RequestsPerIP != 25 || config.Window != 30*time.Second || config.MaxClients != 500 {
		t.Fatalf("overridden config = %+v, error=%v", config, err)
	}

	values["ATLAS_RATE_LIMIT_PER_IP"] = "bad-secret-looking-value"
	if _, err := LoadConfig(getenv); err == nil || err.Error() != "ATLAS_RATE_LIMIT_PER_IP must be between 0 and 1000000" {
		t.Fatalf("invalid config error = %v, want safe setting-name error", err)
	}
	if _, err := New(Config{MaxConcurrentRequests: 1, RequestsPerAPIKey: 1, RequestsPerIP: 1, Window: time.Second, MaxClients: 0}); err == nil {
		t.Fatal("New accepted zero MaxClients")
	}
}
