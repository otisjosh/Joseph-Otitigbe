package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/otisjosh/Joseph-Otitigbe/internal/ratelimit"
)

func TestProtectedEndpointAuthorizationMatrix(t *testing.T) {
	store := newMemoryKeyStore()
	manager := NewKeyManager(store)
	reader, readerToken, err := manager.Create(context.Background(), "matrix-reader", RoleReader, nil)
	if err != nil { t.Fatal(err) }
	writer, writerToken, err := manager.Create(context.Background(), "matrix-writer", RoleWriter, nil)
	if err != nil { t.Fatal(err) }
	admin, adminToken, err := manager.Create(context.Background(), "matrix-admin", RoleAdmin, nil)
	if err != nil { t.Fatal(err) }

	endpoints := []struct {
		method string
		path string
		reader bool
		writer bool
		admin bool
	}{
		{http.MethodGet, "/records/1", true, true, true},
		{http.MethodPost, "/records", false, true, true},
		{http.MethodGet, "/api-keys", false, false, true},
		{http.MethodPost, "/api-keys", false, false, true},
		{http.MethodPatch, fmt.Sprintf("/api-keys/%d/role", reader.ID), false, false, true},
		{http.MethodDelete, fmt.Sprintf("/api-keys/%d", writer.ID), false, false, true},
		{http.MethodGet, "/roles", false, false, true},
		{http.MethodGet, "/audit-logs", false, false, true},
	}
	for _, endpoint := range endpoints {
		endpoint := endpoint
		t.Run(endpoint.method+" "+endpoint.path, func(t *testing.T) {
			for _, test := range []struct {
				name string
				token string
				allowed bool
			}{
				{name: "reader", token: readerToken, allowed: endpoint.reader},
				{name: "writer", token: writerToken, allowed: endpoint.writer},
				{name: "admin", token: adminToken, allowed: endpoint.admin},
			} {
				t.Run(test.name, func(t *testing.T) {
					request := httptest.NewRequest(endpoint.method, endpoint.path, nil)
					request.Header.Set("Authorization", "Bearer "+test.token)
					recorder := httptest.NewRecorder()
					Middleware(store, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						w.WriteHeader(http.StatusNoContent)
					})).ServeHTTP(recorder, request)
					want := http.StatusForbidden
					if test.allowed { want = http.StatusNoContent }
					if recorder.Code != want {
						t.Fatalf("status = %d, want %d: %s", recorder.Code, want, recorder.Body.String())
					}
					if strings.Contains(recorder.Body.String(), test.token) {
						t.Fatal("API error reflected the bearer credential")
					}
				})
			}

			request := httptest.NewRequest(endpoint.method, endpoint.path, nil)
			recorder := httptest.NewRecorder()
			Middleware(store, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			})).ServeHTTP(recorder, request)
			if recorder.Code != http.StatusUnauthorized || !strings.Contains(recorder.Body.String(), "authentication_required") {
				t.Fatalf("missing credential response = %d %q, want 401 authentication_required", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestAuthenticationErrorsDoNotEchoCredential(t *testing.T) {
	secret := "atlas_sensitive-token-that-must-not-be-reflected"
	request := httptest.NewRequest(http.MethodGet, "/records/1", nil)
	request.Header.Set("Authorization", "Bearer "+secret)
	recorder := httptest.NewRecorder()
	Middleware(newMemoryKeyStore(), http.NotFoundHandler()).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", recorder.Code)
	}
	if strings.Contains(recorder.Body.String(), secret) {
		t.Fatalf("authentication error exposed bearer credential: %q", recorder.Body.String())
	}
}

func TestSourceAndAPIKeyLimitsAreAppliedAtAuthenticationBoundary(t *testing.T) {
	store := newMemoryKeyStore()
	manager := NewKeyManager(store)
	_, token, err := manager.Create(context.Background(), "limited-reader", RoleReader, nil)
	if err != nil { t.Fatal(err) }

	config := ratelimit.DefaultConfig()
	config.RequestsPerIP = 1
	config.RequestsPerAPIKey = 0
	config.Window = time.Minute
	sourceLimiter, err := ratelimit.New(config)
	if err != nil { t.Fatal(err) }
	handler := MiddlewareWithLimiter(store, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), sourceLimiter)

	first := httptest.NewRequest(http.MethodGet, "/records/1", nil)
	first.RemoteAddr = "192.0.2.44:1234"
	first.Header.Set("X-Forwarded-For", "198.51.100.10")
	firstResponse := httptest.NewRecorder()
	handler.ServeHTTP(firstResponse, first)
	if firstResponse.Code != http.StatusUnauthorized {
		t.Fatalf("first missing-key response = %d, want 401", firstResponse.Code)
	}
	second := httptest.NewRequest(http.MethodGet, "/records/1", nil)
	second.RemoteAddr = "192.0.2.44:4321"
	second.Header.Set("X-Forwarded-For", "203.0.113.50")
	secondResponse := httptest.NewRecorder()
	handler.ServeHTTP(secondResponse, second)
	if secondResponse.Code != http.StatusTooManyRequests || secondResponse.Header().Get("RateLimit-Limit") != "1" {
		t.Fatalf("same RemoteAddr with changed forwarding header = %d headers=%v, want 429", secondResponse.Code, secondResponse.Header())
	}

	config.RequestsPerIP = 0
	config.RequestsPerAPIKey = 1
	keyLimiter, err := ratelimit.New(config)
	if err != nil { t.Fatal(err) }
	keyHandler := MiddlewareWithLimiter(store, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), keyLimiter)
	for i, want := range []int{http.StatusNoContent, http.StatusTooManyRequests} {
		request := httptest.NewRequest(http.MethodGet, "/records/1", nil)
		request.RemoteAddr = fmt.Sprintf("192.0.2.50:%d", 5000+i)
		request.Header.Set("Authorization", "Bearer "+token)
		response := httptest.NewRecorder()
		keyHandler.ServeHTTP(response, request)
		if response.Code != want {
			t.Fatalf("per-key request %d = %d, want %d: %s", i+1, response.Code, want, response.Body.String())
		}
		if want == http.StatusTooManyRequests && !strings.Contains(response.Body.String(), "rate_limited") {
			t.Fatalf("per-key response body = %q, want rate_limited", response.Body.String())
		}
	}
}

func TestOversizedAPIKeyManagementBodiesAreRejectedWithoutReflection(t *testing.T) {
	store := newMemoryKeyStore()
	manager := NewKeyManager(store)
	handler := NewKeyHandler(manager)
	adminContext := ContextWithPrincipal(context.Background(), Principal{KeyID: 1, Role: RoleAdmin})

	createBody := `{"name":"` + strings.Repeat("a", (16<<10)+1) + `","role":"reader"}`
	roleBody := `{"role":"writer"}` + strings.Repeat(" ", (16<<10)+1)
	for _, test := range []struct {
		method string
		path string
		body string
	}{
		{http.MethodPost, "/api-keys", createBody},
		{http.MethodPatch, "/api-keys/1/role", roleBody},
	} {
		request := httptest.NewRequest(test.method, test.path, strings.NewReader(test.body)).WithContext(adminContext)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "invalid_json") {
			t.Errorf("%s %s oversized response = %d %q, want 400 invalid_json", test.method, test.path, response.Code, response.Body.String())
		}
		if strings.Contains(response.Body.String(), strings.Repeat("a", 100)) || strings.Contains(response.Body.String(), "writer") {
			t.Errorf("%s %s error reflected request data: %q", test.method, test.path, response.Body.String())
		}
	}
}

func TestConcurrentAPIKeyProvisioning(t *testing.T) {
	store := newMemoryKeyStore()
	handler := NewKeyHandler(NewKeyManager(store))
	ctx := ContextWithPrincipal(context.Background(), Principal{KeyID: 1, Role: RoleAdmin})
	const count = 40
	var wg sync.WaitGroup
	var mu sync.Mutex
	ids := make(map[int64]bool)
	tokens := make(map[string]bool)
	errors := make(chan string, count)
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			body := fmt.Sprintf(`{"name":"parallel-%d","role":"reader"}`, i)
			request := httptest.NewRequest(http.MethodPost, "/api-keys", strings.NewReader(body)).WithContext(ctx)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusCreated {
				errors <- fmt.Sprintf("status=%d body=%s", response.Code, response.Body.String())
				return
			}
			var result struct {
				KeyMetadata
				APIKey string `json:"api_key"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
				errors <- fmt.Sprintf("decode response: %v", err)
				return
			}
			mu.Lock()
			defer mu.Unlock()
			if ids[result.ID] || tokens[result.APIKey] || result.APIKey == "" {
				errors <- "duplicate or empty provisioned ID/token"
				return
			}
			ids[result.ID] = true
			tokens[result.APIKey] = true
		}(i)
	}
	wg.Wait()
	close(errors)
	for err := range errors { t.Error(err) }
	if len(ids) != count || len(tokens) != count {
		t.Fatalf("provisioned IDs=%d unique tokens=%d, want %d each", len(ids), len(tokens), count)
	}
}
