package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/otisjosh/Joseph-Otitigbe/internal/ratelimit"
)

type touchCountingStore struct {
	KeyStore
	touches atomic.Int32
}

func (s *touchCountingStore) TouchKey(ctx context.Context, id int64) error {
	s.touches.Add(1)
	return s.KeyStore.TouchKey(ctx, id)
}

type keyDecisionLimiter struct {
	allowKey bool
}

func (l keyDecisionLimiter) AllowRemoteAddr(string, http.ResponseWriter) bool { return true }
func (l keyDecisionLimiter) AllowAPIKey(int64, http.ResponseWriter) bool { return l.allowKey }

type revokeAfterLookupStore struct {
	KeyStore
}

func (s revokeAfterLookupStore) LookupKey(ctx context.Context, publicID string) (Credential, error) {
	credential, err := s.KeyStore.LookupKey(ctx, publicID)
	if err == nil {
		_, _ = s.KeyStore.RevokeKey(ctx, credential.ID, nil)
	}
	return credential, err
}

func TestPerKeyRateRejectionHappensBeforeTouchAndHandler(t *testing.T) {
	base := newMemoryKeyStore()
	_, token, err := NewKeyManager(base).Create(context.Background(), "limited", RoleReader, nil)
	if err != nil {
		t.Fatal(err)
	}
	store := &touchCountingStore{KeyStore: base}
	handlerReached := atomic.Bool{}
	handler := MiddlewareWithLimiter(store, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		handlerReached.Store(true)
		w.WriteHeader(http.StatusNoContent)
	}), keyDecisionLimiter{allowKey: false})

	request := httptest.NewRequest(http.MethodGet, "/records/1", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusTooManyRequests {
		t.Fatalf("response = %d %q, want 429", response.Code, response.Body.String())
	}
	if store.touches.Load() != 0 {
		t.Fatalf("TouchKey calls = %d, want 0 for a rate-limited request", store.touches.Load())
	}
	if handlerReached.Load() {
		t.Fatal("rate-limited request reached protected handler")
	}
}

func TestRevocationAfterLookupStillRejectsBeforeProtectedHandler(t *testing.T) {
	base := newMemoryKeyStore()
	_, token, err := NewKeyManager(base).Create(context.Background(), "racing", RoleReader, nil)
	if err != nil {
		t.Fatal(err)
	}
	store := revokeAfterLookupStore{KeyStore: base}
	handlerReached := atomic.Bool{}
	handler := MiddlewareWithLimiter(store, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		handlerReached.Store(true)
		w.WriteHeader(http.StatusNoContent)
	}), keyDecisionLimiter{allowKey: true})

	request := httptest.NewRequest(http.MethodGet, "/records/1", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("response = %d %q, want 401 after revocation race", response.Code, response.Body.String())
	}
	if handlerReached.Load() {
		t.Fatal("revoked key reached protected handler")
	}
}

var _ ratelimit.Config
