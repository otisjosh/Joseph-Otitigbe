package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/otisjosh/Joseph-Otitigbe/internal/auth"
)

func TestAPIKeyExpirationPersistenceAuthenticationAndSafeListing(t *testing.T) {
	pool := isolatedAuthPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	store := NewKeyStore(pool)
	manager := auth.NewKeyManager(store)
	future := time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond)
	futureMetadata, futureToken, err := manager.CreateWithExpiry(ctx, fmt.Sprintf("future-%d", time.Now().UnixNano()), auth.RoleReader, &future, nil)
	if err != nil { t.Fatalf("create future-expiring key: %v", err) }
	legacyMetadata, legacyToken, err := manager.Create(ctx, fmt.Sprintf("legacy-%d", time.Now().UnixNano()), auth.RoleReader, nil)
	if err != nil { t.Fatalf("create non-expiring key: %v", err) }
	past := time.Now().UTC().Add(-time.Minute)
	expiredMetadata, expiredToken, err := manager.CreateWithExpiry(ctx, fmt.Sprintf("expired-%d", time.Now().UnixNano()), auth.RoleReader, &future, nil)
	if err != nil { t.Fatalf("create key to expire: %v", err) }
	if _, err := pool.Exec(ctx, "UPDATE atlas_api_keys SET expires_at = $1 WHERE id = $2", past, expiredMetadata.ID); err != nil {
		t.Fatalf("set key expiry in the past: %v", err)
	}
	revokedMetadata, revokedToken, err := manager.CreateWithExpiry(ctx, fmt.Sprintf("revoked-%d", time.Now().UnixNano()), auth.RoleReader, &future, nil)
	if err != nil { t.Fatalf("create revoked key: %v", err) }
	if _, err := pool.Exec(ctx, "UPDATE atlas_api_keys SET expires_at = $1 WHERE id = $2", past, revokedMetadata.ID); err != nil { t.Fatal(err) }
	if _, err := manager.Revoke(ctx, revokedMetadata.ID, nil); err != nil { t.Fatalf("revoke expired key: %v", err) }

	for _, tc := range []struct{name, token string; want int}{
		{"future expiry", futureToken, http.StatusNoContent},
		{"legacy null expiry", legacyToken, http.StatusNoContent},
		{"expired", expiredToken, http.StatusUnauthorized},
		{"revoked and expired", revokedToken, http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			handler := auth.Middleware(store, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls++; w.WriteHeader(http.StatusNoContent) }))
			req := httptest.NewRequest(http.MethodGet, "/records/1", nil)
			req.Header.Set("Authorization", "Bearer "+tc.token)
			res := httptest.NewRecorder()
			handler.ServeHTTP(res, req)
			if res.Code != tc.want { t.Fatalf("status=%d want=%d body=%s", res.Code, tc.want, res.Body) }
			if (tc.want == http.StatusNoContent) != (calls == 1) { t.Fatalf("handler calls=%d", calls) }
		})
	}

	listed, err := manager.List(ctx)
	if err != nil { t.Fatalf("list API keys: %v", err) }
	byID := map[int64]auth.KeyMetadata{}
	for _, key := range listed { byID[key.ID] = key }
	if byID[futureMetadata.ID].ExpiresAt == nil || !byID[futureMetadata.ID].ExpiresAt.Equal(future) {
		t.Fatalf("future expiry missing or changed: %+v", byID[futureMetadata.ID].ExpiresAt)
	}
	if byID[legacyMetadata.ID].ExpiresAt != nil { t.Fatalf("legacy key expiry = %v, want null", byID[legacyMetadata.ID].ExpiresAt) }
	encoded, err := json.Marshal(listed)
	if err != nil { t.Fatal(err) }
	if strings.Contains(string(encoded), futureToken) || strings.Contains(string(encoded), "key_hash") || strings.Contains(string(encoded), "expires-") {
		t.Fatalf("key listing leaked secret/hash or unexpected token material: %s", encoded)
	}
}
