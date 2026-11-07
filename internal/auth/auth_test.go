package auth

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type memoryKeyStore struct {
	mu          sync.Mutex
	nextID      int64
	credentials map[string]Credential
	metadata    map[int64]KeyMetadata
	roles       []RoleInfo
}

func newMemoryKeyStore() *memoryKeyStore {
	return &memoryKeyStore{
		nextID:      1,
		credentials: make(map[string]Credential),
		metadata:    make(map[int64]KeyMetadata),
		roles: []RoleInfo{
			{Name: RoleReader, Permissions: []Permission{PermissionRecordsRead}},
			{Name: RoleWriter, Permissions: []Permission{PermissionRecordsRead, PermissionRecordsWrite}},
			{Name: RoleAdmin, Permissions: []Permission{PermissionRecordsRead, PermissionRecordsWrite, PermissionKeysManage}},
		},
	}
}

func (s *memoryKeyStore) CreateKey(_ context.Context, name string, role Role, publicID string, hash []byte, actor *int64) (KeyMetadata, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !ValidRole(role) {
		return KeyMetadata{}, ErrInvalidRole
	}
	metadata := KeyMetadata{ID: s.nextID, PublicID: publicID, Name: name, Role: role, CreatedAt: time.Now().UTC(), CreatedByKeyID: actor}
	s.nextID++
	s.metadata[metadata.ID] = metadata
	var permissions []Permission
	for _, info := range s.roles {
		if info.Name == role {
			permissions = info.Permissions
		}
	}
	s.credentials[publicID] = Credential{ID: metadata.ID, PublicID: publicID, Hash: append([]byte(nil), hash...), Role: role, Permissions: permissions}
	return metadata, nil
}

func (s *memoryKeyStore) CreateKeyWithExpiry(ctx context.Context, name string, role Role, publicID string, hash []byte, expiresAt *time.Time, actor *int64) (KeyMetadata, error) {
	metadata, err := s.CreateKey(ctx, name, role, publicID, hash, actor)
	if err != nil { return KeyMetadata{}, err }
	s.mu.Lock()
	defer s.mu.Unlock()
	value := expiresAt.UTC()
	metadata.ExpiresAt = &value
	s.metadata[metadata.ID] = metadata
	credential := s.credentials[publicID]
	credential.ExpiresAt = &value
	s.credentials[publicID] = credential
	return metadata, nil
}

func (s *memoryKeyStore) LookupKey(_ context.Context, publicID string) (Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	credential, ok := s.credentials[publicID]
	if !ok {
		return Credential{}, ErrInvalidKey
	}
	credential.Hash = append([]byte(nil), credential.Hash...)
	return credential, nil
}

func (s *memoryKeyStore) TouchKey(_ context.Context, id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, metadata := range s.metadata {
		if metadata.ID == id {
			if metadata.RevokedAt != nil {
				return ErrInvalidKey
			}
			return nil
		}
	}
	return ErrInvalidKey
}

func (s *memoryKeyStore) ListKeys(context.Context) ([]KeyMetadata, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	keys := make([]KeyMetadata, 0, len(s.metadata))
	for _, metadata := range s.metadata {
		keys = append(keys, metadata)
	}
	return keys, nil
}

func (s *memoryKeyStore) RevokeKey(_ context.Context, id int64, actor *int64) (KeyMetadata, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	metadata, ok := s.metadata[id]
	if !ok || metadata.RevokedAt != nil {
		return KeyMetadata{}, ErrKeyNotFound
	}
	now := time.Now().UTC()
	metadata.RevokedAt = &now
	metadata.RevokedByKeyID = actor
	s.metadata[id] = metadata
	delete(s.credentials, metadata.PublicID)
	return metadata, nil
}

func (s *memoryKeyStore) ChangeKeyRole(_ context.Context, id int64, role Role, actor *int64) (KeyMetadata, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	metadata, ok := s.metadata[id]
	if !ok || metadata.RevokedAt != nil {
		return KeyMetadata{}, ErrKeyNotFound
	}
	if !ValidRole(role) {
		return KeyMetadata{}, ErrInvalidRole
	}
	metadata.Role = role
	now := time.Now().UTC()
	metadata.RoleChangedAt = &now
	metadata.RoleChangedByKeyID = actor
	s.metadata[id] = metadata
	credential := s.credentials[metadata.PublicID]
	credential.Role = role
	for _, info := range s.roles {
		if info.Name == role {
			credential.Permissions = info.Permissions
		}
	}
	s.credentials[metadata.PublicID] = credential
	return metadata, nil
}

func (s *memoryKeyStore) ListRoles(context.Context) ([]RoleInfo, error) {
	return s.roles, nil
}

func TestKeyManagerGeneratesRandomOneTimeKeyAndStoresOnlyHash(t *testing.T) {
	store := newMemoryKeyStore()
	manager := NewKeyManager(store)
	metadata, token, err := manager.Create(context.Background(), "automation", RoleWriter, nil)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if !strings.HasPrefix(token, "atlas_") || !strings.Contains(token, ".") {
		t.Fatal("generated token has unexpected format")
	}
	publicID, secret, ok := parseToken(token)
	if !ok {
		t.Fatal("generated token could not be parsed")
	}
	defer clear(secret)
	hash := sha256.Sum256(secret)
	credential, err := store.LookupKey(context.Background(), publicID)
	if err != nil {
		t.Fatalf("LookupKey() error = %v", err)
	}
	if len(credential.Hash) != sha256.Size || string(credential.Hash) == token {
		t.Fatal("stored credential is not a SHA-256 hash")
	}
	if string(credential.Hash) != string(hash[:]) {
		t.Fatal("stored hash does not match generated secret")
	}
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(metadataJSON), token) || strings.Contains(string(metadataJSON), "key_hash") {
		t.Fatalf("metadata exposed credential material: %s", metadataJSON)
	}
}

func TestMiddlewareRequiresValidBearerAndEnforcesRole(t *testing.T) {
	store := newMemoryKeyStore()
	manager := NewKeyManager(store)
	_, readerToken, err := manager.Create(context.Background(), "reader", RoleReader, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, writerToken, err := manager.Create(context.Background(), "writer", RoleWriter, nil)
	if err != nil {
		t.Fatal(err)
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	handler := Middleware(store, next)

	tests := []struct {
		name, method, path, authorization string
		wantStatus                        int
		wantCode                          string
	}{
		{"missing", http.MethodGet, "/records/1", "", http.StatusUnauthorized, "authentication_required"},
		{"malformed scheme", http.MethodGet, "/records/1", "Basic abc", http.StatusUnauthorized, "invalid_api_key"},
		{"malformed token", http.MethodGet, "/records/1", "Bearer atlas_bad", http.StatusUnauthorized, "invalid_api_key"},
		{"wrong secret", http.MethodGet, "/records/1", "Bearer "+readerToken[:strings.LastIndex(readerToken, ".")+1]+"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", http.StatusUnauthorized, "invalid_api_key"},
		{"reader denied write", http.MethodPost, "/records", "Bearer "+readerToken, http.StatusForbidden, "permission_denied"},
		{"reader may read", http.MethodGet, "/records/1", "Bearer "+readerToken, http.StatusNoContent, ""},
		{"writer may create", http.MethodPost, "/records", "Bearer "+writerToken, http.StatusNoContent, ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(test.method, test.path, nil)
			if test.authorization != "" {
				req.Header.Set("Authorization", test.authorization)
			}
			res := httptest.NewRecorder()
			handler.ServeHTTP(res, req)
			if res.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d: %s", res.Code, test.wantStatus, res.Body)
			}
			if test.wantCode != "" && !strings.Contains(res.Body.String(), test.wantCode) {
				t.Fatalf("body = %q, want error code %q", res.Body.String(), test.wantCode)
			}
		})
	}
}

func TestHealthIsPublicAndUnknownPathsRemainUnprotected(t *testing.T) {
	store := newMemoryKeyStore()
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	handler := Middleware(store, next)
	for _, path := range []string{"/healthz", "/unmatched"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code != http.StatusNoContent {
			t.Errorf("%s status = %d, want %d", path, res.Code, http.StatusNoContent)
		}
	}
}

func TestRevokedKeyIsRejected(t *testing.T) {
	store := newMemoryKeyStore()
	manager := NewKeyManager(store)
	metadata, token, err := manager.Create(context.Background(), "temporary", RoleReader, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Revoke(context.Background(), metadata.ID, nil); err != nil {
		t.Fatal(err)
	}
	handler := Middleware(store, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodGet, "/records/1", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusUnauthorized || !strings.Contains(res.Body.String(), "invalid_api_key") {
		t.Fatalf("revoked-key response = %d %q", res.Code, res.Body.String())
	}
}

func TestAdminHandlerProvisioningResponseNeverListsSecretsOrHashes(t *testing.T) {
	store := newMemoryKeyStore()
	manager := NewKeyManager(store)
	admin, _, err := manager.Create(context.Background(), "admin", RoleAdmin, nil)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewKeyHandler(manager)
	req := httptest.NewRequest(http.MethodPost, "/api-keys", strings.NewReader(`{"name":"new reader","role":"reader"}`))
	req = req.WithContext(context.WithValue(req.Context(), principalContextKey{}, Principal{KeyID: admin.ID, Role: RoleAdmin}))
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusCreated || res.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("create response = %d headers=%v body=%s", res.Code, res.Header(), res.Body)
	}
	var created struct {
		APIKey string `json:"api_key"`
		ID     int64  `json:"id"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.APIKey == "" || created.ID == 0 {
		t.Fatalf("provisioning response omitted one-time key or metadata: %+v", created)
	}
	listReq := httptest.NewRequest(http.MethodGet, "/api-keys", nil)
	listReq = listReq.WithContext(context.WithValue(listReq.Context(), principalContextKey{}, Principal{KeyID: admin.ID, Role: RoleAdmin}))
	listRes := httptest.NewRecorder()
	handler.ServeHTTP(listRes, listReq)
	if strings.Contains(listRes.Body.String(), created.APIKey) || strings.Contains(listRes.Body.String(), "key_hash") {
		t.Fatalf("API key list exposed credential material: %s", listRes.Body.String())
	}

	patchReq := httptest.NewRequest(http.MethodPatch, fmt.Sprintf("/api-keys/%d/role", created.ID), strings.NewReader(`{"role":"writer"}`))
	patchReq = patchReq.WithContext(context.WithValue(patchReq.Context(), principalContextKey{}, Principal{KeyID: admin.ID, Role: RoleAdmin}))
	patchRes := httptest.NewRecorder()
	handler.ServeHTTP(patchRes, patchReq)
	if patchRes.Code != http.StatusOK || !strings.Contains(patchRes.Body.String(), `"role":"writer"`) {
		t.Fatalf("role update response = %d %q", patchRes.Code, patchRes.Body.String())
	}

	deleteReq := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/api-keys/%d", created.ID), nil)
	deleteReq = deleteReq.WithContext(context.WithValue(deleteReq.Context(), principalContextKey{}, Principal{KeyID: admin.ID, Role: RoleAdmin}))
	deleteRes := httptest.NewRecorder()
	handler.ServeHTTP(deleteRes, deleteReq)
	if deleteRes.Code != http.StatusOK || !strings.Contains(deleteRes.Body.String(), `"revoked_at"`) {
		t.Fatalf("revoke response = %d %q", deleteRes.Code, deleteRes.Body.String())
	}
}


func TestMiddlewareEnforcesExpiryBoundaryAndNullExpiry(t *testing.T) {
	now := time.Date(2032, 4, 5, 6, 7, 8, 0, time.UTC)
	cases := []struct {
		name string
		expiry *time.Time
		revoked bool
		want int
	}{
		{name: "non-expiring existing key", want: http.StatusNoContent},
		{name: "not expired", expiry: ptrTime(now.Add(time.Nanosecond)), want: http.StatusNoContent},
		{name: "future expiry", expiry: ptrTime(now.Add(time.Second)), want: http.StatusNoContent},
		{name: "expiry reached", expiry: ptrTime(now), want: http.StatusUnauthorized},
		{name: "expired in past", expiry: ptrTime(now.Add(-time.Second)), want: http.StatusUnauthorized},
		{name: "revoked and expired", expiry: ptrTime(now.Add(-time.Second)), revoked: true, want: http.StatusUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := newMemoryKeyStore()
			manager := NewKeyManager(store)
			metadata, token, err := manager.Create(context.Background(), "expiry-test", RoleReader, nil)
			if err != nil { t.Fatal(err) }
			publicID, _, ok := parseToken(token)
			if !ok { t.Fatal("generated token did not parse") }
			store.mu.Lock()
			credential := store.credentials[publicID]
			credential.ExpiresAt = tc.expiry
			store.credentials[publicID] = credential
			meta := store.metadata[metadata.ID]
			meta.ExpiresAt = tc.expiry
			store.metadata[metadata.ID] = meta
			store.mu.Unlock()
			if tc.revoked {
				if _, err := manager.Revoke(context.Background(), metadata.ID, nil); err != nil { t.Fatal(err) }
			}
			calls := 0
			handler := middlewareWithClock(store, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls++
				w.WriteHeader(http.StatusNoContent)
			}), nil, func() time.Time { return now })
			req := httptest.NewRequest(http.MethodGet, "/records/1", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			res := httptest.NewRecorder()
			handler.ServeHTTP(res, req)
			if res.Code != tc.want { t.Fatalf("status=%d want=%d body=%s", res.Code, tc.want, res.Body) }
			if (tc.want == http.StatusNoContent) != (calls == 1) { t.Fatalf("protected handler calls=%d", calls) }
		})
	}
}

func ptrTime(value time.Time) *time.Time { return &value }

func TestKeyManagerRejectsNonFutureExpiryAndUsesUTC(t *testing.T) {
	store := newMemoryKeyStore()
	manager := NewKeyManager(store)
	now := time.Date(2034, 1, 2, 3, 4, 5, 0, time.UTC)
	manager.now = func() time.Time { return now }
	for _, expiry := range []time.Time{now, now.Add(-time.Second)} {
		if _, _, err := manager.CreateWithExpiry(context.Background(), "bad-expiry", RoleReader, &expiry, nil); !errors.Is(err, ErrInvalidExpiry) {
			t.Fatalf("CreateWithExpiry(%s) error=%v want ErrInvalidExpiry", expiry, err)
		}
	}
	future := now.Add(time.Hour).In(time.FixedZone("offset", -7*60*60))
	metadata, _, err := manager.CreateWithExpiry(context.Background(), "future-expiry", RoleReader, &future, nil)
	if err != nil { t.Fatal(err) }
	if metadata.ExpiresAt == nil || metadata.ExpiresAt.Location() != time.UTC || !metadata.ExpiresAt.Equal(future) {
		t.Fatalf("expiry metadata not normalized to UTC: %+v", metadata.ExpiresAt)
	}
}
