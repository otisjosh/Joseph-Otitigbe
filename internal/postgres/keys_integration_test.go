package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/otisjosh/Joseph-Otitigbe/internal/auth"
	"github.com/otisjosh/Joseph-Otitigbe/internal/records"
)

func TestAPIKeyPersistenceRolesAndRevocation(t *testing.T) {
	pool, _ := integrationPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	store := NewKeyStore(pool)
	manager := auth.NewKeyManager(store)
	name := fmt.Sprintf("integration-key-%d", time.Now().UnixNano())
	metadata, token, err := manager.Create(ctx, name, auth.RoleWriter, nil)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if !strings.HasPrefix(token, "atlas_") {
		t.Fatal("provisioned key has unexpected prefix")
	}
	pieces := strings.Split(strings.TrimPrefix(token, "atlas_"), ".")
	if len(pieces) != 2 {
		t.Fatal("provisioned key format is invalid")
	}
	secret, err := base64.RawURLEncoding.DecodeString(pieces[1])
	if err != nil {
		t.Fatalf("decode provisioned secret: %v", err)
	}
	hash := sha256.Sum256(secret)
	clear(secret)

	credential, err := store.LookupKey(ctx, pieces[0])
	if err != nil {
		t.Fatalf("LookupKey() error = %v", err)
	}
	if string(credential.Hash) != string(hash[:]) || credential.Role != auth.RoleWriter {
		t.Fatal("persisted credential hash or role does not match")
	}
	if len(credential.Permissions) != 2 || credential.Permissions[0] != auth.PermissionRecordsRead {
		t.Fatalf("writer permissions = %v", credential.Permissions)
	}
	recordStore := NewStore(pool)
	record, err := recordStore.Create(ctx, "Auth integration", fmt.Sprintf("auth-%d@example.test", time.Now().UnixNano()))
	if err != nil {
		t.Fatalf("create record for authenticated API check: %v", err)
	}
	handler := auth.Middleware(store, records.NewHandler(recordStore))
	getReq := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/records/%d", record.ID), nil)
	getReq.Header.Set("Authorization", "Bearer "+token)
	getRes := httptest.NewRecorder()
	handler.ServeHTTP(getRes, getReq)
	if getRes.Code != http.StatusOK {
		t.Fatalf("writer GET status = %d, want 200: %s", getRes.Code, getRes.Body)
	}
	_, readerToken, err := manager.Create(ctx, fmt.Sprintf("reader-%d", time.Now().UnixNano()), auth.RoleReader, nil)
	if err != nil {
		t.Fatalf("create reader key: %v", err)
	}
	postBody := strings.NewReader(`{"name":"Denied","email":"denied@example.test"}`)
	postReq := httptest.NewRequest(http.MethodPost, "/records", postBody)
	postReq.Header.Set("Authorization", "Bearer "+readerToken)
	postRes := httptest.NewRecorder()
	handler.ServeHTTP(postRes, postReq)
	if postRes.Code != http.StatusForbidden || !strings.Contains(postRes.Body.String(), "permission_denied") {
		t.Fatalf("reader POST response = %d %q, want 403 permission_denied", postRes.Code, postRes.Body.String())
	}

	if err := store.TouchKey(ctx, metadata.ID); err != nil {
		t.Fatalf("TouchKey() error = %v", err)
	}

	listed, err := manager.List(ctx)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	var listedKey *auth.KeyMetadata
	for i := range listed {
		if listed[i].ID == metadata.ID {
			listedKey = &listed[i]
		}
	}
	if listedKey == nil || listedKey.LastUsedAt == nil || listedKey.Name != name {
		t.Fatalf("list did not return safe key metadata")
	}
	encoded, err := json.Marshal(listedKey)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), token) || strings.Contains(string(encoded), "key_hash") {
		t.Fatalf("key metadata leaked key material: %s", encoded)
	}
	var storedHash []byte
	if err := pool.QueryRow(ctx, "SELECT key_hash FROM atlas_api_keys WHERE id = $1", metadata.ID).Scan(&storedHash); err != nil {
		t.Fatalf("read stored hash: %v", err)
	}
	if len(storedHash) != sha256.Size || string(storedHash) != string(hash[:]) {
		t.Fatal("database did not store the SHA-256 key hash")
	}

	changed, err := manager.ChangeRole(ctx, metadata.ID, auth.RoleReader, nil)
	if err != nil {
		t.Fatalf("ChangeRole() error = %v", err)
	}
	if changed.Role != auth.RoleReader || changed.RoleChangedAt == nil {
		t.Fatalf("role change metadata = %+v", changed)
	}
	if _, _, err := manager.Create(ctx, "invalid-role", auth.Role("root"), nil); !errors.Is(err, auth.ErrInvalidRole) {
		t.Fatalf("Create() invalid role error = %v, want ErrInvalidRole", err)
	}

	if _, err := manager.Revoke(ctx, metadata.ID, nil); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	if _, err := store.LookupKey(ctx, pieces[0]); !errors.Is(err, auth.ErrInvalidKey) {
		t.Fatalf("LookupKey() after revoke = %v, want ErrInvalidKey", err)
	}
}

func TestKeyStoreDatabaseFailuresAreReturned(t *testing.T) {
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DATABASE_URL is not set; PostgreSQL integration test skipped")
	}
	pool, err := pgxpool.New(context.Background(), databaseURL)
	if err != nil {
		t.Fatalf("create pool for failure test: %v", err)
	}
	pool.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := NewKeyStore(pool).LookupKey(ctx, "public-selector"); !errors.Is(err, auth.ErrKeyStorageUnavailable) {
		t.Fatalf("LookupKey() error = %v, want ErrKeyStorageUnavailable", err)
	}
}
