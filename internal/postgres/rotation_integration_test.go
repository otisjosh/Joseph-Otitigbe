package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/otisjosh/Joseph-Otitigbe/internal/audit"
	"github.com/otisjosh/Joseph-Otitigbe/internal/auth"
)

func TestAPIKeyRotationIsAtomicPreservesMetadataAndAudits(t *testing.T) {
	pool := isolatedAuthPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	store := NewKeyStore(pool)
	manager := auth.NewKeyManager(store)
	admin, adminToken, err := manager.Create(ctx, fmt.Sprintf("rotation-admin-%d", time.Now().UnixNano()), auth.RoleAdmin, nil)
	if err != nil { t.Fatalf("create admin: %v", err) }
	expiry := time.Now().UTC().Add(2*time.Hour).Truncate(time.Microsecond)
	old, oldToken, err := manager.CreateWithExpiry(ctx, fmt.Sprintf("rotation-source-%d", time.Now().UnixNano()), auth.RoleWriter, &expiry, &admin.ID)
	if err != nil { t.Fatalf("create source key: %v", err) }

	replacement, newToken, err := manager.Rotate(ctx, old.ID, nil, nil, &admin.ID)
	if err != nil { t.Fatalf("Rotate(): %v", err) }
	if replacement.Role != auth.RoleWriter || replacement.Name != old.Name || replacement.ExpiresAt == nil || !replacement.ExpiresAt.Equal(expiry) {
		t.Fatalf("replacement did not preserve role/name/expiry: %+v", replacement)
	}
	if _, err := store.LookupKey(ctx, old.PublicID); !errors.Is(err, auth.ErrInvalidKey) {
		t.Fatalf("old key lookup after rotation = %v, want ErrInvalidKey", err)
	}
	pieces := strings.Split(strings.TrimPrefix(newToken, "atlas_"), ".")
	if len(pieces) != 2 { t.Fatalf("replacement token format invalid: %q", newToken) }
	if _, err := store.LookupKey(ctx, pieces[0]); err != nil { t.Fatalf("replacement key lookup: %v", err) }

	handler := auth.Middleware(store, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	for _, tc := range []struct{name, token string; want int}{{"old key", oldToken, http.StatusUnauthorized}, {"replacement", newToken, http.StatusNoContent}} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/records/1", nil)
			req.Header.Set("Authorization", "Bearer "+tc.token)
			res := httptest.NewRecorder()
			handler.ServeHTTP(res, req)
			if res.Code != tc.want { t.Fatalf("status=%d want=%d body=%s", res.Code, tc.want, res.Body) }
		})
	}

	events, err := NewAuditStore(pool).ListEvents(ctx, 100, 0)
	if err != nil { t.Fatalf("ListEvents(): %v", err) }
	found := false
	for _, event := range events {
		if event.Action == "api_key.rotated" && event.ResourceID != nil && *event.ResourceID == old.ID {
			found = event.ActorKeyID != nil && *event.ActorKeyID == admin.ID &&
				event.Details["replacement_key_id"] == fmt.Sprintf("%d", replacement.ID) &&
				event.Details["role"] == string(auth.RoleWriter) &&
				event.Details["expires_at"] == expiry.Format(time.RFC3339Nano)
		}
	}
	if !found { t.Fatal("rotation audit event missing or incomplete") }
	encoded, err := json.Marshal(events)
	if err != nil { t.Fatal(err) }
	if strings.Contains(string(encoded), oldToken) || strings.Contains(string(encoded), newToken) || strings.Contains(string(encoded), "key_hash") {
		t.Fatalf("audit output exposed credentials: %s", encoded)
	}
	_ = adminToken
}

func TestAPIKeyRotationCanExplicitlyChangeRoleAndExpiry(t *testing.T) {
	pool := isolatedAuthPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	manager := auth.NewKeyManager(NewKeyStore(pool))
	admin, _, err := manager.Create(ctx, fmt.Sprintf("rotation-override-admin-%d", time.Now().UnixNano()), auth.RoleAdmin, nil)
	if err != nil { t.Fatal(err) }
	oldExpiry := time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond)
	old, _, err := manager.CreateWithExpiry(ctx, fmt.Sprintf("rotation-override-%d", time.Now().UnixNano()), auth.RoleWriter, &oldExpiry, &admin.ID)
	if err != nil { t.Fatal(err) }
	role := auth.RoleReader
	newExpiry := time.Now().UTC().Add(30*time.Minute).Truncate(time.Microsecond)
	replacement, _, err := manager.Rotate(ctx, old.ID, &role, &newExpiry, &admin.ID)
	if err != nil { t.Fatalf("Rotate() with explicit replacement metadata: %v", err) }
	if replacement.Role != role || replacement.ExpiresAt == nil || !replacement.ExpiresAt.Equal(newExpiry) {
		t.Fatalf("replacement metadata = %+v", replacement)
	}
}

func TestAPIKeyRotationRejectsExpiredRevokedAndLastAdminDowngrade(t *testing.T) {
	pool := isolatedAuthPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	store := NewKeyStore(pool)
	manager := auth.NewKeyManager(store)
	admin, _, err := manager.Create(ctx, fmt.Sprintf("rotation-last-admin-%d", time.Now().UnixNano()), auth.RoleAdmin, nil)
	if err != nil { t.Fatal(err) }

	writer, _, err := manager.Create(ctx, fmt.Sprintf("rotation-writer-%d", time.Now().UnixNano()), auth.RoleWriter, &admin.ID)
	if err != nil { t.Fatal(err) }
	downgrade := auth.RoleWriter
	if _, _, err := manager.Rotate(ctx, admin.ID, &downgrade, nil, nil); !errors.Is(err, auth.ErrLastAdmin) {
		t.Fatalf("last-admin downgrade rotation error = %v, want ErrLastAdmin", err)
	}
	if _, err := store.LookupKey(ctx, admin.PublicID); err != nil {
		t.Fatalf("last admin was invalidated after denied rotation: %v", err)
	}
	if _, _, err := manager.Rotate(ctx, 99999999, nil, nil, nil); !errors.Is(err, auth.ErrKeyNotFound) {
		t.Fatalf("unknown key rotation error = %v, want ErrKeyNotFound", err)
	}

	future := time.Now().UTC().Add(time.Hour)
	expired, _, err := manager.CreateWithExpiry(ctx, fmt.Sprintf("rotation-expired-%d", time.Now().UnixNano()), auth.RoleReader, &future, &admin.ID)
	if err != nil { t.Fatal(err) }
	if _, err := pool.Exec(ctx, "UPDATE atlas_api_keys SET expires_at = $1 WHERE id = $2", time.Now().UTC().Add(-time.Minute), expired.ID); err != nil { t.Fatal(err) }
	if _, _, err := manager.Rotate(ctx, expired.ID, nil, nil, &admin.ID); !errors.Is(err, auth.ErrKeyNotFound) {
		t.Fatalf("expired key rotation error = %v, want ErrKeyNotFound", err)
	}

	revoked, _, err := manager.Create(ctx, fmt.Sprintf("rotation-revoked-%d", time.Now().UnixNano()), auth.RoleReader, &admin.ID)
	if err != nil { t.Fatal(err) }
	if _, err := manager.Revoke(ctx, revoked.ID, &admin.ID); err != nil { t.Fatal(err) }
	if _, _, err := manager.Rotate(ctx, revoked.ID, nil, nil, &admin.ID); !errors.Is(err, auth.ErrKeyNotFound) {
		t.Fatalf("revoked key rotation error = %v, want ErrKeyNotFound", err)
	}
	_ = writer
}

func TestAPIKeyRotationAuditFailureRollsBackBothKeys(t *testing.T) {
	pool := isolatedAuthPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	store := NewKeyStore(pool)
	manager := auth.NewKeyManager(store)
	admin, _, err := manager.Create(ctx, fmt.Sprintf("rotation-rollback-admin-%d", time.Now().UnixNano()), auth.RoleAdmin, nil)
	if err != nil { t.Fatal(err) }
	old, _, err := manager.Create(ctx, fmt.Sprintf("rotation-rollback-source-%d", time.Now().UnixNano()), auth.RoleWriter, &admin.ID)
	if err != nil { t.Fatal(err) }

	installRejectAuditTrigger(t, pool)
	metadata, token, err := manager.Rotate(ctx, old.ID, nil, nil, &admin.ID)
	if !errors.Is(err, auth.ErrKeyStorageUnavailable) {
		t.Fatalf("Rotate() with audit failure error = %v, want ErrKeyStorageUnavailable", err)
	}
	if metadata.ID != 0 || token != "" { t.Fatal("failed rotation returned replacement metadata or secret") }
	if _, err := store.LookupKey(ctx, old.PublicID); err != nil {
		t.Fatalf("source key was revoked despite audit failure: %v", err)
	}
	var count int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM atlas_api_keys WHERE name = $1", old.Name).Scan(&count); err != nil { t.Fatal(err) }
	if count != 1 { t.Fatalf("key rows after audit failure = %d, want original only", count) }
	var rotations int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM atlas_audit_events WHERE action = $1", "api_key.rotated").Scan(&rotations); err != nil { t.Fatal(err) }
	if rotations != 0 { t.Fatalf("rotation audit rows after failed transaction = %d", rotations) }
}

// Keep this import use explicit: rotation audit data is represented by the shared audit event contract.
var _ audit.Event
