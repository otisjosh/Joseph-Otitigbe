package postgres

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/otisjosh/Joseph-Otitigbe/internal/auth"
	"github.com/otisjosh/Joseph-Otitigbe/internal/records"
)

func installRejectAuditTrigger(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := pool.Exec(ctx, `CREATE FUNCTION reject_audit_insert() RETURNS trigger
		LANGUAGE plpgsql AS $body$
		BEGIN
			RAISE EXCEPTION 'forced audit insert failure';
		END;
		$body$`)
	if err != nil {
		t.Fatalf("create audit failure function: %v", err)
	}
	_, err = pool.Exec(ctx, `CREATE TRIGGER reject_audit_insert
		BEFORE INSERT ON atlas_audit_events
		FOR EACH ROW EXECUTE FUNCTION reject_audit_insert()`)
	if err != nil {
		t.Fatalf("create audit failure trigger: %v", err)
	}
}

func TestAuditWriteFailureRollsBackRecordAndAPIKeyChanges(t *testing.T) {
	pool := isolatedAuthPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	manager := auth.NewKeyManager(NewKeyStore(pool))
	admin, _, err := manager.Create(ctx, fmt.Sprintf("rollback-admin-%d", time.Now().UnixNano()), auth.RoleAdmin, nil)
	if err != nil {
		t.Fatalf("create admin: %v", err)
	}
	target, _, err := manager.Create(ctx, fmt.Sprintf("rollback-target-%d", time.Now().UnixNano()), auth.RoleWriter, &admin.ID)
	if err != nil {
		t.Fatalf("create target key: %v", err)
	}

	installRejectAuditTrigger(t, pool)

	email := fmt.Sprintf("rollback-%d@example.test", time.Now().UnixNano())
	principalCtx := auth.ContextWithPrincipal(ctx, auth.Principal{KeyID: admin.ID, Role: auth.RoleAdmin})
	if _, err := NewStore(pool).Create(principalCtx, "Rollback record", email); !errors.Is(err, records.ErrUnavailable) {
		t.Fatalf("record Create() error = %v, want records.ErrUnavailable", err)
	}
	var recordsCreated int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM atlas_records WHERE email = $1", email).Scan(&recordsCreated); err != nil {
		t.Fatalf("count rolled-back record: %v", err)
	}
	if recordsCreated != 0 {
		t.Fatalf("records persisted after audit failure = %d, want 0", recordsCreated)
	}

	if _, err := manager.ChangeRole(ctx, target.ID, auth.RoleReader, &admin.ID); !errors.Is(err, auth.ErrKeyStorageUnavailable) {
		t.Fatalf("ChangeRole() error = %v, want auth.ErrKeyStorageUnavailable", err)
	}
	credential, err := NewKeyStore(pool).LookupKey(ctx, target.PublicID)
	if err != nil {
		t.Fatalf("LookupKey() after failed role change: %v", err)
	}
	if credential.Role != auth.RoleWriter {
		t.Fatalf("role after audit failure = %q, want writer", credential.Role)
	}

	if _, err := manager.Revoke(ctx, target.ID, &admin.ID); !errors.Is(err, auth.ErrKeyStorageUnavailable) {
		t.Fatalf("Revoke() error = %v, want auth.ErrKeyStorageUnavailable", err)
	}
	var revoked bool
	if err := pool.QueryRow(ctx, "SELECT revoked_at IS NOT NULL FROM atlas_api_keys WHERE id = $1", target.ID).Scan(&revoked); err != nil {
		t.Fatalf("read revocation state: %v", err)
	}
	if revoked {
		t.Fatal("key was revoked even though its audit event failed")
	}

	name := fmt.Sprintf("rollback-create-%d", time.Now().UnixNano())
	if _, _, err := manager.Create(ctx, name, auth.RoleReader, &admin.ID); !errors.Is(err, auth.ErrKeyStorageUnavailable) {
		t.Fatalf("CreateKey() error = %v, want auth.ErrKeyStorageUnavailable", err)
	}
	var keysCreated int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM atlas_api_keys WHERE name = $1", name).Scan(&keysCreated); err != nil {
		t.Fatalf("count rolled-back key: %v", err)
	}
	if keysCreated != 0 {
		t.Fatalf("API keys persisted after audit failure = %d, want 0", keysCreated)
	}
}
