package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/otisjosh/Joseph-Otitigbe/internal/audit"
	"github.com/otisjosh/Joseph-Otitigbe/internal/auth"
)

func createKeyAuditDetails(role auth.Role, expiresAt *time.Time) map[string]string {
	details := map[string]string{"role": string(role)}
	if expiresAt != nil {
		details["expires_at"] = expiresAt.UTC().Format(time.RFC3339Nano)
	}
	return details
}

type KeyStore struct {
	pool *pgxpool.Pool
}

func NewKeyStore(pool *pgxpool.Pool) *KeyStore {
	return &KeyStore{pool: pool}
}

func (s *KeyStore) AuditStore() *AuditStore { return NewAuditStore(s.pool) }

type rowScanner interface {
	Scan(dest ...any) error
}

func scanKeyMetadata(row rowScanner) (auth.KeyMetadata, error) {
	var metadata auth.KeyMetadata
	var createdBy, revokedBy, roleChangedBy pgtype.Int8
	var revokedAt, lastUsedAt, roleChangedAt, expiresAt pgtype.Timestamptz
	err := row.Scan(
		&metadata.ID, &metadata.PublicID, &metadata.Name, &metadata.Role, &metadata.CreatedAt,
		&createdBy, &revokedAt, &revokedBy, &lastUsedAt, &roleChangedAt, &roleChangedBy, &expiresAt,
	)
	if err != nil {
		return auth.KeyMetadata{}, err
	}
	if createdBy.Valid {
		metadata.CreatedByKeyID = &createdBy.Int64
	}
	if revokedBy.Valid {
		metadata.RevokedByKeyID = &revokedBy.Int64
	}
	if roleChangedBy.Valid {
		metadata.RoleChangedByKeyID = &roleChangedBy.Int64
	}
	if revokedAt.Valid {
		value := revokedAt.Time
		metadata.RevokedAt = &value
	}
	if lastUsedAt.Valid {
		value := lastUsedAt.Time
		metadata.LastUsedAt = &value
	}
	if roleChangedAt.Valid {
		value := roleChangedAt.Time.UTC()
		metadata.RoleChangedAt = &value
	}
	if expiresAt.Valid {
		value := expiresAt.Time.UTC()
		metadata.ExpiresAt = &value
	}
	return metadata, nil
}

const keyMetadataColumns = `id, public_id, name, role_name, created_at,
	created_by_key_id, revoked_at, revoked_by_key_id, last_used_at,
	role_changed_at, role_changed_by_key_id, expires_at`

func (s *KeyStore) CreateKey(ctx context.Context, name string, role auth.Role, publicID string, hash []byte, createdBy *int64) (auth.KeyMetadata, error) {
	return s.CreateKeyWithExpiry(ctx, name, role, publicID, hash, nil, createdBy)
}

func (s *KeyStore) CreateKeyWithExpiry(ctx context.Context, name string, role auth.Role, publicID string, hash []byte, expiresAt *time.Time, createdBy *int64) (auth.KeyMetadata, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return auth.KeyMetadata{}, fmt.Errorf("%w: %v", auth.ErrKeyStorageUnavailable, err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	query := `INSERT INTO atlas_api_keys (name, role_name, public_id, key_hash, created_by_key_id, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6) RETURNING ` + keyMetadataColumns
	metadata, err := scanKeyMetadata(tx.QueryRow(ctx, query, name, string(role), publicID, hash, createdBy, expiresAt))
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && (pgErr.Code == "23503" || pgErr.Code == "23514") {
			return auth.KeyMetadata{}, auth.ErrInvalidRole
		}
		return auth.KeyMetadata{}, fmt.Errorf("%w: %v", auth.ErrKeyStorageUnavailable, err)
	}
	if err := insertAuditEvent(ctx, tx, audit.Event{ActorKeyID: createdBy, Action: "api_key.created", ResourceType: "api_key", ResourceID: &metadata.ID, Details: createKeyAuditDetails(role, expiresAt)}); err != nil {
		return auth.KeyMetadata{}, fmt.Errorf("%w: %v", auth.ErrKeyStorageUnavailable, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return auth.KeyMetadata{}, fmt.Errorf("%w: %v", auth.ErrKeyStorageUnavailable, err)
	}
	return metadata, nil
}

func (s *KeyStore) LookupKey(ctx context.Context, publicID string) (auth.Credential, error) {
	const query = `SELECT k.id, k.public_id, k.key_hash, k.role_name, r.permissions, k.expires_at
		FROM atlas_api_keys AS k JOIN atlas_roles AS r ON r.role_name = k.role_name
		WHERE k.public_id = $1 AND k.revoked_at IS NULL
		AND (k.expires_at IS NULL OR k.expires_at > now())`
	var credential auth.Credential
	var permissions []string
	err := s.pool.QueryRow(ctx, query, publicID).Scan(&credential.ID, &credential.PublicID, &credential.Hash, &credential.Role, &permissions, &credential.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return auth.Credential{}, auth.ErrInvalidKey
	}
	if err != nil {
		return auth.Credential{}, fmt.Errorf("%w: %v", auth.ErrKeyStorageUnavailable, err)
	}
	if credential.ExpiresAt != nil {
		value := credential.ExpiresAt.UTC()
		credential.ExpiresAt = &value
	}
	credential.Permissions = make([]auth.Permission, len(permissions))
	for i, permission := range permissions {
		credential.Permissions[i] = auth.Permission(permission)
	}
	return credential, nil
}

func (s *KeyStore) TouchKey(ctx context.Context, id int64) error {
	tag, err := s.pool.Exec(ctx, `UPDATE atlas_api_keys SET last_used_at = now()
		WHERE id = $1 AND revoked_at IS NULL
		AND (expires_at IS NULL OR expires_at > now())`, id)
	if err != nil {
		return fmt.Errorf("%w: %v", auth.ErrKeyStorageUnavailable, err)
	}
	if tag.RowsAffected() == 0 {
		return auth.ErrInvalidKey
	}
	return nil
}

func (s *KeyStore) ListKeys(ctx context.Context) ([]auth.KeyMetadata, error) {
	rows, err := s.pool.Query(ctx, "SELECT "+keyMetadataColumns+" FROM atlas_api_keys ORDER BY id")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", auth.ErrKeyStorageUnavailable, err)
	}
	defer rows.Close()
	keys := make([]auth.KeyMetadata, 0)
	for rows.Next() {
		metadata, err := scanKeyMetadata(rows)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", auth.ErrKeyStorageUnavailable, err)
		}
		keys = append(keys, metadata)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: %v", auth.ErrKeyStorageUnavailable, err)
	}
	return keys, nil
}

const adminMutationLockID int64 = 0x41544c4153

func lockAdminMutations(ctx context.Context, tx pgx.Tx) error {
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", adminMutationLockID); err != nil {
		return fmt.Errorf("%w: %v", auth.ErrKeyStorageUnavailable, err)
	}
	return nil
}

func activeKeyRole(ctx context.Context, tx pgx.Tx, id int64) (auth.Role, error) {
	var role auth.Role
	err := tx.QueryRow(ctx, `SELECT role_name FROM atlas_api_keys
		WHERE id = $1 AND revoked_at IS NULL FOR UPDATE`, id).Scan(&role)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", auth.ErrKeyNotFound
	}
	if err != nil {
		return "", fmt.Errorf("%w: %v", auth.ErrKeyStorageUnavailable, err)
	}
	return role, nil
}

func ensureAnotherAdmin(ctx context.Context, tx pgx.Tx) error {
	var count int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM atlas_api_keys
		WHERE role_name = $1 AND revoked_at IS NULL`, string(auth.RoleAdmin)).Scan(&count); err != nil {
		return fmt.Errorf("%w: %v", auth.ErrKeyStorageUnavailable, err)
	}
	if count <= 1 {
		return auth.ErrLastAdmin
	}
	return nil
}

func (s *KeyStore) RevokeKey(ctx context.Context, id int64, actor *int64) (auth.KeyMetadata, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return auth.KeyMetadata{}, fmt.Errorf("%w: %v", auth.ErrKeyStorageUnavailable, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := lockAdminMutations(ctx, tx); err != nil {
		return auth.KeyMetadata{}, err
	}
	role, err := activeKeyRole(ctx, tx, id)
	if err != nil {
		return auth.KeyMetadata{}, err
	}
	if role == auth.RoleAdmin {
		if err := ensureAnotherAdmin(ctx, tx); err != nil {
			return auth.KeyMetadata{}, err
		}
	}
	query := `UPDATE atlas_api_keys SET revoked_at = now(), revoked_by_key_id = $2
		WHERE id = $1 AND revoked_at IS NULL RETURNING ` + keyMetadataColumns
	metadata, err := scanKeyMetadata(tx.QueryRow(ctx, query, id, actor))
	if err != nil {
		return auth.KeyMetadata{}, fmt.Errorf("%w: %v", auth.ErrKeyStorageUnavailable, err)
	}
	if err := insertAuditEvent(ctx, tx, audit.Event{ActorKeyID: actor, Action: "api_key.revoked", ResourceType: "api_key", ResourceID: &metadata.ID}); err != nil {
		return auth.KeyMetadata{}, fmt.Errorf("%w: %v", auth.ErrKeyStorageUnavailable, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return auth.KeyMetadata{}, fmt.Errorf("%w: %v", auth.ErrKeyStorageUnavailable, err)
	}
	return metadata, nil
}

func (s *KeyStore) ChangeKeyRole(ctx context.Context, id int64, role auth.Role, actor *int64) (auth.KeyMetadata, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return auth.KeyMetadata{}, fmt.Errorf("%w: %v", auth.ErrKeyStorageUnavailable, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := lockAdminMutations(ctx, tx); err != nil {
		return auth.KeyMetadata{}, err
	}
	currentRole, err := activeKeyRole(ctx, tx, id)
	if err != nil {
		return auth.KeyMetadata{}, err
	}
	if currentRole == auth.RoleAdmin && role != auth.RoleAdmin {
		if err := ensureAnotherAdmin(ctx, tx); err != nil {
			return auth.KeyMetadata{}, err
		}
	}
	query := `UPDATE atlas_api_keys SET role_name = $2, role_changed_at = now(), role_changed_by_key_id = $3
		WHERE id = $1 AND revoked_at IS NULL RETURNING ` + keyMetadataColumns
	metadata, err := scanKeyMetadata(tx.QueryRow(ctx, query, id, string(role), actor))
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23503" {
			return auth.KeyMetadata{}, auth.ErrInvalidRole
		}
		return auth.KeyMetadata{}, fmt.Errorf("%w: %v", auth.ErrKeyStorageUnavailable, err)
	}
	if err := insertAuditEvent(ctx, tx, audit.Event{ActorKeyID: actor, Action: "api_key.role_changed", ResourceType: "api_key", ResourceID: &metadata.ID, Details: map[string]string{"role": string(role)}}); err != nil {
		return auth.KeyMetadata{}, fmt.Errorf("%w: %v", auth.ErrKeyStorageUnavailable, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return auth.KeyMetadata{}, fmt.Errorf("%w: %v", auth.ErrKeyStorageUnavailable, err)
	}
	return metadata, nil
}

func (s *KeyStore) ListRoles(ctx context.Context) ([]auth.RoleInfo, error) {
	rows, err := s.pool.Query(ctx, `SELECT role_name, description, permissions FROM atlas_roles ORDER BY role_name`)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", auth.ErrKeyStorageUnavailable, err)
	}
	defer rows.Close()
	roles := make([]auth.RoleInfo, 0)
	for rows.Next() {
		var role auth.RoleInfo
		var permissions []string
		if err := rows.Scan(&role.Name, &role.Description, &permissions); err != nil {
			return nil, fmt.Errorf("%w: %v", auth.ErrKeyStorageUnavailable, err)
		}
		role.Permissions = make([]auth.Permission, len(permissions))
		for i, permission := range permissions {
			role.Permissions[i] = auth.Permission(permission)
		}
		roles = append(roles, role)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: %v", auth.ErrKeyStorageUnavailable, err)
	}
	return roles, nil
}
