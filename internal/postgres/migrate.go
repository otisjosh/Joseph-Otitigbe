package postgres

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

type migration struct {
	version int64
	up      string
}

var migrations = []migration{
	{version: 1, up: "migrations/000001_create_records.up.sql"},
	{version: 2, up: "migrations/000002_unique_normalized_email.up.sql"},
	{version: 3, up: "migrations/000003_create_roles.up.sql"},
	{version: 4, up: "migrations/000004_seed_roles.up.sql"},
	{version: 5, up: "migrations/000005_create_api_keys.up.sql"},
	{version: 6, up: "migrations/000006_index_api_keys.up.sql"},
	{version: 7, up: "migrations/000007_create_audit_events.up.sql"},
	{version: 8, up: "migrations/000008_add_api_key_expires_at.up.sql"},
}

func RunMigrations(ctx context.Context, pool *pgxpool.Pool) error {
	if err := pool.Ping(ctx); err != nil {
		return fmt.Errorf("ping database before migrations: %w", err)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin migration transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(731246801)`); err != nil {
		return fmt.Errorf("lock migrations: %w", err)
	}
	if _, err := tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS atlas_schema_migrations (
		version bigint PRIMARY KEY,
		applied_at timestamptz NOT NULL DEFAULT now()
	)`); err != nil {
		return fmt.Errorf("create migration tracking table: %w", err)
	}

	for _, migration := range migrations {
		var applied bool
		if err := tx.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM atlas_schema_migrations WHERE version = $1)`,
			migration.version,
		).Scan(&applied); err != nil {
			return fmt.Errorf("read migration version %d: %w", migration.version, err)
		}
		if applied {
			continue
		}
		sql, err := fs.ReadFile(migrationFiles, migration.up)
		if err != nil {
			return fmt.Errorf("read migration version %d: %w", migration.version, err)
		}
		if _, err := tx.Exec(ctx, strings.TrimSpace(string(sql))); err != nil {
			return fmt.Errorf("apply migration version %d: %w", migration.version, err)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO atlas_schema_migrations (version) VALUES ($1)`,
			migration.version,
		); err != nil {
			return fmt.Errorf("record migration version %d: %w", migration.version, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit migrations: %w", err)
	}
	return nil
}
