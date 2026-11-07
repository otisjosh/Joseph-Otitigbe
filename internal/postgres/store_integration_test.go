package postgres

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/otisjosh/Joseph-Otitigbe/internal/records"
)

var testEmailCounter atomic.Uint64

func integrationPool(t *testing.T) (*pgxpool.Pool, *Store) {
	t.Helper()
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DATABASE_URL is not set; PostgreSQL integration test skipped")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := Open(ctx, databaseURL)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(pool.Close)
	return pool, NewStore(pool)
}

func TestMigrationsAreVersionedAndIdempotent(t *testing.T) {
	pool, _ := integrationPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := RunMigrations(ctx, pool); err != nil {
		t.Fatalf("second RunMigrations() error = %v", err)
	}
	var count int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM atlas_schema_migrations").Scan(&count); err != nil {
		t.Fatalf("count migration versions: %v", err)
	}
	if count != 2 {
		t.Fatalf("applied migration count = %d, want 2", count)
	}
}

func TestRepositoryPersistsRetrievesAndEnforcesUniqueEmail(t *testing.T) {
	pool, store := integrationPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	email := fmt.Sprintf("phase2-%d-%d@example.test", time.Now().UnixNano(), testEmailCounter.Add(1))
	created, err := store.Create(ctx, "Atlas Integration", email)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	loaded, err := NewStore(pool).Get(ctx, created.ID)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if loaded.ID != created.ID || loaded.Name != created.Name || loaded.Email != created.Email {
		t.Fatalf("Get() = %+v, want %+v", loaded, created)
	}
	if _, err := store.Create(ctx, "Duplicate", strings.ToUpper(email)); !errors.Is(err, records.ErrDuplicate) {
		t.Fatalf("duplicate Create() error = %v, want records.ErrDuplicate", err)
	}
}

func TestDatabaseAndMigrationFailuresAreReturned(t *testing.T) {
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
	if err := RunMigrations(ctx, pool); err == nil {
		t.Fatal("RunMigrations() on a closed pool succeeded, want a database error")
	}
	_, err := NewStore(pool).Create(ctx, "Atlas Failure", "failure@example.test")
	if !errors.Is(err, records.ErrUnavailable) {
		t.Fatalf("Create() error = %v, want records.ErrUnavailable", err)
	}
	_, err = NewStore(pool).Get(ctx, 1)
	if !errors.Is(err, records.ErrUnavailable) {
		t.Fatalf("Get() error = %v, want records.ErrUnavailable", err)
	}
}

func TestOpenRejectsInvalidConnectionString(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := Open(ctx, "not a postgres URL"); err == nil {
		t.Fatal("Open() succeeded with malformed DATABASE_URL")
	}
}
