package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/otisjosh/Joseph-Otitigbe/internal/audit"
	"github.com/otisjosh/Joseph-Otitigbe/internal/auth"
	"github.com/otisjosh/Joseph-Otitigbe/internal/records"
)

type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

func (s *Store) Create(ctx context.Context, name, email string) (records.Record, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return records.Record{}, fmt.Errorf("%w: %v", records.ErrUnavailable, err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	const query = `INSERT INTO atlas_records (name, email) VALUES ($1, $2)
		RETURNING id, name, email`
	var record records.Record
	err = tx.QueryRow(ctx, query, name, email).Scan(&record.ID, &record.Name, &record.Email)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return records.Record{}, records.ErrDuplicate
		}
		return records.Record{}, fmt.Errorf("%w: %v", records.ErrUnavailable, err)
	}
	var actorID *int64
	if principal, ok := auth.PrincipalFromContext(ctx); ok {
		actorID = &principal.KeyID
	}
	if err := insertAuditEvent(ctx, tx, audit.Event{ActorKeyID: actorID, Action: "record.created", ResourceType: "record", ResourceID: &record.ID}); err != nil {
		return records.Record{}, fmt.Errorf("%w: audit record creation: %v", records.ErrUnavailable, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return records.Record{}, fmt.Errorf("%w: %v", records.ErrUnavailable, err)
	}
	return record, nil
}

func (s *Store) Get(ctx context.Context, id int64) (records.Record, error) {
	const query = `SELECT id, name, email FROM atlas_records WHERE id = $1`
	var record records.Record
	err := s.pool.QueryRow(ctx, query, id).Scan(&record.ID, &record.Name, &record.Email)
	if errors.Is(err, pgx.ErrNoRows) {
		return records.Record{}, records.ErrNotFound
	}
	if err != nil {
		return records.Record{}, fmt.Errorf("%w: %v", records.ErrUnavailable, err)
	}
	return record, nil
}
