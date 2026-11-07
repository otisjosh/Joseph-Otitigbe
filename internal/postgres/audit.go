package postgres

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/otisjosh/Joseph-Otitigbe/internal/audit"
)

type AuditStore struct { pool *pgxpool.Pool }
func NewAuditStore(pool *pgxpool.Pool) *AuditStore { return &AuditStore{pool:pool} }

func insertAuditEvent(ctx context.Context, tx pgx.Tx, event audit.Event) error {
	details:=event.Details
	if details==nil { details=map[string]string{} }
	encoded,err:=json.Marshal(details)
	if err!=nil { return fmt.Errorf("encode audit event details: %w",err) }
	_,err=tx.Exec(ctx,`INSERT INTO atlas_audit_events (actor_key_id, action, resource_type, resource_id, details)
		VALUES ($1, $2, $3, $4, $5)`,event.ActorKeyID,event.Action,event.ResourceType,event.ResourceID,encoded)
	return err
}

func (s *AuditStore) ListEvents(ctx context.Context,limit int,beforeID int64)([]audit.Event,error) {
	rows,err:=s.pool.Query(ctx,`SELECT id, occurred_at, actor_key_id, action, resource_type, resource_id, details
		FROM atlas_audit_events
		WHERE ($1::bigint = 0 OR id < $1)
		ORDER BY id DESC LIMIT $2`,beforeID,limit)
	if err!=nil { return nil,err }
	defer rows.Close()
	events:=make([]audit.Event,0)
	for rows.Next() {
		var event audit.Event
		var actorID,resourceID pgtype.Int8
		var details []byte
		if err:=rows.Scan(&event.ID,&event.OccurredAt,&actorID,&event.Action,&event.ResourceType,&resourceID,&details);err!=nil{return nil,err}
		if actorID.Valid { event.ActorKeyID=&actorID.Int64 }
		if resourceID.Valid { event.ResourceID=&resourceID.Int64 }
		if err:=json.Unmarshal(details,&event.Details);err!=nil{return nil,err}
		events=append(events,event)
	}
	if err:=rows.Err();err!=nil{return nil,err}
	return events,nil
}
