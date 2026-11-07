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

	"github.com/otisjosh/Joseph-Otitigbe/internal/audit"
	"github.com/otisjosh/Joseph-Otitigbe/internal/auth"
)

func TestAuditEventsCaptureMutationsWithoutSecretsOrRecordContents(t *testing.T) {
	pool:=isolatedAuthPool(t)
	ctx,cancel:=context.WithTimeout(context.Background(),15*time.Second); defer cancel()
	manager:=auth.NewKeyManager(NewKeyStore(pool))
	admin,adminToken,err:=manager.Create(ctx,fmt.Sprintf("audit-admin-%d",time.Now().UnixNano()),auth.RoleAdmin,nil)
	if err!=nil { t.Fatalf("create admin: %v",err) }
	target,token,err:=manager.Create(ctx,fmt.Sprintf("audit-target-%d",time.Now().UnixNano()),auth.RoleWriter,&admin.ID)
	if err!=nil { t.Fatalf("create target key: %v",err) }
	if _,err:=manager.ChangeRole(ctx,target.ID,auth.RoleReader,&admin.ID);err!=nil { t.Fatalf("change role: %v",err) }
	if _,err:=manager.Revoke(ctx,target.ID,&admin.ID);err!=nil { t.Fatalf("revoke key: %v",err) }

	principalCtx:=auth.ContextWithPrincipal(ctx,auth.Principal{KeyID:admin.ID,Role:auth.RoleAdmin})
	email:=fmt.Sprintf("audit-%d@example.test",time.Now().UnixNano())
	record,err:=NewStore(pool).Create(principalCtx,"Sensitive record name",email)
	if err!=nil { t.Fatalf("create record: %v",err) }
	store:=NewAuditStore(pool)
	events,err:=store.ListEvents(ctx,500,0);if err!=nil{t.Fatalf("ListEvents(): %v",err)}
	want:=map[string]bool{"api_key.created":false,"api_key.role_changed":false,"api_key.revoked":false,"record.created":false}
	for _,event:=range events {
		if event.Action=="api_key.created"&&event.ResourceID!=nil&&*event.ResourceID==target.ID { want[event.Action]=event.ActorKeyID!=nil&&*event.ActorKeyID==admin.ID&&event.Details["role"]=="writer" }
		if event.Action=="api_key.role_changed"&&event.ResourceID!=nil&&*event.ResourceID==target.ID { want[event.Action]=event.ActorKeyID!=nil&&*event.ActorKeyID==admin.ID&&event.Details["role"]=="reader" }
		if event.Action=="api_key.revoked"&&event.ResourceID!=nil&&*event.ResourceID==target.ID { want[event.Action]=event.ActorKeyID!=nil&&*event.ActorKeyID==admin.ID }
		if event.Action=="record.created"&&event.ResourceID!=nil&&*event.ResourceID==record.ID { want[event.Action]=event.ActorKeyID!=nil&&*event.ActorKeyID==admin.ID }
	}
	for action,found:=range want { if !found { t.Errorf("missing or incomplete %s audit event",action) } }
	encoded,err:=json.Marshal(events);if err!=nil{t.Fatal(err)}
	if strings.Contains(string(encoded),token)||strings.Contains(string(encoded),email)||strings.Contains(string(encoded),"Sensitive record name"){t.Fatalf("audit events contain secret or record content: %s",encoded)}

	handler := auth.Middleware(NewKeyStore(pool), audit.NewHandler(store))
	adminReq := httptest.NewRequest(http.MethodGet, "/audit-logs?limit=20", nil)
	adminReq.Header.Set("Authorization", "Bearer "+adminToken)
	adminRes := httptest.NewRecorder()
	handler.ServeHTTP(adminRes, adminReq)
	if adminRes.Code != http.StatusOK || !strings.Contains(adminRes.Body.String(), "api_key.role_changed") {
		t.Fatalf("admin audit endpoint = %d %q", adminRes.Code, adminRes.Body.String())
	}

	for _, role := range []auth.Role{auth.RoleReader, auth.RoleWriter} {
		_, restrictedToken, err := manager.Create(ctx, fmt.Sprintf("audit-%s-%d", role, time.Now().UnixNano()), role, &admin.ID)
		if err != nil {
			t.Fatalf("create %s key: %v", role, err)
		}
		req := httptest.NewRequest(http.MethodGet, "/audit-logs", nil)
		req.Header.Set("Authorization", "Bearer "+restrictedToken)
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code != http.StatusForbidden || !strings.Contains(res.Body.String(), "permission_denied") {
			t.Errorf("%s GET /audit-logs = %d %q, want 403 permission_denied", role, res.Code, res.Body.String())
		}
	}
}
