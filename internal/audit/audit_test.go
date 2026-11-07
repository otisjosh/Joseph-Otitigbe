package audit

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type fakeStore struct { events []Event; limit int; before int64; err error }
func (f *fakeStore) ListEvents(_ context.Context, limit int, before int64) ([]Event, error) {
	f.limit, f.before = limit, before
	return f.events, f.err
}
func TestHandlerListsAuditEventsWithBoundedPagination(t *testing.T) {
	actor, resource := int64(8), int64(42)
	event := Event{ID:12, OccurredAt:time.Date(2026,1,2,3,4,5,0,time.UTC), ActorKeyID:&actor, Action:"record.created", ResourceType:"record", ResourceID:&resource, Details:map[string]string{}}
	store := &fakeStore{events: []Event{event}}
	res := httptest.NewRecorder()
	NewHandler(store).ServeHTTP(res, httptest.NewRequest(http.MethodGet,"/audit-logs?limit=20&before_id=15",nil))
	if res.Code != http.StatusOK || store.limit != 20 || store.before != 15 { t.Fatalf("status=%d limit=%d before=%d body=%s",res.Code,store.limit,store.before,res.Body) }
	for _, want := range []string{"record.created","actor_key_id","42"} { if !strings.Contains(res.Body.String(),want) { t.Errorf("response %q missing %q",res.Body.String(),want) } }
}
func TestHandlerRejectsInvalidPaginationAndMethods(t *testing.T) {
	for _, test := range []struct{ method,path,code string }{
		{http.MethodGet,"/audit-logs?limit=501","invalid_limit"},
		{http.MethodGet,"/audit-logs?limit=0","invalid_limit"},
		{http.MethodGet,"/audit-logs?before_id=01","invalid_before_id"},
		{http.MethodPost,"/audit-logs","method_not_allowed"},
	} {
		res:=httptest.NewRecorder(); NewHandler(&fakeStore{}).ServeHTTP(res,httptest.NewRequest(test.method,test.path,nil))
		if res.Code!=http.StatusBadRequest && res.Code!=http.StatusMethodNotAllowed { t.Errorf("%s %s status=%d",test.method,test.path,res.Code) }
		if !strings.Contains(res.Body.String(),test.code) { t.Errorf("%s %s body=%q want %q",test.method,test.path,res.Body.String(),test.code) }
	}
}
func TestHandlerReturnsUnavailableWithoutDatabaseDetails(t *testing.T) {
	res:=httptest.NewRecorder()
	NewHandler(&fakeStore{err:errors.New("connection string contains secret")}).ServeHTTP(res,httptest.NewRequest(http.MethodGet,"/audit-logs",nil))
	if res.Code!=http.StatusServiceUnavailable || strings.Contains(res.Body.String(),"secret") { t.Fatalf("response=%d %q",res.Code,res.Body.String()) }
}
