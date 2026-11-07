package records

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCreateValidatesAndDetectsDuplicates(t *testing.T) {
	store := NewStore()
	record, err := store.Create(context.Background(), " Ada Lovelace ", " ada@example.com ")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if record.ID != 1 || record.Name != "Ada Lovelace" || record.Email != "ada@example.com" {
		t.Fatalf("unexpected record: %+v", record)
	}
	if _, err := store.Create(context.Background(), "Another Name", "ADA@example.com"); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("duplicate error = %v, want ErrDuplicate", err)
	}
	if _, err := store.Create(context.Background(), " ", "bad"); !errors.Is(err, ErrInvalidRecord) {
		t.Fatalf("invalid input error = %v, want ErrInvalidRecord", err)
	}
}

func TestStoreHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	store := NewStore()
	if _, err := store.Create(ctx, "Ada", "ada@example.com"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Create() error = %v, want context.Canceled", err)
	}
	if _, err := store.Get(ctx, 1); !errors.Is(err, context.Canceled) {
		t.Fatalf("Get() error = %v, want context.Canceled", err)
	}
}

func TestEmailValidation(t *testing.T) {
	tests := []struct {
		email string
		valid bool
	}{
		{"ada@example.com", true},
		{"ada+tag@sub.example.co", true},
		{"ada@example", false},
		{"ada@.example.com", false},
		{"ada@example..com", false},
		{"ada@-example.com", false},
		{"ada@example-.com", false},
		{"ada@@example.com", false},
		{"Ada <ada@example.com>", false},
		{"ada example@example.com", false},
		{"ada@example.com.", false},
		{strings.Repeat("a", 243) + "@example.com", false},
	}
	for _, test := range tests {
		t.Run(test.email, func(t *testing.T) {
			if got := validEmail(test.email); got != test.valid {
				t.Errorf("validEmail(%q) = %v, want %v", test.email, got, test.valid)
			}
		})
	}
}

func performRequest(handler http.Handler, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	return res
}

func TestHandlerCreateDuplicateAndGet(t *testing.T) {
	handler := NewHandler(NewStore())
	first := performRequest(handler, http.MethodPost, "/records", `{"name":"Ada","email":"ada@example.com"}`)
	if first.Code != http.StatusCreated {
		t.Fatalf("first create status = %d, want %d: %s", first.Code, http.StatusCreated, first.Body)
	}
	duplicate := performRequest(handler, http.MethodPost, "/records", `{"name":"Ada","email":"ADA@example.com"}`)
	if duplicate.Code != http.StatusConflict {
		t.Fatalf("duplicate status = %d, want %d", duplicate.Code, http.StatusConflict)
	}
	get := performRequest(handler, http.MethodGet, "/records/1", "")
	if get.Code != http.StatusOK || !strings.Contains(get.Body.String(), "ada@example.com") {
		t.Fatalf("GET response = %d %q", get.Code, get.Body.String())
	}
}

type failedRepository struct {
	err error
}

func (f failedRepository) Create(context.Context, string, string) (Record, error) {
	return Record{}, f.err
}

func (f failedRepository) Get(context.Context, int64) (Record, error) {
	return Record{}, f.err
}

func TestHandlerReturnsServiceUnavailableForStorageErrors(t *testing.T) {
	handler := NewHandler(failedRepository{err: ErrUnavailable})
	create := performRequest(handler, http.MethodPost, "/records", `{"name":"Ada","email":"ada@example.com"}`)
	if create.Code != http.StatusServiceUnavailable || !strings.Contains(create.Body.String(), "storage_unavailable") {
		t.Fatalf("create response = %d %q, want 503 storage_unavailable", create.Code, create.Body.String())
	}
	get := performRequest(handler, http.MethodGet, "/records/1", "")
	if get.Code != http.StatusServiceUnavailable || !strings.Contains(get.Body.String(), "storage_unavailable") {
		t.Fatalf("get response = %d %q, want 503 storage_unavailable", get.Code, get.Body.String())
	}
}

func TestHandlerReturnsNotFoundForMissingRecord(t *testing.T) {
	handler := NewHandler(NewStore())
	res := performRequest(handler, http.MethodGet, "/records/8", "")
	if res.Code != http.StatusNotFound || !strings.Contains(res.Body.String(), "not_found") {
		t.Fatalf("missing record response = %d %q", res.Code, res.Body.String())
	}
}

func TestHandlerRejectsMalformedJSONAndUnknownFields(t *testing.T) {
	handler := NewHandler(NewStore())
	for _, body := range []string{`{"name":"Ada","email":"ada@example.com","extra":true}`, "{", `{"name":"Ada","email":"ada@example.com"} trailing`, `{"name":" ","email":"bad"}`} {
		res := performRequest(handler, http.MethodPost, "/records", body)
		if res.Code != http.StatusBadRequest {
			t.Errorf("body %q status = %d, want %d", body, res.Code, http.StatusBadRequest)
		}
		if res.Header().Get("Content-Type") != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", res.Header().Get("Content-Type"))
		}
	}
}

func TestHandlerRejectsOversizedRequest(t *testing.T) {
	handler := NewHandler(NewStore())
	body := `{"name":"` + strings.Repeat("a", maxRequestBody) + `","email":"ada@example.com"}`
	res := performRequest(handler, http.MethodPost, "/records", body)
	if res.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized request status = %d, want %d", res.Code, http.StatusRequestEntityTooLarge)
	}
	if !strings.Contains(res.Body.String(), "request_too_large") {
		t.Fatalf("oversized request response = %q, want API error code", res.Body.String())
	}
}

func TestGetRejectsMalformedRecordIDs(t *testing.T) {
	handler := NewHandler(NewStore())
	for _, id := range []string{"abc", "-1", "0", "1junk", "01", "1/extra", ""} {
		res := performRequest(handler, http.MethodGet, "/records/"+id, "")
		if res.Code != http.StatusBadRequest {
			t.Errorf("ID %q status = %d, want %d", id, res.Code, http.StatusBadRequest)
		}
		if !strings.Contains(res.Body.String(), "invalid_record_id") {
			t.Errorf("ID %q response = %q, want invalid_record_id", id, res.Body.String())
		}
	}
}

func TestUnsupportedMethodsReturnJSON405AndAllow(t *testing.T) {
	for _, test := range []struct {
		method, path, allow string
	}{
		{http.MethodGet, "/records", http.MethodPost},
		{http.MethodPatch, "/records/1", http.MethodGet},
		{http.MethodPost, "/healthz", http.MethodGet},
	} {
		res := performRequest(NewHandler(NewStore()), test.method, test.path, "")
		if res.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s status = %d, want %d", test.method, test.path, res.Code, http.StatusMethodNotAllowed)
		}
		if got := res.Header().Get("Allow"); got != test.allow {
			t.Errorf("%s %s Allow = %q, want %q", test.method, test.path, got, test.allow)
		}
		if !strings.Contains(res.Body.String(), "method_not_allowed") {
			t.Errorf("%s %s body = %q, want API error code", test.method, test.path, res.Body.String())
		}
	}
}

func TestHealthAndUnknownRoute(t *testing.T) {
	handler := NewHandler(NewStore())
	health := performRequest(handler, http.MethodGet, "/healthz", "")
	if health.Code != http.StatusOK {
		t.Fatalf("health status = %d, want %d", health.Code, http.StatusOK)
	}
	unknown := performRequest(handler, http.MethodGet, "/unknown", "")
	if unknown.Code != http.StatusNotFound || !strings.Contains(unknown.Body.String(), "not_found") {
		t.Fatalf("unknown route response = %d %q", unknown.Code, unknown.Body.String())
	}
}
