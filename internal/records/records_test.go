package records

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCreateValidatesAndDetectsDuplicates(t *testing.T) {
	store := NewStore()
	record, err := store.Create(" Ada Lovelace ", " ada@example.com ")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if record.ID != 1 || record.Name != "Ada Lovelace" || record.Email != "ada@example.com" {
		t.Fatalf("unexpected record: %+v", record)
	}
	if _, err := store.Create("Another Name", "ADA@example.com"); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("duplicate error = %v, want ErrDuplicate", err)
	}
	if _, err := store.Create(" ", "bad"); !errors.Is(err, ErrInvalidRecord) {
		t.Fatalf("invalid input error = %v, want ErrInvalidRecord", err)
	}
}

func TestHandlerCreateDuplicateAndGet(t *testing.T) {
	handler := NewHandler()
	create := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/records", strings.NewReader(body))
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		return res
	}
	first := create(`{"name":"Ada","email":"ada@example.com"}`)
	if first.Code != http.StatusCreated {
		t.Fatalf("first create status = %d, want %d", first.Code, http.StatusCreated)
	}
	duplicate := create(`{"name":"Ada","email":"ADA@example.com"}`)
	if duplicate.Code != http.StatusConflict {
		t.Fatalf("duplicate status = %d, want %d", duplicate.Code, http.StatusConflict)
	}
	get := httptest.NewRecorder()
	handler.ServeHTTP(get, httptest.NewRequest(http.MethodGet, "/records/1", nil))
	if get.Code != http.StatusOK || !strings.Contains(get.Body.String(), "ada@example.com") {
		t.Fatalf("GET response = %d %q", get.Code, get.Body.String())
	}
}

func TestHandlerRejectsUnknownFieldsAndInvalidJSON(t *testing.T) {
	handler := NewHandler()
	for _, body := range []string{`{"name":"Ada","email":"ada@example.com","extra":true}`, "{", `{"name":" ","email":"bad"}`} {
		req := httptest.NewRequest(http.MethodPost, "/records", strings.NewReader(body))
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code != http.StatusBadRequest {
			t.Errorf("body %q status = %d, want %d", body, res.Code, http.StatusBadRequest)
		}
	}
}

func TestHealthAndNotFound(t *testing.T) {
	handler := NewHandler()
	health := httptest.NewRecorder()
	handler.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if health.Code != http.StatusOK {
		t.Fatalf("health status = %d, want %d", health.Code, http.StatusOK)
	}
	missing := httptest.NewRecorder()
	handler.ServeHTTP(missing, httptest.NewRequest(http.MethodGet, "/records/8", nil))
	if missing.Code != http.StatusNotFound {
		t.Fatalf("missing record status = %d, want %d", missing.Code, http.StatusNotFound)
	}
}
