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
	handler := NewHandler()
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

func TestHandlerRejectsMalformedJSONAndUnknownFields(t *testing.T) {
	handler := NewHandler()
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
	handler := NewHandler()
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
	handler := NewHandler()
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
		res := performRequest(NewHandler(), test.method, test.path, "")
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

func TestHealthAndNotFound(t *testing.T) {
	handler := NewHandler()
	health := performRequest(handler, http.MethodGet, "/healthz", "")
	if health.Code != http.StatusOK {
		t.Fatalf("health status = %d, want %d", health.Code, http.StatusOK)
	}
	missing := performRequest(handler, http.MethodGet, "/records/8", "")
	if missing.Code != http.StatusNotFound {
		t.Fatalf("missing record status = %d, want %d", missing.Code, http.StatusNotFound)
	}
	unknown := performRequest(handler, http.MethodGet, "/unknown", "")
	if unknown.Code != http.StatusNotFound || !strings.Contains(unknown.Body.String(), "not_found") {
		t.Fatalf("unknown route response = %d %q", unknown.Code, unknown.Body.String())
	}
}
