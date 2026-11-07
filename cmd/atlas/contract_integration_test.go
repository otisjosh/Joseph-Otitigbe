package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/otisjosh/Joseph-Otitigbe/internal/audit"
	"github.com/otisjosh/Joseph-Otitigbe/internal/auth"
	"github.com/otisjosh/Joseph-Otitigbe/internal/postgres"
	"github.com/otisjosh/Joseph-Otitigbe/internal/records"
)

func contractPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DATABASE_URL is not set; PostgreSQL contract integration test skipped")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	root, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect contract-test database: %v", err)
	}
	schema := fmt.Sprintf("atlas_contract_%d", time.Now().UnixNano())
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	if _, err := root.Exec(ctx, "CREATE SCHEMA "+quotedSchema); err != nil {
		root.Close()
		t.Fatalf("create contract-test schema: %v", err)
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		_, _ = root.Exec(context.Background(), "DROP SCHEMA "+quotedSchema+" CASCADE")
		root.Close()
		t.Fatalf("parse contract-test database URL: %v", err)
	}
	if config.ConnConfig.RuntimeParams == nil {
		config.ConnConfig.RuntimeParams = make(map[string]string)
	}
	config.ConnConfig.RuntimeParams["search_path"] = quotedSchema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		_, _ = root.Exec(context.Background(), "DROP SCHEMA "+quotedSchema+" CASCADE")
		root.Close()
		t.Fatalf("create contract-test pool: %v", err)
	}
	t.Cleanup(func() {
		pool.Close()
		dropCtx, dropCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer dropCancel()
		_, _ = root.Exec(dropCtx, "DROP SCHEMA "+quotedSchema+" CASCADE")
		root.Close()
	})
	if err := postgres.RunMigrations(ctx, pool); err != nil {
		t.Fatalf("apply contract-test migrations: %v", err)
	}
	return pool
}

func TestAPIRouteContract(t *testing.T) {
	pool := contractPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	keyStore := postgres.NewKeyStore(pool)
	recordStore := postgres.NewStore(pool)
	manager := auth.NewKeyManager(keyStore)
	admin, adminToken, err := manager.Create(ctx, "contract-admin", auth.RoleAdmin, nil)
	if err != nil {
		t.Fatalf("create contract admin: %v", err)
	}
	_, writerToken, err := manager.Create(ctx, "contract-writer", auth.RoleWriter, &admin.ID)
	if err != nil {
		t.Fatalf("create contract writer: %v", err)
	}
	_, readerToken, err := manager.Create(ctx, "contract-reader", auth.RoleReader, &admin.ID)
	if err != nil {
		t.Fatalf("create contract reader: %v", err)
	}
	handler := routes(keyStore, recordStore, pool, newJSONLogger(io.Discard))
	seenRequestIDs := make(map[string]bool)
	request := func(method, path, token, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		requestID := res.Header().Get("X-Request-ID")
		rawID, err := hex.DecodeString(requestID)
		if err != nil || len(rawID) != 16 || !regexp.MustCompile("^[0-9a-f]{32}$").MatchString(requestID) {
			t.Errorf("%s %s returned invalid X-Request-ID %q", method, path, requestID)
		}
		if seenRequestIDs[requestID] {
			t.Errorf("request ID %q was reused", requestID)
		}
		seenRequestIDs[requestID] = true
		return res
	}
	assertError := func(res *httptest.ResponseRecorder, status int, code string) {
		t.Helper()
		if res.Code != status {
			t.Fatalf("status = %d, want %d", res.Code, status)
		}
		if !strings.HasPrefix(res.Header().Get("Content-Type"), "application/json") {
			t.Fatalf("Content-Type = %q, want application/json", res.Header().Get("Content-Type"))
		}
		var payload struct {
			Error struct {
				Code string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal(res.Body.Bytes(), &payload); err != nil {
			t.Fatalf("decode error response JSON: %v", err)
		}
		if payload.Error.Code != code || payload.Error.Message == "" {
			t.Fatalf("error response = %+v, want code %q and message", payload.Error, code)
		}
	}

	health := request(http.MethodGet, "/healthz", "", "")
	if health.Code != http.StatusOK || health.Body.Len() != 0 {
		t.Fatalf("GET /healthz = %d %q, want empty 200", health.Code, health.Body.String())
	}
	ready := request(http.MethodGet, "/readyz", "", "")
	if ready.Code != http.StatusOK || !strings.Contains(ready.Body.String(), `"status":"ready"`) {
		t.Fatalf("GET /readyz = %d %q, want 200 ready JSON", ready.Code, ready.Body.String())
	}
	healthMethod := request(http.MethodPost, "/healthz", "", "")
	assertError(healthMethod, http.StatusMethodNotAllowed, "method_not_allowed")
	if healthMethod.Header().Get("Allow") != http.MethodGet {
		t.Errorf("POST /healthz Allow = %q, want GET", healthMethod.Header().Get("Allow"))
	}
	readyMethod := request(http.MethodPost, "/readyz", "", "")
	assertError(readyMethod, http.StatusMethodNotAllowed, "method_not_allowed")
	if readyMethod.Header().Get("Allow") != http.MethodGet {
		t.Errorf("POST /readyz Allow = %q, want GET", readyMethod.Header().Get("Allow"))
	}

	assertError(request(http.MethodGet, "/records/1", "", ""), http.StatusUnauthorized, "authentication_required")
	assertError(request(http.MethodGet, "/api-keys", "", ""), http.StatusUnauthorized, "authentication_required")
	assertError(request(http.MethodGet, "/roles", "", ""), http.StatusUnauthorized, "authentication_required")
	assertError(request(http.MethodGet, "/audit-logs", "", ""), http.StatusUnauthorized, "authentication_required")
	assertError(request(http.MethodGet, "/audit-logs", readerToken, ""), http.StatusForbidden, "permission_denied")
	assertError(request(http.MethodGet, "/audit-logs", writerToken, ""), http.StatusForbidden, "permission_denied")

	roles := request(http.MethodGet, "/roles", adminToken, "")
	if roles.Code != http.StatusOK {
		t.Fatalf("GET /roles = %d, want 200", roles.Code)
	}
	var roleValues []auth.RoleInfo
	if err := json.Unmarshal(roles.Body.Bytes(), &roleValues); err != nil || len(roleValues) != 3 {
		t.Fatalf("GET /roles returned invalid role array: err=%v count=%d", err, len(roleValues))
	}

	keyList := request(http.MethodGet, "/api-keys", adminToken, "")
	if keyList.Code != http.StatusOK {
		t.Fatalf("GET /api-keys = %d, want 200", keyList.Code)
	}
	var listed []auth.KeyMetadata
	if err := json.Unmarshal(keyList.Body.Bytes(), &listed); err != nil || len(listed) < 3 {
		t.Fatalf("GET /api-keys returned invalid metadata array: err=%v", err)
	}
	apiKeyMethod := request(http.MethodPut, "/api-keys", adminToken, "")
	assertError(apiKeyMethod, http.StatusMethodNotAllowed, "method_not_allowed")
	if apiKeyMethod.Header().Get("Allow") != "GET, POST" {
		t.Errorf("PUT /api-keys Allow = %q, want GET, POST", apiKeyMethod.Header().Get("Allow"))
	}
	assertError(request(http.MethodPost, "/api-keys", writerToken, `{"name":"denied","role":"reader"}`), http.StatusForbidden, "permission_denied")

	recordBody := `{"name":"Contract Record","email":"contract@example.test"}`
	createdResponse := request(http.MethodPost, "/records", writerToken, recordBody)
	if createdResponse.Code != http.StatusCreated {
		t.Fatalf("POST /records = %d, want 201", createdResponse.Code)
	}
	var created records.Record
	if err := json.Unmarshal(createdResponse.Body.Bytes(), &created); err != nil || created.ID < 1 || created.Name != "Contract Record" {
		t.Fatalf("POST /records response invalid: err=%v", err)
	}
	gotResponse := request(http.MethodGet, fmt.Sprintf("/records/%d", created.ID), readerToken, "")
	if gotResponse.Code != http.StatusOK {
		t.Fatalf("GET /records/{id} = %d, want 200", gotResponse.Code)
	}
	var got records.Record
	if err := json.Unmarshal(gotResponse.Body.Bytes(), &got); err != nil || got.ID != created.ID || got.Email != created.Email {
		t.Fatalf("GET /records/{id} response invalid: err=%v", err)
	}
	assertError(request(http.MethodPost, "/records", readerToken, recordBody), http.StatusForbidden, "permission_denied")
	assertError(request(http.MethodPost, "/records", writerToken, "{"), http.StatusBadRequest, "invalid_json")
	assertError(request(http.MethodPost, "/records", writerToken, `{"name":"No Email","email":"bad"}`), http.StatusBadRequest, "invalid_record")
	assertError(request(http.MethodPost, "/records", writerToken, recordBody), http.StatusConflict, "duplicate_record")
	assertError(request(http.MethodGet, "/records/not-an-id", readerToken, ""), http.StatusBadRequest, "invalid_record_id")
	assertError(request(http.MethodGet, "/records/999999999", readerToken, ""), http.StatusNotFound, "not_found")
	recordMethod := request(http.MethodGet, "/records", writerToken, "")
	assertError(recordMethod, http.StatusMethodNotAllowed, "method_not_allowed")
	if recordMethod.Header().Get("Allow") != http.MethodPost {
		t.Errorf("GET /records Allow = %q, want POST", recordMethod.Header().Get("Allow"))
	}

	createKey := request(http.MethodPost, "/api-keys", adminToken, `{"name":"contract-managed","role":"reader"}`)
	if createKey.Code != http.StatusCreated || createKey.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("POST /api-keys = %d Cache-Control=%q, want 201 no-store", createKey.Code, createKey.Header().Get("Cache-Control"))
	}
	var provisioned struct {
		auth.KeyMetadata
		APIKey string `json:"api_key"`
	}
	if err := json.Unmarshal(createKey.Body.Bytes(), &provisioned); err != nil || provisioned.ID < 1 || provisioned.APIKey == "" {
		t.Fatalf("POST /api-keys response invalid: err=%v", err)
	}
	keyPathMethod := request(http.MethodGet, fmt.Sprintf("/api-keys/%d", provisioned.ID), adminToken, "")
	assertError(keyPathMethod, http.StatusMethodNotAllowed, "method_not_allowed")
	if keyPathMethod.Header().Get("Allow") != "PATCH, DELETE" {
		t.Errorf("GET /api-keys/{id} Allow = %q, want PATCH, DELETE", keyPathMethod.Header().Get("Allow"))
	}
	roleChanged := request(http.MethodPatch, fmt.Sprintf("/api-keys/%d/role", provisioned.ID), adminToken, `{"role":"writer"}`)
	if roleChanged.Code != http.StatusOK || !strings.Contains(roleChanged.Body.String(), `"role":"writer"`) {
		t.Fatalf("PATCH /api-keys/{id}/role = %d", roleChanged.Code)
	}
	assertError(request(http.MethodPatch, fmt.Sprintf("/api-keys/%d/role", provisioned.ID), adminToken, `{"role":"invalid"}`), http.StatusBadRequest, "invalid_role")
	assertError(request(http.MethodPatch, "/api-keys/bad-id/role", adminToken, `{"role":"writer"}`), http.StatusBadRequest, "invalid_api_key_id")
	assertError(request(http.MethodDelete, "/api-keys/999999999", adminToken, ""), http.StatusNotFound, "api_key_not_found")
	assertError(request(http.MethodPatch, fmt.Sprintf("/api-keys/%d/role", admin.ID), adminToken, `{"role":"reader"}`), http.StatusConflict, "last_admin_required")
	deleted := request(http.MethodDelete, fmt.Sprintf("/api-keys/%d", provisioned.ID), adminToken, "")
	if deleted.Code != http.StatusOK || !strings.Contains(deleted.Body.String(), `"revoked_at"`) {
		t.Fatalf("DELETE /api-keys/{id} = %d", deleted.Code)
	}
	assertError(request(http.MethodGet, "/records/1", provisioned.APIKey, ""), http.StatusUnauthorized, "invalid_api_key")

	auditPage := request(http.MethodGet, "/audit-logs?limit=1", adminToken, "")
	if auditPage.Code != http.StatusOK {
		t.Fatalf("GET /audit-logs = %d, want 200", auditPage.Code)
	}
	var page struct { Events []audit.Event `json:"events"` }
	if err := json.Unmarshal(auditPage.Body.Bytes(), &page); err != nil || len(page.Events) != 1 {
		t.Fatalf("audit page invalid: err=%v count=%d", err, len(page.Events))
	}
	nextPage := request(http.MethodGet, fmt.Sprintf("/audit-logs?limit=1&before_id=%d", page.Events[0].ID), adminToken, "")
	var next struct { Events []audit.Event `json:"events"` }
	if nextPage.Code != http.StatusOK || json.Unmarshal(nextPage.Body.Bytes(), &next) != nil || len(next.Events) != 1 || next.Events[0].ID >= page.Events[0].ID {
		t.Fatalf("exclusive audit cursor behavior incorrect: status=%d events=%d", nextPage.Code, len(next.Events))
	}
	assertError(request(http.MethodGet, "/audit-logs?limit=501", adminToken, ""), http.StatusBadRequest, "invalid_limit")
	assertError(request(http.MethodGet, "/audit-logs?before_id=01", adminToken, ""), http.StatusBadRequest, "invalid_before_id")
	assertError(request(http.MethodPost, "/audit-logs", adminToken, ""), http.StatusMethodNotAllowed, "method_not_allowed")
	assertError(request(http.MethodPost, "/roles", adminToken, ""), http.StatusMethodNotAllowed, "method_not_allowed")
}
