package auth

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

type KeyHandler struct {
	manager *KeyManager
}

func NewKeyHandler(manager *KeyManager) http.Handler {
	return &KeyHandler{manager: manager}
}

func (h *KeyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/api-keys":
		switch r.Method {
		case http.MethodGet:
			h.listKeys(w, r)
		case http.MethodPost:
			h.createKey(w, r)
		default:
			methodNotAllowed(w, "GET, POST")
		}
	case strings.HasPrefix(r.URL.Path, "/api-keys/"):
		h.manageKey(w, r)
	case r.URL.Path == "/roles":
		if r.Method != http.MethodGet {
			methodNotAllowed(w, http.MethodGet)
			return
		}
		roles, err := h.manager.Roles(r.Context())
		if err != nil {
			writeManagerError(w, err, "unable to list roles")
			return
		}
		writeJSON(w, http.StatusOK, roles)
	default:
		writeError(w, http.StatusNotFound, "not_found", "resource not found")
	}
}

func (h *KeyHandler) listKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := h.manager.List(r.Context())
	if err != nil {
		writeManagerError(w, err, "unable to list API keys")
		return
	}
	writeJSON(w, http.StatusOK, keys)
}

func (h *KeyHandler) createKey(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var input struct {
		Name string `json:"name"`
		Role Role   `json:"role"`
	}
	if err := decoder.Decode(&input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", "request body must contain a valid key name and role")
		return
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		writeError(w, http.StatusBadRequest, "invalid_json", "request must contain exactly one JSON object")
		return
	}
	principal, ok := PrincipalFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication_required", "an administrator API key is required")
		return
	}
	actor := principal.KeyID
	metadata, token, err := h.manager.Create(r.Context(), input.Name, input.Role, &actor)
	if err != nil {
		writeManagerError(w, err, "unable to create API key")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, http.StatusCreated, struct {
		KeyMetadata
		APIKey string `json:"api_key"`
	}{KeyMetadata: metadata, APIKey: token})
}

func (h *KeyHandler) manageKey(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api-keys/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		writeError(w, http.StatusBadRequest, "invalid_api_key_id", "API key ID must be a positive integer")
		return
	}
	id, err := parseKeyID(parts[0])
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_api_key_id", "API key ID must be a positive integer")
		return
	}
	principal, ok := PrincipalFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication_required", "an administrator API key is required")
		return
	}
	actor := principal.KeyID
	switch {
	case len(parts) == 1 && r.Method == http.MethodDelete:
		metadata, err := h.manager.Revoke(r.Context(), id, &actor)
		if err != nil {
			writeManagerError(w, err, "unable to revoke API key")
			return
		}
		writeJSON(w, http.StatusOK, metadata)
	case len(parts) == 2 && parts[1] == "role" && r.Method == http.MethodPatch:
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		var input struct {
			Role Role `json:"role"`
		}
		if err := decoder.Decode(&input); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_json", "request body must contain a valid role")
			return
		}
		var extra any
		if err := decoder.Decode(&extra); err != io.EOF {
			writeError(w, http.StatusBadRequest, "invalid_json", "request must contain exactly one JSON object")
			return
		}
		metadata, err := h.manager.ChangeRole(r.Context(), id, input.Role, &actor)
		if err != nil {
			writeManagerError(w, err, "unable to change API key role")
			return
		}
		writeJSON(w, http.StatusOK, metadata)
	default:
		methodNotAllowed(w, "PATCH, DELETE")
	}
}

func writeManagerError(w http.ResponseWriter, err error, fallback string) {
	switch {
	case errors.Is(err, ErrInvalidRole):
		writeError(w, http.StatusBadRequest, "invalid_role", "role must be reader, writer, or admin")
	case errors.Is(err, ErrInvalidKeyName):
		writeError(w, http.StatusBadRequest, "invalid_key_name", "key name must be between 1 and 100 characters")
	case errors.Is(err, ErrKeyNotFound):
		writeError(w, http.StatusNotFound, "api_key_not_found", "API key not found")
	case errors.Is(err, ErrKeyStorageUnavailable):
		writeError(w, http.StatusServiceUnavailable, "authentication_unavailable", "API key storage is temporarily unavailable")
	default:
		writeError(w, http.StatusInternalServerError, "internal_error", fallback)
	}
}

func methodNotAllowed(w http.ResponseWriter, allow string) {
	w.Header().Set("Allow", allow)
	writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
}
