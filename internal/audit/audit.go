package audit

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"
)

const (
	DefaultPageSize = 100
	MaxPageSize     = 500
)

type Event struct {
	ID int64 `json:"id"`
	OccurredAt time.Time `json:"occurred_at"`
	ActorKeyID *int64 `json:"actor_key_id,omitempty"`
	Action string `json:"action"`
	ResourceType string `json:"resource_type"`
	ResourceID *int64 `json:"resource_id,omitempty"`
	Details map[string]string `json:"details"`
	RequestID string `json:"request_id,omitempty"`
	Outcome string `json:"outcome,omitempty"`
}

type Store interface {
	ListEvents(context.Context, int, int64) ([]Event, error)
}

type Handler struct { store Store }

func NewHandler(store Store) http.Handler { return &Handler{store: store} }

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	limit := DefaultPageSize
	if raw := r.URL.Query().Get("limit"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 || value > MaxPageSize {
			writeError(w, http.StatusBadRequest, "invalid_limit", "limit must be between 1 and 500")
			return
		}
		limit = value
	}
	var beforeID int64
	if raw := r.URL.Query().Get("before_id"); raw != "" {
		value, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || value < 1 || strconv.FormatInt(value, 10) != raw {
			writeError(w, http.StatusBadRequest, "invalid_before_id", "before_id must be a positive integer")
			return
		}
		beforeID = value
	}
	events, err := h.store.ListEvents(r.Context(), limit, beforeID)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "audit_unavailable", "audit log is temporarily unavailable")
		return
	}
	writeJSON(w, http.StatusOK, struct { Events []Event `json:"events"` }{Events: events})
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": code, "message": message}})
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
