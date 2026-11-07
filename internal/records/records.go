package records

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/mail"
	"strconv"
	"strings"
	"sync"
)

const maxRequestBody = 1 << 20

var (
	ErrInvalidRecord = errors.New("name and a valid email are required")
	ErrDuplicate     = errors.New("a record with this email already exists")
)

type Record struct {
	ID    int    `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

type Store struct {
	mu      sync.RWMutex
	nextID  int
	records map[int]Record
	emails  map[string]int
}

func NewStore() *Store {
	return &Store{nextID: 1, records: make(map[int]Record), emails: make(map[string]int)}
}

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func validEmail(email string) bool {
	if len(email) > 254 {
		return false
	}
	address, err := mail.ParseAddress(email)
	if err != nil || address.Address != email {
		return false
	}
	at := strings.LastIndexByte(email, '@')
	if at <= 0 || at == len(email)-1 {
		return false
	}
	domain := email[at+1:]
	if !strings.Contains(domain, ".") || strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if label == "" || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}

func (s *Store) Create(name, email string) (Record, error) {
	name = strings.TrimSpace(name)
	email = strings.TrimSpace(email)
	if name == "" || !validEmail(email) {
		return Record{}, ErrInvalidRecord
	}

	key := normalizeEmail(email)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.emails[key]; exists {
		return Record{}, ErrDuplicate
	}
	record := Record{ID: s.nextID, Name: name, Email: email}
	s.nextID++
	s.records[record.ID] = record
	s.emails[key] = record.ID
	return record, nil
}

func (s *Store) Get(id int) (Record, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, ok := s.records[id]
	return record, ok
}

type Handler struct {
	store *Store
}

func NewHandler() http.Handler {
	return &Handler{store: NewStore()}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/healthz":
		if r.Method != http.MethodGet {
			methodNotAllowed(w, http.MethodGet)
			return
		}
		w.WriteHeader(http.StatusOK)
	case r.URL.Path == "/records":
		if r.Method != http.MethodPost {
			methodNotAllowed(w, http.MethodPost)
			return
		}
		h.createRecord(w, r)
	case strings.HasPrefix(r.URL.Path, "/records/"):
		if r.Method != http.MethodGet {
			methodNotAllowed(w, http.MethodGet)
			return
		}
		h.getRecord(w, r)
	default:
		writeError(w, http.StatusNotFound, "not_found", "resource not found")
	}
}

func methodNotAllowed(w http.ResponseWriter, allowed string) {
	w.Header().Set("Allow", allowed)
	writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}{Error: struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}{Code: code, Message: message}})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func (h *Handler) createRecord(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var input struct {
		Name  string `json:"name"`
		Email string `json:"email"`
	}
	if err := decoder.Decode(&input); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "request_too_large", "request body exceeds the 1 MiB limit")
		} else {
			writeError(w, http.StatusBadRequest, "invalid_json", "request body must be a valid record object")
		}
		return
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		writeError(w, http.StatusBadRequest, "invalid_json", "request must contain exactly one JSON object")
		return
	}

	record, err := h.store.Create(input.Name, input.Email)
	switch {
	case errors.Is(err, ErrInvalidRecord):
		writeError(w, http.StatusBadRequest, "invalid_record", err.Error())
	case errors.Is(err, ErrDuplicate):
		writeError(w, http.StatusConflict, "duplicate_record", err.Error())
	case err != nil:
		writeError(w, http.StatusInternalServerError, "internal_error", "unable to create record")
	default:
		writeJSON(w, http.StatusCreated, record)
	}
}

func (h *Handler) getRecord(w http.ResponseWriter, r *http.Request) {
	rawID := strings.TrimPrefix(r.URL.Path, "/records/")
	id, err := strconv.Atoi(rawID)
	if err != nil || id < 1 || strconv.Itoa(id) != rawID {
		writeError(w, http.StatusBadRequest, "invalid_record_id", "record ID must be a positive integer")
		return
	}
	record, ok := h.store.Get(id)
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "record not found")
		return
	}
	writeJSON(w, http.StatusOK, record)
}
