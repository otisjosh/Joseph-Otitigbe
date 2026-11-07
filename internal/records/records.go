package records

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

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
	at := strings.IndexByte(email, '@')
	return at > 0 && at < len(email)-1 && !strings.ContainsAny(email, " \t\r\n")
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
	case r.URL.Path == "/healthz" && r.Method == http.MethodGet:
		w.WriteHeader(http.StatusOK)
	case r.URL.Path == "/records" && r.Method == http.MethodPost:
		h.createRecord(w, r)
	case strings.HasPrefix(r.URL.Path, "/records/") && r.Method == http.MethodGet:
		h.getRecord(w, r)
	case r.URL.Path == "/records" || strings.HasPrefix(r.URL.Path, "/records/"):
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	default:
		http.NotFound(w, r)
	}
}

func (h *Handler) createRecord(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var input struct {
		Name  string `json:"name"`
		Email string `json:"email"`
	}
	if err := decoder.Decode(&input); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		http.Error(w, "request must contain one JSON object", http.StatusBadRequest)
		return
	}

	record, err := h.store.Create(input.Name, input.Email)
	switch {
	case errors.Is(err, ErrInvalidRecord):
		http.Error(w, err.Error(), http.StatusBadRequest)
	case errors.Is(err, ErrDuplicate):
		http.Error(w, err.Error(), http.StatusConflict)
	case err != nil:
		http.Error(w, "unable to create record", http.StatusInternalServerError)
	default:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(record)
	}
}

func (h *Handler) getRecord(w http.ResponseWriter, r *http.Request) {
	parsedID, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/records/"))
	if err != nil || parsedID < 1 {
		http.NotFound(w, r)
		return
	}
	record, ok := h.store.Get(parsedID)
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(record)
}
