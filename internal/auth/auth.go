package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type Role string
type Permission string

const (
	RoleReader Role = "reader"
	RoleWriter Role = "writer"
	RoleAdmin  Role = "admin"

	PermissionRecordsRead  Permission = "records:read"
	PermissionRecordsWrite Permission = "records:write"
	PermissionKeysManage   Permission = "keys:manage"
)

var (
	ErrInvalidKey              = errors.New("invalid API key")
	ErrKeyNotFound             = errors.New("API key not found")
	ErrInvalidRole             = errors.New("invalid role")
	ErrInvalidKeyName          = errors.New("invalid API key name")
	ErrKeyStorageUnavailable   = errors.New("API key storage unavailable")
)

const apiKeyPrefix = "atlas_"

type RoleInfo struct {
	Name        Role         `json:"name"`
	Description string       `json:"description"`
	Permissions []Permission `json:"permissions"`
}

type KeyMetadata struct {
	ID                 int64      `json:"id"`
	PublicID           string     `json:"public_id"`
	Name               string     `json:"name"`
	Role               Role       `json:"role"`
	CreatedAt          time.Time  `json:"created_at"`
	CreatedByKeyID     *int64     `json:"created_by_key_id,omitempty"`
	RevokedAt          *time.Time `json:"revoked_at,omitempty"`
	RevokedByKeyID     *int64     `json:"revoked_by_key_id,omitempty"`
	LastUsedAt         *time.Time `json:"last_used_at,omitempty"`
	RoleChangedAt      *time.Time `json:"role_changed_at,omitempty"`
	RoleChangedByKeyID *int64     `json:"role_changed_by_key_id,omitempty"`
}

// Credential is internal authentication data. Hash must never be serialized or returned by an API.
type Credential struct {
	ID          int64
	PublicID    string
	Hash        []byte `json:"-"`
	Role        Role
	Permissions []Permission
}

type KeyStore interface {
	CreateKey(ctx context.Context, name string, role Role, publicID string, hash []byte, createdBy *int64) (KeyMetadata, error)
	LookupKey(ctx context.Context, publicID string) (Credential, error)
	TouchKey(ctx context.Context, id int64) error
	ListKeys(ctx context.Context) ([]KeyMetadata, error)
	RevokeKey(ctx context.Context, id int64, actor *int64) (KeyMetadata, error)
	ChangeKeyRole(ctx context.Context, id int64, role Role, actor *int64) (KeyMetadata, error)
	ListRoles(ctx context.Context) ([]RoleInfo, error)
}

type KeyManager struct {
	store  KeyStore
	random io.Reader
}

func NewKeyManager(store KeyStore) *KeyManager {
	return &KeyManager{store: store, random: rand.Reader}
}

func (m *KeyManager) Create(ctx context.Context, name string, role Role, actor *int64) (KeyMetadata, string, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 100 {
		return KeyMetadata{}, "", ErrInvalidKeyName
	}
	if !ValidRole(role) {
		return KeyMetadata{}, "", ErrInvalidRole
	}
	publicBytes := make([]byte, 16)
	secret := make([]byte, 32)
	if _, err := io.ReadFull(m.random, publicBytes); err != nil {
		return KeyMetadata{}, "", fmt.Errorf("generate API key identifier: %w", err)
	}
	if _, err := io.ReadFull(m.random, secret); err != nil {
		return KeyMetadata{}, "", fmt.Errorf("generate API key secret: %w", err)
	}
	defer clear(secret)

	publicID := base64.RawURLEncoding.EncodeToString(publicBytes)
	token := apiKeyPrefix + publicID + "." + base64.RawURLEncoding.EncodeToString(secret)
	hash := sha256.Sum256(secret)
	metadata, err := m.store.CreateKey(ctx, name, role, publicID, hash[:], actor)
	if err != nil {
		return KeyMetadata{}, "", err
	}
	return metadata, token, nil
}

func (m *KeyManager) List(ctx context.Context) ([]KeyMetadata, error) {
	return m.store.ListKeys(ctx)
}

func (m *KeyManager) Revoke(ctx context.Context, id int64, actor *int64) (KeyMetadata, error) {
	return m.store.RevokeKey(ctx, id, actor)
}

func (m *KeyManager) ChangeRole(ctx context.Context, id int64, role Role, actor *int64) (KeyMetadata, error) {
	if !ValidRole(role) {
		return KeyMetadata{}, ErrInvalidRole
	}
	return m.store.ChangeKeyRole(ctx, id, role, actor)
}

func (m *KeyManager) Roles(ctx context.Context) ([]RoleInfo, error) {
	return m.store.ListRoles(ctx)
}

func ValidRole(role Role) bool {
	return role == RoleReader || role == RoleWriter || role == RoleAdmin
}

type Principal struct {
	KeyID       int64
	Role        Role
	Permissions []Permission
}

type principalContextKey struct{}

func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	principal, ok := ctx.Value(principalContextKey{}).(Principal)
	return principal, ok
}

func Middleware(store KeyStore, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		required, protected := RequiredPermission(r.Method, r.URL.Path)
		if !protected {
			next.ServeHTTP(w, r)
			return
		}
		header := r.Header.Get("Authorization")
		if header == "" {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeError(w, http.StatusUnauthorized, "authentication_required", "a bearer API key is required")
			return
		}
		token, ok := bearerToken(header)
		if !ok {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeError(w, http.StatusUnauthorized, "invalid_api_key", "the bearer API key is invalid")
			return
		}
		publicID, secret, ok := parseToken(token)
		if !ok {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeError(w, http.StatusUnauthorized, "invalid_api_key", "the bearer API key is invalid")
			return
		}
		defer clear(secret)
		hash := sha256.Sum256(secret)
		credential, err := store.LookupKey(r.Context(), publicID)
		if errors.Is(err, ErrInvalidKey) {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeError(w, http.StatusUnauthorized, "invalid_api_key", "the bearer API key is invalid")
			return
		}
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "authentication_unavailable", "authentication is temporarily unavailable")
			return
		}
		if len(credential.Hash) != len(hash) || subtle.ConstantTimeCompare(credential.Hash, hash[:]) != 1 {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeError(w, http.StatusUnauthorized, "invalid_api_key", "the bearer API key is invalid")
			return
		}
		if err := store.TouchKey(r.Context(), credential.ID); errors.Is(err, ErrInvalidKey) {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeError(w, http.StatusUnauthorized, "invalid_api_key", "the bearer API key is invalid")
			return
		} else if err != nil {
			writeError(w, http.StatusServiceUnavailable, "authentication_unavailable", "authentication is temporarily unavailable")
			return
		}
		if !hasPermission(credential.Permissions, required) {
			writeError(w, http.StatusForbidden, "permission_denied", "the API key does not have permission for this operation")
			return
		}
		principal := Principal{KeyID: credential.ID, Role: credential.Role, Permissions: credential.Permissions}
		ctx := context.WithValue(r.Context(), principalContextKey{}, principal)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func RequiredPermission(method, path string) (Permission, bool) {
	switch {
	case path == "/records":
		if method == http.MethodPost {
			return PermissionRecordsWrite, true
		}
		return PermissionRecordsRead, true
	case strings.HasPrefix(path, "/records/"):
		return PermissionRecordsRead, true
	case path == "/api-keys" || strings.HasPrefix(path, "/api-keys/") || path == "/roles":
		return PermissionKeysManage, true
	default:
		return "", false
	}
}

func hasPermission(permissions []Permission, required Permission) bool {
	for _, permission := range permissions {
		if permission == required {
			return true
		}
	}
	return false
}

func bearerToken(header string) (string, bool) {
	scheme, token, ok := strings.Cut(header, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || token == "" || strings.ContainsAny(token, " \t\r\n") {
		return "", false
	}
	return token, true
}

func parseToken(token string) (string, []byte, bool) {
	if !strings.HasPrefix(token, apiKeyPrefix) {
		return "", nil, false
	}
	parts := strings.Split(strings.TrimPrefix(token, apiKeyPrefix), ".")
	if len(parts) != 2 {
		return "", nil, false
	}
	publicBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || len(publicBytes) != 16 || base64.RawURLEncoding.EncodeToString(publicBytes) != parts[0] {
		return "", nil, false
	}
	secret, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(secret) != 32 || base64.RawURLEncoding.EncodeToString(secret) != parts[1] {
		return "", nil, false
	}
	return parts[0], secret, true
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

func parseKeyID(raw string) (int64, error) {
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id < 1 || strconv.FormatInt(id, 10) != raw {
		return 0, errors.New("invalid API key ID")
	}
	return id, nil
}
