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

	"github.com/otisjosh/Joseph-Otitigbe/internal/observability"
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
	ErrInvalidExpiry           = errors.New("API key expiry must be in the future")
	ErrKeyStorageUnavailable   = errors.New("API key storage unavailable")
	ErrLastAdmin             = errors.New("cannot remove the last active administrator")
	ErrRotationUnavailable    = errors.New("API key rotation unavailable")
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
	ExpiresAt          *time.Time `json:"expires_at"`
}

// Credential is internal authentication data. Hash must never be serialized or returned by an API.
type Credential struct {
	ID          int64
	PublicID    string
	Hash        []byte `json:"-"`
	Role        Role
	Permissions []Permission
	ExpiresAt   *time.Time `json:"-"`
}

type ExpiringKeyStore interface {
	CreateKeyWithExpiry(ctx context.Context, name string, role Role, publicID string, hash []byte, expiresAt *time.Time, createdBy *int64) (KeyMetadata, error)
}

type RotatingKeyStore interface {
	RotateKey(ctx context.Context, oldID int64, newPublicID string, newHash []byte, role *Role, expiresAt *time.Time, actor *int64) (KeyMetadata, error)
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
	now    func() time.Time
}

func NewKeyManager(store KeyStore) *KeyManager {
	return &KeyManager{store: store, random: rand.Reader, now: time.Now}
}

func (m *KeyManager) Create(ctx context.Context, name string, role Role, actor *int64) (KeyMetadata, string, error) {
	return m.CreateWithExpiry(ctx, name, role, nil, actor)
}

func (m *KeyManager) CreateWithExpiry(ctx context.Context, name string, role Role, expiresAt *time.Time, actor *int64) (KeyMetadata, string, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 100 {
		return KeyMetadata{}, "", ErrInvalidKeyName
	}
	if !ValidRole(role) {
		return KeyMetadata{}, "", ErrInvalidRole
	}
	if expiresAt != nil {
		expiry := expiresAt.UTC()
		if !m.now().UTC().Before(expiry) {
			return KeyMetadata{}, "", ErrInvalidExpiry
		}
		expiresAt = &expiry
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
	var metadata KeyMetadata
	var err error
	if expiresAt == nil {
		metadata, err = m.store.CreateKey(ctx, name, role, publicID, hash[:], actor)
	} else if store, ok := m.store.(ExpiringKeyStore); ok {
		metadata, err = store.CreateKeyWithExpiry(ctx, name, role, publicID, hash[:], expiresAt, actor)
	} else {
		return KeyMetadata{}, "", ErrKeyStorageUnavailable
	}
	if err != nil {
		return KeyMetadata{}, "", err
	}
	return metadata, token, nil
}

func (m *KeyManager) Rotate(ctx context.Context, id int64, role *Role, expiresAt *time.Time, actor *int64) (KeyMetadata, string, error) {
	if id < 1 {
		return KeyMetadata{}, "", ErrKeyNotFound
	}
	if role != nil && !ValidRole(*role) {
		return KeyMetadata{}, "", ErrInvalidRole
	}
	if expiresAt != nil {
		expiry := expiresAt.UTC()
		if !m.now().UTC().Before(expiry) {
			return KeyMetadata{}, "", ErrInvalidExpiry
		}
		expiresAt = &expiry
	}
	store, ok := m.store.(RotatingKeyStore)
	if !ok {
		return KeyMetadata{}, "", ErrRotationUnavailable
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
	metadata, err := store.RotateKey(ctx, id, publicID, hash[:], role, expiresAt, actor)
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

func ContextWithPrincipal(ctx context.Context, principal Principal) context.Context {
	return context.WithValue(ctx, principalContextKey{}, principal)
}

func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	principal, ok := ctx.Value(principalContextKey{}).(Principal)
	return principal, ok
}

type RequestLimiter interface {
	AllowRemoteAddr(remoteAddr string, w http.ResponseWriter) bool
	AllowAPIKey(id int64, w http.ResponseWriter) bool
}

// AuthenticationAuditor records bounded authentication outcomes. identity is used
// only by its in-memory sampling gate and must never be persisted.
type AuthenticationAuditor interface {
	RecordAuthentication(ctx context.Context, outcome, reason, requestID string, actorKeyID *int64, identity string) error
}

func Middleware(store KeyStore, next http.Handler) http.Handler {
	return MiddlewareWithLimiterAndAuditor(store, next, nil, nil)
}

func MiddlewareWithLimiter(store KeyStore, next http.Handler, limiter RequestLimiter) http.Handler {
	return MiddlewareWithLimiterAndAuditor(store, next, limiter, nil)
}

func MiddlewareWithAuditor(store KeyStore, next http.Handler, auditor AuthenticationAuditor) http.Handler {
	return MiddlewareWithLimiterAndAuditor(store, next, nil, auditor)
}

func MiddlewareWithLimiterAndAuditor(store KeyStore, next http.Handler, limiter RequestLimiter, auditor AuthenticationAuditor) http.Handler {
	return middlewareWithClockAndAuditor(store, next, limiter, auditor, time.Now)
}

func middlewareWithClock(store KeyStore, next http.Handler, limiter RequestLimiter, now func() time.Time) http.Handler {
	return middlewareWithClockAndAuditor(store, next, limiter, nil, now)
}

func middlewareWithClockAndAuditor(store KeyStore, next http.Handler, limiter RequestLimiter, auditor AuthenticationAuditor, now func() time.Time) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
			next.ServeHTTP(w, r)
			return
		}
		required, protected := RequiredPermission(r.Method, r.URL.Path)
		if !protected {
			next.ServeHTTP(w, r)
			return
		}
		if limiter != nil && !limiter.AllowRemoteAddr(r.RemoteAddr, w) {
			return
		}
		recordAuth := func(outcome, reason string, actorKeyID *int64) bool {
			if auditor == nil {
				return true
			}
			requestID, _ := observability.RequestIDFromContext(r.Context())
			identity := "source:" + r.RemoteAddr
			if actorKeyID != nil {
				identity = fmt.Sprintf("key:%d", *actorKeyID)
			}
			if err := auditor.RecordAuthentication(r.Context(), outcome, reason, requestID, actorKeyID, identity); err != nil {
				writeError(w, http.StatusServiceUnavailable, "authentication_unavailable", "authentication is temporarily unavailable")
				return false
			}
			return true
		}
		unauthorized := func(code, message, reason string) {
			if !recordAuth("failure", reason, nil) {
				return
			}
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeError(w, http.StatusUnauthorized, code, message)
		}

		header := r.Header.Get("Authorization")
		if header == "" {
			unauthorized("authentication_required", "a bearer API key is required", "missing_authorization")
			return
		}
		token, ok := bearerToken(header)
		if !ok {
			unauthorized("invalid_api_key", "the bearer API key is invalid", "invalid_authorization")
			return
		}
		publicID, secret, ok := parseToken(token)
		if !ok {
			unauthorized("invalid_api_key", "the bearer API key is invalid", "invalid_credential")
			return
		}
		defer clear(secret)
		hash := sha256.Sum256(secret)
		credential, err := store.LookupKey(r.Context(), publicID)
		if errors.Is(err, ErrInvalidKey) {
			unauthorized("invalid_api_key", "the bearer API key is invalid", "invalid_credential")
			return
		}
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "authentication_unavailable", "authentication is temporarily unavailable")
			return
		}
		if len(credential.Hash) != len(hash) || subtle.ConstantTimeCompare(credential.Hash, hash[:]) != 1 {
			unauthorized("invalid_api_key", "the bearer API key is invalid", "invalid_credential")
			return
		}
		if credential.ExpiresAt != nil && !now().UTC().Before(credential.ExpiresAt.UTC()) {
			unauthorized("invalid_api_key", "the bearer API key is invalid", "invalid_credential")
			return
		}
		if limiter != nil && !limiter.AllowAPIKey(credential.ID, w) {
			return
		}
		if err := store.TouchKey(r.Context(), credential.ID); errors.Is(err, ErrInvalidKey) {
			unauthorized("invalid_api_key", "the bearer API key is invalid", "invalid_credential")
			return
		} else if err != nil {
			writeError(w, http.StatusServiceUnavailable, "authentication_unavailable", "authentication is temporarily unavailable")
			return
		}
		if credential.ExpiresAt != nil && !now().UTC().Before(credential.ExpiresAt.UTC()) {
			unauthorized("invalid_api_key", "the bearer API key is invalid", "invalid_credential")
			return
		}
		if !recordAuth("success", "", &credential.ID) {
			return
		}
		if !hasPermission(credential.Permissions, required) {
			writeError(w, http.StatusForbidden, "permission_denied", "the API key does not have permission for this operation")
			return
		}
		principal := Principal{KeyID: credential.ID, Role: credential.Role, Permissions: credential.Permissions}
		ctx := ContextWithPrincipal(r.Context(), principal)
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
	case path == "/api-keys" || strings.HasPrefix(path, "/api-keys/") || path == "/roles" || path == "/audit-logs":
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
