package ratelimit

import (
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type ConfigError struct {
	message string
}

func (e ConfigError) Error() string { return e.message }

type Config struct {
	MaxConcurrentRequests int
	RequestsPerAPIKey     int
	RequestsPerIP         int
	Window                time.Duration
	MaxClients            int
}

func DefaultConfig() Config {
	return Config{
		MaxConcurrentRequests: 256,
		RequestsPerAPIKey:     120,
		RequestsPerIP:         600,
		Window:                time.Minute,
		MaxClients:            10000,
	}
}

func LoadConfig(getenv func(string) string) (Config, error) {
	config := DefaultConfig()
	var err error
	if config.MaxConcurrentRequests, err = intSetting(getenv, "ATLAS_MAX_CONCURRENT_REQUESTS", config.MaxConcurrentRequests, 1, 10000); err != nil {
		return Config{}, err
	}
	if config.RequestsPerAPIKey, err = intSetting(getenv, "ATLAS_RATE_LIMIT_PER_KEY", config.RequestsPerAPIKey, 0, 1000000); err != nil {
		return Config{}, err
	}
	if config.RequestsPerIP, err = intSetting(getenv, "ATLAS_RATE_LIMIT_PER_IP", config.RequestsPerIP, 0, 1000000); err != nil {
		return Config{}, err
	}
	if config.MaxClients, err = intSetting(getenv, "ATLAS_RATE_LIMIT_MAX_CLIENTS", config.MaxClients, 1, 100000); err != nil {
		return Config{}, err
	}
	if raw := strings.TrimSpace(getenv("ATLAS_RATE_LIMIT_WINDOW")); raw != "" {
		window, parseErr := time.ParseDuration(raw)
		if parseErr != nil || window < time.Second || window > 24*time.Hour {
			return Config{}, ConfigError{message: "ATLAS_RATE_LIMIT_WINDOW must be a duration between 1s and 24h"}
		}
		config.Window = window
	}
	return config, nil
}

func intSetting(getenv func(string) string, name string, fallback, min, max int) (int, error) {
	raw := strings.TrimSpace(getenv(name))
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < min || value > max {
		return 0, ConfigError{message: fmt.Sprintf("%s must be between %d and %d", name, min, max)}
	}
	return value, nil
}

type bucket struct {
	start time.Time
	count int
}

type Limiter struct {
	config Config
	mu     sync.Mutex
	keys   map[int64]bucket
	ips    map[string]bucket
	nextSweep time.Time
	now    func() time.Time
	inFlight chan struct{}
}

func New(config Config) (*Limiter, error) {
	if config.MaxConcurrentRequests < 1 || config.MaxConcurrentRequests > 10000 {
		return nil, ConfigError{message: "ATLAS_MAX_CONCURRENT_REQUESTS must be between 1 and 10000"}
	}
	if config.RequestsPerAPIKey < 0 || config.RequestsPerAPIKey > 1000000 {
		return nil, ConfigError{message: "ATLAS_RATE_LIMIT_PER_KEY must be between 0 and 1000000"}
	}
	if config.RequestsPerIP < 0 || config.RequestsPerIP > 1000000 {
		return nil, ConfigError{message: "ATLAS_RATE_LIMIT_PER_IP must be between 0 and 1000000"}
	}
	if config.Window < time.Second || config.Window > 24*time.Hour {
		return nil, ConfigError{message: "ATLAS_RATE_LIMIT_WINDOW must be a duration between 1s and 24h"}
	}
	if config.MaxClients < 1 || config.MaxClients > 100000 {
		return nil, ConfigError{message: "ATLAS_RATE_LIMIT_MAX_CLIENTS must be between 1 and 100000"}
	}
	return &Limiter{
		config:   config,
		keys:     make(map[int64]bucket),
		ips:      make(map[string]bucket),
		now:      time.Now,
		inFlight: make(chan struct{}, config.MaxConcurrentRequests),
	}, nil
}

type decision struct {
	allowed   bool
	limit     int
	remaining int
	reset     time.Time
	now       time.Time
}

func (l *Limiter) AllowAPIKey(id int64, w http.ResponseWriter) bool {
	if l.config.RequestsPerAPIKey == 0 {
		return true
	}
	d := l.allowKey(id)
	writeHeaders(w, d)
	if !d.allowed {
		writeLimited(w, d)
	}
	return d.allowed
}

func (l *Limiter) AllowRemoteAddr(remoteAddr string, w http.ResponseWriter) bool {
	if l.config.RequestsPerIP == 0 {
		return true
	}
	ip := sourceIP(remoteAddr)
	d := l.allowIP(ip)
	writeHeaders(w, d)
	if !d.allowed {
		writeLimited(w, d)
	}
	return d.allowed
}

func (l *Limiter) allowKey(id int64) decision {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sweepLocked(now)
	return allowBucket(l.keys, id, l.config.RequestsPerAPIKey, l.config.MaxClients, l.config.Window, now)
}

func (l *Limiter) allowIP(ip string) decision {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sweepLocked(now)
	return allowBucket(l.ips, ip, l.config.RequestsPerIP, l.config.MaxClients, l.config.Window, now)
}

func allowBucket[K comparable](entries map[K]bucket, key K, limit, capacity int, window time.Duration, now time.Time) decision {
	current, exists := entries[key]
	if exists && !now.Before(current.start.Add(window)) {
		delete(entries, key)
		exists = false
	}
	if !exists {
		if len(entries) >= capacity {
			for existingKey, value := range entries {
				if !now.Before(value.start.Add(window)) {
					delete(entries, existingKey)
				}
			}
		}
		if len(entries) >= capacity {
			return decision{allowed: false, limit: limit, remaining: 0, reset: now.Add(time.Second), now: now}
		}
		current = bucket{start: now}
	}
	if current.count >= limit {
		return decision{allowed: false, limit: limit, remaining: 0, reset: current.start.Add(window), now: now}
	}
	current.count++
	entries[key] = current
	return decision{allowed: true, limit: limit, remaining: limit - current.count, reset: current.start.Add(window), now: now}
}

func (l *Limiter) sweepLocked(now time.Time) {
	if !l.nextSweep.IsZero() && now.Before(l.nextSweep) {
		return
	}
	for key, value := range l.keys {
		if !now.Before(value.start.Add(l.config.Window)) {
			delete(l.keys, key)
		}
	}
	for key, value := range l.ips {
		if !now.Before(value.start.Add(l.config.Window)) {
			delete(l.ips, key)
		}
	}
	interval := l.config.Window
	if interval > 30*time.Second {
		interval = 30 * time.Second
	}
	l.nextSweep = now.Add(interval)
}

// EntryCounts returns the number of tracked key and source entries for monitoring and tests.
func (l *Limiter) EntryCounts() (keys, ips int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.keys), len(l.ips)
}

func sourceIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil {
		if ip := net.ParseIP(host); ip != nil {
			return ip.String()
		}
		if host != "" && len(host) <= 128 {
			return strings.ToLower(host)
		}
		return "unknown"
	}
	if ip := net.ParseIP(remoteAddr); ip != nil {
		return ip.String()
	}
	return "unknown"
}

func writeHeaders(w http.ResponseWriter, d decision) {
	if d.limit <= 0 {
		return
	}
	reset := secondsUntil(d.reset, d.now)
	w.Header().Set("RateLimit-Limit", strconv.Itoa(d.limit))
	w.Header().Set("RateLimit-Remaining", strconv.Itoa(d.remaining))
	w.Header().Set("RateLimit-Reset", strconv.Itoa(reset))
}

func secondsUntil(target, now time.Time) int {
	seconds := math.Ceil(target.Sub(now).Seconds())
	if seconds < 1 {
		return 1
	}
	return int(seconds)
}

func writeLimited(w http.ResponseWriter, d decision) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Retry-After", strconv.Itoa(secondsUntil(d.reset, d.now)))
	w.WriteHeader(http.StatusTooManyRequests)
	_ = json.NewEncoder(w).Encode(struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}{Error: struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}{Code: "rate_limited", Message: "request rate limit exceeded"}})
}

func (l *Limiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case l.inFlight <- struct{}{}:
			defer func() { <-l.inFlight }()
			next.ServeHTTP(w, r)
		default:
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{
				"code": "rate_limited", "message": "request rate limit exceeded",
			}})
		}
	})
}
