package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"flag"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/otisjosh/Joseph-Otitigbe/internal/audit"
	"github.com/otisjosh/Joseph-Otitigbe/internal/auth"
	"github.com/otisjosh/Joseph-Otitigbe/internal/observability"
	"github.com/otisjosh/Joseph-Otitigbe/internal/postgres"
	"github.com/otisjosh/Joseph-Otitigbe/internal/records"
)

func newJSONLogger(output io.Writer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(output, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

type safeHTTPErrorWriter struct {
	logger *slog.Logger
}

func (w safeHTTPErrorWriter) Write(message []byte) (int, error) {
	w.logger.Error("http_server_internal_error")
	return len(message), nil
}

func newServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
}

func loadDatabaseURL(getenv func(string) string) (string, error) {
	databaseURL := strings.TrimSpace(getenv("DATABASE_URL"))
	if databaseURL == "" {
		return "", errors.New("DATABASE_URL is required")
	}
	if _, err := pgxpool.ParseConfig(databaseURL); err != nil {
		return "", errors.New("DATABASE_URL is invalid")
	}
	return databaseURL, nil
}

func loadListenAddress(getenv func(string) string) (string, error) {
	addr := getenv("ATLAS_ADDR")
	if addr == "" {
		return ":8080", nil
	}
	if strings.TrimSpace(addr) != addr {
		return "", errors.New("ATLAS_ADDR must be a valid host:port address")
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return "", errors.New("ATLAS_ADDR must be a valid host:port address")
	}
	return addr, nil
}

func openDatabase(ctx context.Context) (*postgres.KeyStore, *postgres.Store, *pgxpool.Pool, error) {
	databaseURL, err := loadDatabaseURL(os.Getenv)
	if err != nil {
		return nil, nil, nil, err
	}
	return openDatabaseURL(ctx, databaseURL)
}

func openDatabaseURL(ctx context.Context, databaseURL string) (*postgres.KeyStore, *postgres.Store, *pgxpool.Pool, error) {
	pool, err := postgres.Open(ctx, databaseURL)
	if err != nil {
		return nil, nil, nil, err
	}
	return postgres.NewKeyStore(pool), postgres.NewStore(pool), pool, nil
}

func routes(keyStore *postgres.KeyStore, recordStore *postgres.Store, pinger observability.Pinger, logger *slog.Logger) http.Handler {
	mux := http.NewServeMux()
	recordHandler := records.NewHandler(recordStore)
	keyHandler := auth.NewKeyHandler(auth.NewKeyManager(keyStore))
	auditHandler := audit.NewHandler(keyStore.AuditStore())
	mux.Handle("/healthz", recordHandler)
	mux.Handle("/readyz", observability.NewReadinessHandler(pinger, 2*time.Second))
	mux.Handle("/records", recordHandler)
	mux.Handle("/records/", recordHandler)
	mux.Handle("/api-keys", keyHandler)
	mux.Handle("/api-keys/", keyHandler)
	mux.Handle("/roles", keyHandler)
	mux.Handle("/audit-logs", auditHandler)
	return observability.RequestLogging(logger, auth.Middleware(keyStore, mux))
}

func runServer() error {
	databaseURL, err := loadDatabaseURL(os.Getenv)
	if err != nil {
		return err
	}
	addr, err := loadListenAddress(os.Getenv)
	if err != nil {
		return err
	}

	startupCtx, cancelStartup := context.WithTimeout(context.Background(), 20*time.Second)
	keyStore, recordStore, closer, err := openDatabaseURL(startupCtx, databaseURL)
	cancelStartup()
	if err != nil {
		return err
	}

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		closer.Close()
		return fmt.Errorf("listen on configured ATLAS_ADDR: %w", err)
	}

	logger := newJSONLogger(os.Stderr)
	server := newServer(addr, routes(keyStore, recordStore, closer, logger))
	server.ErrorLog = log.New(safeHTTPErrorWriter{logger: logger}, "", 0)
	shutdownCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	return serveHTTP(shutdownCtx, server, listener, closer.Close, logger)
}

func serveHTTP(ctx context.Context, server *http.Server, listener net.Listener, closeDatabase func(), logger *slog.Logger) error {
	if closeDatabase != nil {
		defer closeDatabase()
	}
	serverErrors := make(chan error, 1)
	go func() {
		logger.Info("server_started")
		serverErrors <- server.Serve(listener)
	}()

	select {
	case err := <-serverErrors:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			_ = server.Close()
			return err
		}
		err := <-serverErrors
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
}
func provisionKey(args []string) error {
	flags := flag.NewFlagSet("provision-key", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	name := flags.String("name", "", "human-readable API key name")
	role := flags.String("role", "", "role: reader, writer, or admin")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if *name == "" || *role == "" {
		return errors.New("provision-key requires --name and --role")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	keyStore, _, closer, err := openDatabase(ctx)
	if err != nil {
		return err
	}
	defer closer.Close()

	metadata, apiKey, err := auth.NewKeyManager(keyStore).Create(ctx, *name, auth.Role(*role), nil)
	if err != nil {
		return err
	}
	// The raw key is intentionally emitted once to stdout for secure operator capture.
	return json.NewEncoder(os.Stdout).Encode(struct {
		auth.KeyMetadata
		APIKey string `json:"api_key"`
	}{KeyMetadata: metadata, APIKey: apiKey})
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "provision-key" {
		if err := provisionKey(os.Args[2:]); err != nil {
			newJSONLogger(os.Stderr).Error("provision_key_failed")
			os.Exit(1)
		}
		return
	}
	if err := runServer(); err != nil {
		newJSONLogger(os.Stderr).Error("server_failed")
		os.Exit(1)
	}
}
