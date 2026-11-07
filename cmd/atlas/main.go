package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log/slog"
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

func openDatabase(ctx context.Context) (*postgres.KeyStore, *postgres.Store, *pgxpool.Pool, error) {
	databaseURL := os.Getenv("DATABASE_URL")
	if strings.TrimSpace(databaseURL) == "" {
		return nil, nil, nil, errors.New("DATABASE_URL is required")
	}
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
	startupCtx, cancelStartup := context.WithTimeout(context.Background(), 20*time.Second)
	keyStore, recordStore, closer, err := openDatabase(startupCtx)
	cancelStartup()
	if err != nil {
		return err
	}
	defer closer.Close()

	addr := os.Getenv("ATLAS_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	server := newServer(addr, routes(keyStore, recordStore, closer, newJSONLogger(os.Stderr)))
	shutdownCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	serverErrors := make(chan error, 1)
	go func() {
		newJSONLogger(os.Stderr).Info("server_started", "address", addr)
		serverErrors <- server.ListenAndServe()
	}()

	select {
	case err := <-serverErrors:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-shutdownCtx.Done():
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
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
