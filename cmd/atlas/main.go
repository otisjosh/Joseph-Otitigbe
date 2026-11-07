package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/otisjosh/Joseph-Otitigbe/internal/postgres"
	"github.com/otisjosh/Joseph-Otitigbe/internal/records"
)

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

func run() error {
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		return errors.New("DATABASE_URL is required")
	}
	startupCtx, cancelStartup := context.WithTimeout(context.Background(), 20*time.Second)
	pool, err := postgres.Open(startupCtx, databaseURL)
	cancelStartup()
	if err != nil {
		return err
	}
	defer pool.Close()

	addr := os.Getenv("ATLAS_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	server := newServer(addr, records.NewHandler(postgres.NewStore(pool)))
	shutdownCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	serverErrors := make(chan error, 1)
	go func() {
		log.Printf("Atlas API listening on %s", addr)
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

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
