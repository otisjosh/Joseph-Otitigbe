package main

import (
	"log"
	"net/http"
	"os"
	"time"

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

func main() {
	addr := os.Getenv("ATLAS_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	server := newServer(addr, records.NewHandler())
	log.Printf("Atlas API listening on %s", addr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
