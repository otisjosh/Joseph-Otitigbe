package main

import (
	"log"
	"net/http"
	"os"

	"github.com/otisjosh/Joseph-Otitigbe/internal/records"
)

func main() {
	addr := os.Getenv("ATLAS_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	log.Printf("Atlas API listening on %s", addr)
	if err := http.ListenAndServe(addr, records.NewHandler()); err != nil {
		log.Fatal(err)
	}
}
