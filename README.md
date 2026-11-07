# Atlas – Enterprise Data Intelligence Platform

Atlas is a Go service foundation for managing enterprise data records. The initial API provides health checks, validated record creation, and duplicate detection by normalized email.

## Requirements
- Go 1.22 or newer

## Run
```sh
go run ./cmd/atlas
```

The API listens on `:8080` by default. Set `ATLAS_ADDR` to change the listen address.

## API
- `GET /healthz` returns `200 OK` when the process is healthy.
- `POST /records` creates a record from JSON `{"name":"Ada Lovelace","email":"ada@example.com"}`.
  - Returns `201 Created` and the created record.
  - Returns `400 Bad Request` for malformed or invalid input.
  - Returns `409 Conflict` when the email already exists (comparison is trimmed and case-insensitive).
- `GET /records/{id}` returns a record or `404 Not Found`.

Records are currently held in memory and are lost when the process exits. Persistence, authentication, and production deployment configuration are future work.

## Development
```sh
go test ./...
go test -cover ./...
go vet ./...
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidance.
