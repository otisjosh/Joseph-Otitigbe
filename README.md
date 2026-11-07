# Atlas – Enterprise Data Intelligence Platform

Atlas is a Go service for managing enterprise data records. PostgreSQL is the source of truth for record creation and retrieval, with migrations applied during startup.

## Requirements
- Go 1.25 or newer
- PostgreSQL 14 or newer

## Configuration
Set `DATABASE_URL` using your local secret manager or environment. A blank, safe-to-edit template is provided in `.env.example`; do not commit populated `.env` files or credentials.

Example connection string shape (replace placeholders with locally managed values):
```text
postgres://<user>:<password>@<host>:5432/<database>?sslmode=require
```

For local development, set `sslmode=disable` only when connecting to a trusted local PostgreSQL instance. The server listens on `:8080` by default; set `ATLAS_ADDR` to change it.

## Run
```sh
export DATABASE_URL='postgres://<user>:<password>@localhost:5432/atlas?sslmode=disable'
go run ./cmd/atlas
```

Atlas checks the database connection and applies pending versioned migrations before serving requests. On SIGINT or SIGTERM, it stops accepting new requests, drains active HTTP requests, then closes the PostgreSQL pool.

## API
- `GET /healthz` returns `200 OK` when the process is healthy.
- `POST /records` creates a record from JSON `{"name":"Ada Lovelace","email":"ada@example.com"}`.
  - Returns `201 Created` and the created record.
  - Returns `400 Bad Request` for malformed or invalid input.
  - Returns `409 Conflict` when the email already exists (trimmed, case-insensitive uniqueness is enforced by PostgreSQL).
  - Returns `503 Service Unavailable` when PostgreSQL cannot complete the operation.
- `GET /records/{id}` returns a record, `400 Bad Request` for malformed IDs, or `404 Not Found` when no record exists.

The PostgreSQL pool uses parameterized queries. The schema and ordered migrations are in `internal/postgres/migrations`; migrations are tracked in `atlas_schema_migrations`.

## Development
With a PostgreSQL service available and `DATABASE_URL` set:
```sh
go test ./...
go test -race ./...
go test -cover ./...
go vet ./...
```

PostgreSQL integration tests skip when `DATABASE_URL` is unset. GitHub Actions starts a disposable PostgreSQL service for these tests.

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidance.
