# Atlas – Enterprise Data Intelligence Platform

Atlas is a Go HTTP API for enterprise records, PostgreSQL persistence, API-key authentication, role-based authorization, audit events, and operational probes.

## Prerequisites

- Go 1.25 or newer.
- PostgreSQL 16 for the supported CI and integration-test configuration.
- A PostgreSQL database role authorized to create Atlas tables, indexes, and migration metadata.

## PostgreSQL and environment setup

Install and start PostgreSQL 16 using your platform's package manager or approved development environment. Create a local database named `atlas` (for example, with `createdb atlas`) and configure its local role according to your PostgreSQL installation.

Set `DATABASE_URL` from your local environment or approved secret manager. The safe template in `.env.example` is a reference only; Go does not load `.env` files automatically. Export values into the process environment. Never commit populated environment files or credentials.

```sh
export DATABASE_URL='postgres://<user>:<password>@localhost:5432/atlas?sslmode=disable'
export ATLAS_ADDR=':8080'
```

Use `sslmode=disable` only for trusted local PostgreSQL. Use TLS verification for deployed databases, such as `sslmode=require` or your provider's stronger certificate-verification configuration. URL-encode reserved characters in connection credentials.

## Database migrations

Atlas applies pending versioned migrations automatically when the API starts. The `provision-key` command uses the same database startup path and applies pending migrations before provisioning. The configured database role must be allowed to create the migration tracking table, application tables, and indexes. Applied versions are tracked in `atlas_schema_migrations`; SQL migration files are under `internal/postgres/migrations`. There is no separate migration command.

## Run Atlas locally

Provision the first administrator key from an authorized operator shell:

```sh
go run ./cmd/atlas provision-key --name initial-admin --role admin
```

The command returns the plaintext API key once as JSON on stdout. Capture it directly into an approved secret manager. Do not paste the output into logs, tickets, or source control.

Start the HTTP API:

```sh
go run ./cmd/atlas
```

The server listens on `:8080` by default; set `ATLAS_ADDR` to change it. On SIGINT or SIGTERM, Atlas drains active HTTP requests before closing its PostgreSQL pool.

## API contract and operations

- [API guide](docs/API.md)
- [OpenAPI 3.1 specification](docs/openapi.yaml)
- `GET /healthz` is a public liveness probe and does not query PostgreSQL.
- `GET /readyz` is a public readiness probe with a two-second PostgreSQL ping timeout.
- Every request receives a generated `X-Request-ID` response header.
- Structured JSON logs include method, route template, status, duration, and request ID. Logs exclude raw paths, query strings, headers, request bodies, credentials, API keys, and record fields.

All routes except the two public probes require a bearer API key. Reader keys retrieve records; writer keys retrieve and create records; admins manage API keys, built-in roles, and audit logs. Permissions are predefined. The last active administrator cannot be revoked or downgraded.

Successful record creation and API-key creation, role changes, and revocations are recorded transactionally in the audit table. Audit events omit API keys, hashes, record names, and emails. Reads and failed authentication attempts are not currently recorded.

## Administrator recovery

If all administrator credentials are lost or compromised, an operator with authorized PostgreSQL access can provision a replacement directly from a trusted deployment checkout:

```sh
go run ./cmd/atlas provision-key --name recovered-admin --role admin
```

Store the one-time output in the approved secret manager, verify the new admin can authenticate, then revoke compromised keys through the API. This recovery path requires database operator access and does not expose or reset existing key secrets. If the database itself is unavailable, use the organization's PostgreSQL backup and access recovery process.

## Tests and static analysis

Set `DATABASE_URL` to a PostgreSQL 16 test database before running the full suite. Integration tests skip when it is unset. GitHub Actions provisions a disposable PostgreSQL 16 service.

```sh
go test ./...
go test -race ./...
go test -cover ./...
go vet ./...
```

## Security notes

API keys do not currently expire automatically. The HTTP server does not terminate TLS; deploy it behind a trusted HTTPS endpoint. Store database credentials and one-time API keys using approved secret-management tools. See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidance.
