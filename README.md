# Atlas – Enterprise Data Intelligence Platform

Atlas is a Go service for managing enterprise data records. PostgreSQL stores records, roles, and hashed API-key credentials.

## Requirements
- Go 1.25 or newer
- PostgreSQL 14 or newer

## Configuration
Set `DATABASE_URL` through your local environment or secret manager. The blank template in `.env.example` contains no credentials; do not commit populated `.env` files or API keys.

Example connection string shape (substitute credentials from a secure source):
```text
postgres://<user>:<password>@<host>:5432/<database>?sslmode=require
```

Use `sslmode=disable` only with trusted local PostgreSQL. The server listens on `:8080` by default; set `ATLAS_ADDR` to change it.

## First admin key and server startup
Create the initial admin key using a trusted operator shell with database access:
```sh
go run ./cmd/atlas provision-key --name initial-admin --role admin
```

The command prints the new key once as JSON to stdout. Capture it directly into your approved secret manager. The database stores only the SHA-256 hash of the random key secret. Do not paste the output into logs, tickets, or source control.

Start the API:
```sh
go run ./cmd/atlas
```

Atlas checks the database connection and applies pending versioned migrations before serving requests. On SIGINT or SIGTERM, it drains active HTTP requests before closing the PostgreSQL pool.

## Authentication and roles
All endpoints except `GET /healthz` require an API key in `Authorization: Bearer <api_key>`.

| Role | Permissions |
|---|---|
| Reader | Retrieve records |
| Writer | Retrieve and create records |
| Admin | Retrieve/create records; provision, inspect, revoke, and change roles for API keys |

Roles are predefined and their permissions are seeded by migrations. Admins can assign one of these roles to an API key; custom roles and custom permission definitions are not supported. Atlas prevents revoking or downgrading the last active administrator, including concurrent admin requests.

See [API.md](docs/API.md) for endpoint details and error responses. New keys are shown only in the create response; list, role-change, and revoke responses contain safe metadata only.

## Administrator recovery
If all administrator credentials are lost or compromised, an operator with authorized PostgreSQL access can provision a replacement directly from a trusted deployment checkout: `go run ./cmd/atlas provision-key --name recovered-admin --role admin`. Store the one-time output in the approved secret manager, verify the new admin can authenticate, then revoke any compromised keys using the API. This recovery path requires database operator access and does not expose or reset existing key secrets. If the database itself is unavailable, restore service using the organization's PostgreSQL backup and access recovery process.

## Data and security notes
The PostgreSQL pool uses parameterized queries. The schema and ordered migrations are in `internal/postgres/migrations`; applied versions are tracked in `atlas_schema_migrations`. API keys do not currently expire automatically. Deploy the HTTP service behind a trusted HTTPS endpoint; this server does not terminate TLS itself.

## Development and tests
With PostgreSQL available and `DATABASE_URL` set:
```sh
go test ./...
go test -race ./...
go test -cover ./...
go vet ./...
```

Integration tests skip locally when `DATABASE_URL` is unset. GitHub Actions starts a disposable PostgreSQL 16 service for them.

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidance.
