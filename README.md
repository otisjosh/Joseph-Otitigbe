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

Atlas also applies bounded request-abuse controls. Defaults are:

```dotenv
ATLAS_MAX_CONCURRENT_REQUESTS=256
ATLAS_RATE_LIMIT_PER_KEY=120
ATLAS_RATE_LIMIT_PER_IP=600
ATLAS_RATE_LIMIT_WINDOW=1m
ATLAS_RATE_LIMIT_MAX_CLIENTS=10000
```

The concurrency setting must be between 1 and 10,000. Per-key and per-IP limits can be disabled individually with `0`; the default window must be between 1 second and 24 hours. The client-table capacity is bounded to 1–100,000 entries per category. Invalid values stop startup with a setting-specific message that does not include the supplied value. Changes take effect after restarting Atlas; limits are not hot-reloaded.

The source-address budget is applied to protected-route requests before authentication using the socket's `RemoteAddr`. After the selector lookup and secret verification, the per-key budget is checked before the last-used/revocation recheck write; a rejected request never reaches authorization or a handler. Atlas ignores `Forwarded` and `X-Forwarded-For` headers. When multiple clients connect through a proxy, they share the proxy's source-address budget. Rate state is in memory per Atlas process and does not coordinate across replicas. A full table rejects new identities with `429` until expired entries are cleaned; existing entries remain bounded and usable within their configured budgets. Health probes use reserved capacity separate from the normal request limit: up to 16 liveness handlers and up to 2 readiness checks can run concurrently. Readiness checks still use the existing two-second PostgreSQL ping timeout; excess health requests fail fast with 503 instead of starting unbounded database work.

Use `sslmode=disable` only for trusted local PostgreSQL. Require TLS for deployed databases. Prefer certificate and hostname verification with `sslmode=verify-full` and your provider's trusted CA configuration; use `sslmode=require` only when encryption without server identity verification is an accepted deployment policy. URL-encode reserved characters in connection credentials.

## Database migrations

Atlas applies its pending forward migrations transactionally during startup. A PostgreSQL advisory transaction lock serializes concurrent startup migration attempts, and applied versions are recorded in `atlas_schema_migrations`. The `provision-key` command uses the same startup path. The database role must be allowed to create the migration table, application tables, indexes, and constraints. SQL files are in `internal/postgres/migrations`; the runner executes only the ordered `.up.sql` files. Migration 8 adds nullable `expires_at` metadata; existing rows get `NULL` and remain valid. It never runs down migrations or automatically drops or rewrites existing tables. There is no separate migration command.

Before upgrading a deployment, take and verify a database backup. Test the new image against a staging database or a restored copy first. Allow a single instance to complete startup migrations before routing traffic if the deployment process needs a controlled rollout. Keep a restorable backup available; schema downgrade is not automated. The supplied migration 8 down SQL drops `expires_at` and therefore discards every configured expiry. Rolling back to application code that ignores expiry could make previously expired keys valid again. Do not run the down migration as routine rollback; coordinate a reviewed database restore or explicit policy decision before downgrading.

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

## Run Atlas in Docker

Build the multi-stage image from the repository root:

```sh
docker build --pull -t atlas:local .
```

The runtime image contains the statically compiled Atlas binary on a minimal Distroless base and runs as UID/GID 65532. It has no shell or package manager. Start the API with `DATABASE_URL` supplied by the host environment or your deployment's secret manager:

```sh
docker run --rm --name atlas -p 8080:8080 \
  --read-only --cap-drop=ALL --security-opt=no-new-privileges \
  --env DATABASE_URL --env ATLAS_ADDR=0.0.0.0:8080 atlas:local
```

Do not put the database URL in the Dockerfile, image build arguments, shell history, or committed files. When PostgreSQL runs in Docker Compose, use its service name as the database host. From Docker Desktop, use the supported host gateway name when PostgreSQL runs on the host; container `localhost` refers to the Atlas container itself. Atlas starts after PostgreSQL is reachable and applies pending migrations on startup.

To provision a key using the same image, run it as a one-shot command and capture stdout directly in an approved secret manager:

```sh
docker run --rm --env DATABASE_URL --entrypoint /atlas atlas:local \
  provision-key --name initial-admin --role admin
```

Send SIGTERM for a graceful stop. Atlas drains active HTTP requests for up to 10 seconds before the database pool closes; configure the orchestrator's termination grace period to allow that interval.

## Database backup and restore

Use PostgreSQL 16 client tools and keep backup files in encrypted, access-controlled storage. This example creates a custom-format logical backup without ownership or ACL entries:

```sh
pg_dump --format=custom --no-owner --no-acl --file=atlas.backup "$DATABASE_URL"
```

Test restoration into a separately provisioned empty database, never over the live database:

```sh
pg_restore --dbname="$RESTORE_DATABASE_URL" --no-owner --no-acl atlas.backup
```

Do not add `--clean` or `--create` when performing a verification restore. After restoring, verify the migration table and data, then start Atlas against that restored target and check `/readyz`. Restore testing does not replace a documented recovery plan, encryption, retention, and restore drills.

## API contract and operations

- [API guide](docs/API.md)
- [OpenAPI 3.1 specification](docs/openapi.yaml)
- `GET /healthz` is a public liveness probe and does not query PostgreSQL.
- `GET /readyz` is a public readiness probe with a two-second PostgreSQL ping timeout.
- Every request receives a generated `X-Request-ID` response header.
- Structured JSON logs include method, route template, status, duration, and request ID. Logs exclude raw paths, query strings, headers, request bodies, credentials, API keys, and record fields.

All routes except the two public probes require a bearer API key. Reader keys retrieve records; writer keys retrieve and create records; admins manage API keys, built-in roles, and audit logs. Permissions are predefined. The last active administrator cannot be revoked or downgraded. Admins can rotate keys with `POST /api-keys/{id}/rotate`; rotation atomically creates a new one-time credential and revokes its source key. The role and expiry are inherited unless explicitly replaced, and an expiry is never silently removed.

Successful record creation and API-key creation, rotation, role changes, and revocations are recorded transactionally in the audit table. Audit events omit API keys, hashes, record names, and emails. Reads and failed authentication attempts are not currently recorded.

## Administrator recovery

If all administrator credentials are lost or compromised, an operator with authorized PostgreSQL access can provision a replacement directly from a trusted deployment checkout:

```sh
go run ./cmd/atlas provision-key --name recovered-admin --role admin
```

Store the one-time output in the approved secret manager, verify the new admin can authenticate, then revoke compromised keys through the API. This recovery path requires database operator access and does not expose or reset existing key secrets. If the database itself is unavailable, use the organization's PostgreSQL backup and access recovery process.

## OpenAPI validation

To validate the OpenAPI 3.1 document locally, install Node.js 22.12 or newer with npm 10.9.2 or newer, then run the same pinned Redocly CLI version used by CI:

```sh
npx --yes @redocly/cli@2.76.0 lint docs/openapi.yaml
```

The repository's `redocly.yaml` checks OpenAPI structure and references and treats invalid request, response, and schema examples as errors. CI runs this validation alongside the existing PostgreSQL 16 Go checks.

## Tests and static analysis

Set `DATABASE_URL` to a PostgreSQL 16 test database before running the full suite. Integration tests skip when it is unset. GitHub Actions provisions a disposable PostgreSQL 16 service.

```sh
go test ./...
go test -race ./...
go test -cover ./...
go vet ./...
```

## Deployment troubleshooting

- **Startup reports missing or invalid `DATABASE_URL`:** provide a valid PostgreSQL connection string through the runtime environment or secret manager. Atlas does not load `.env` files automatically.
- **Startup cannot connect or migrate:** check PostgreSQL 16 is reachable from the container network, the hostname is correct, TLS settings match the server, and the database role can create the migration objects. Application logs use safe event names and do not print the connection URL or driver diagnostics.
- **Container cannot connect to PostgreSQL on the host:** use the host gateway supported by your container runtime; `localhost` inside Atlas points to Atlas itself.
- **`/healthz` returns 200 while `/readyz` returns 503:** the process is alive but PostgreSQL ping failed. Inspect database/network availability and credentials through your approved secret-management workflow.
- **Port bind fails:** ensure `ATLAS_ADDR` is a valid `host:port` address and the port is available. It defaults to `:8080`.
- **Requests are interrupted during deployment:** configure at least 10 seconds of termination grace for Atlas to drain active requests before the pool closes.

## Security notes

API keys may be provisioned with an optional UTC expiry. Omitted or `NULL` expiry means the key does not expire, including existing keys. Expiry is enforced during authentication and expired keys are rejected before protected handlers. Rotation creates the replacement and revokes its source in one audited database transaction. The replacement keeps the source role and expiry unless an explicit role or future expiry is supplied; omitted or null expiry never clears a configured expiry. The last active administrator cannot be rotated to a non-admin role. Store the returned secret securely because it is shown only once. The HTTP server does not terminate TLS; deploy it behind a trusted HTTPS endpoint. Store database credentials and one-time API keys using approved secret-management tools. See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidance.


## Supply-chain security checks

Pull requests and pushes to `main` or `feature/**` run the existing PostgreSQL 16 integration tests, race checks, coverage, vet, OpenAPI lint, and Docker non-root verification. CI also runs:

- **govulncheck v1.1.4** against the Go packages. It reports vulnerabilities in dependencies that affect reachable code; a finding fails the job. Findings are reviewed and fixed or explicitly risk-assessed before merge; no vulnerability suppression file is used.
- **Trivy v0.76.2** against the built image, scanning OS packages and application libraries. HIGH and CRITICAL findings fail CI, including findings without an available fix. Findings are reviewed, the base/dependency is updated where possible, and any accepted risk must be documented through normal review. This scan is not proof that Atlas is vulnerability-free.

GitHub Actions are pinned to full upstream commit SHAs with release comments. The Go builder image is pinned to the multi-architecture index digest `sha256:1ae0735f00daffa3aaf1363a5184c0d2dc55c78e3db4ec70241cdac97bf84b59`. The Distroless Debian 13 nonroot runtime uses its versioned upstream tag; its registry index digest was not available for independent verification during this change, so it remains a mutable reference. Review that pin and convert it to an upstream-verified digest when registry metadata is available. Distroless publishes this image for amd64, arm64, arm, s390x, ppc64le, and riscv64; CI currently builds on GitHub-hosted amd64 runners. See the upstream [Distroless image list](https://github.com/GoogleContainerTools/distroless#what-images-are-available).

### Run scans locally

Use Go 1.26.10 or newer and Docker to match CI. Install the same pinned scanner versions, then run:

```sh
go install golang.org/x/vuln/cmd/govulncheck@v1.1.4
govulncheck ./...
docker build --pull --tag atlas:local .
```

Install the official Trivy CLI v0.76.2, then:

```sh
trivy image --scanners vuln --vuln-type os,library --severity HIGH,CRITICAL --ignore-unfixed=false --exit-code 1 atlas:local
```

The scanner reports selected severity findings and exits nonzero on them; no ignore policy is configured. Redocly validation and the Go checks are documented above.

### Dependency and image updates

Dependabot opens weekly update pull requests for Go modules, GitHub Actions, and Dockerfile image references. It does not auto-merge or apply dependency updates; review each diff, changelog, scanner output, tests, and compatibility before merging. When changing an image pin, verify the release and multi-platform manifest digest at the upstream registry, check supported architectures, update the adjacent version comment/documentation, then run the Docker build and Trivy scan. Do not replace a pinned reference with a moving tag without review.
