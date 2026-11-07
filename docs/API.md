# Atlas API

The authoritative machine-readable contract is [OpenAPI 3.1](openapi.yaml). All error responses from documented application endpoints use:

```json
{"error":{"code":"permission_denied","message":"the API key does not have permission for this operation"}}
```

## Authentication

`GET /healthz` and `GET /readyz` are public and do not require an API key. All other documented endpoints require a bearer key:

```http
Authorization: Bearer ${ATLAS_API_KEY}
```

For example, set `ATLAS_API_KEY` from a secure secret store and `ATLAS_BASE_URL` to the service address:

```sh
curl -i -H "Authorization: Bearer ${ATLAS_API_KEY}" \
  "${ATLAS_BASE_URL}/records/42"
```

Reader keys can retrieve records; writer keys can retrieve and create records; admin keys can manage API keys, role assignments, and audit logs. Roles and permissions are predefined.

## Request IDs

Every response from Atlas includes a fresh `X-Request-ID` response header containing 32 lowercase hexadecimal characters. Atlas generates the ID and replaces any caller-supplied value. Use the response ID when reporting an issue. Structured request logs include the ID with method, route template, status, and duration.

## Public operational endpoints

- `GET /healthz` is a lightweight liveness probe. It does not query PostgreSQL. Success is `200 OK` with an empty body.
- `GET /readyz` pings PostgreSQL using a two-second context timeout. Success is `200 OK` with `{"status":"ready"}`; failure is `503 Service Unavailable` with a generic JSON error that contains no connection details.

```sh
curl -i "${ATLAS_BASE_URL}/healthz"
curl -i "${ATLAS_BASE_URL}/readyz"
```

## Records

Create a record with `POST /records` (requires `records:write`):

```sh
curl -i -X POST "${ATLAS_BASE_URL}/records" \
  -H "Authorization: Bearer ${ATLAS_API_KEY}" \
  -H "Content-Type: application/json" \
  --data '{"name":"Ada Lovelace","email":"ada@example.com"}'
```

Request body:

```json
{"name":"Ada Lovelace","email":"ada@example.com"}
```

A successful response is `201 Created`:

```json
{"id":42,"name":"Ada Lovelace","email":"ada@example.com"}
```

Retrieve the record using `GET /records/{id}` (requires `records:read`). IDs must be positive base-10 integers without leading zeroes. Email validation requires a valid address with a multi-label domain; the service rejects display-name syntax and malformed domain labels.

## API keys and roles

All key and role-management endpoints require `keys:manage`.

- `GET /api-keys` lists safe metadata, including revoked keys. It never returns API keys or stored hashes.
- `POST /api-keys` provisions a key from `{"name":"reporting job","role":"reader"}`. The `201` response includes metadata and `api_key` once. It sets `Cache-Control: no-store` and `Pragma: no-cache`.
- `PATCH /api-keys/{id}/role` changes an active key's role with `{"role":"writer"}`.
- `DELETE /api-keys/{id}` revokes an active key.
- `GET /roles` lists the built-in roles and their permissions.

A successful key provisioning response contains safe metadata plus the one-time key value:

```json
{
  "id": 11,
  "public_id": "<opaque-public-selector>",
  "name": "reporting job",
  "role": "reader",
  "created_at": "2026-01-01T12:00:00Z",
  "api_key": "<returned-once-value>"
}
```

The placeholder is illustrative; Atlas returns the actual key only once. Capture it in an approved secret manager. The last active administrator key cannot be revoked or downgraded; those operations return `409 last_admin_required`.

## Audit logs and pagination

`GET /audit-logs` requires `keys:manage` and returns up to 500 events, newest first. The default `limit` is 100. `before_id` is an exclusive cursor: pass the final event ID from the previous page to request older events.

```text
GET /audit-logs?limit=100
GET /audit-logs?limit=100&before_id=123
```

A successful response has an `events` array:

```json
{
  "events": [
    {
      "id": 122,
      "occurred_at": "2026-01-01T12:00:00Z",
      "actor_key_id": 3,
      "action": "record.created",
      "resource_type": "record",
      "resource_id": 42,
      "details": {}
    }
  ]
}
```

An empty page is returned as `{"events":[]}`. Events record successful record creation and API-key creation, role changes, and revocation. They omit API keys, hashes, record names, and emails. Reads and failed authentication attempts are not currently recorded.

## Rate limits and overload

Normal application requests share a global in-flight request limit (default 256). Health probes use reserved capacity separate from normal requests: at most 16 liveness handlers and 2 readiness checks run concurrently. The readiness endpoint also bounds each PostgreSQL ping to two seconds, so excess probes fail fast with 503 rather than creating unbounded database work. Protected-route requests use a source-address fixed-window budget (default 600 requests per minute) before authentication; after key selector lookup and secret verification, authenticated requests use a per-API-key budget (default 120 per minute) before the last-used/revocation recheck write. These limits can be configured with `ATLAS_MAX_CONCURRENT_REQUESTS`, `ATLAS_RATE_LIMIT_PER_IP`, `ATLAS_RATE_LIMIT_PER_KEY`, and `ATLAS_RATE_LIMIT_WINDOW`. Set either identity rate to `0` to disable that budget; the concurrency limit remains required. Configuration is loaded at startup and requires a restart to change.

Rate-limited requests return `429 Too Many Requests` with the standard JSON error shape and code `rate_limited`. Identity-limit responses include `RateLimit-Limit`, `RateLimit-Remaining`, `RateLimit-Reset` (seconds until reset), and `Retry-After`; normal concurrency overload includes `Retry-After`. Health-reserved-capacity overload returns `503` with `Retry-After` and a safe JSON error.

Source addresses come only from the TCP connection's `RemoteAddr`. Atlas does not trust `Forwarded` or `X-Forwarded-For`. Clients sharing a reverse proxy therefore share its IP budget. Limit state is bounded and in-memory per application instance; it is not coordinated across replicas. When a client table is full, new identities are rejected until expired entries are cleaned up.

## Errors and methods

| Status | Meaning | Common codes |
|---|---|---|
| `400` | Invalid JSON, fields, IDs, or pagination | `invalid_json`, `invalid_record`, `invalid_record_id`, `invalid_api_key_id`, `invalid_limit`, `invalid_before_id`, `invalid_role` |
| `401` | Missing, malformed, incorrect, or revoked API key | `authentication_required`, `invalid_api_key` |
| `403` | Valid key lacks the required permission | `permission_denied` |
| `404` | Record or active API key does not exist | `not_found`, `api_key_not_found` |
| `405` | Method is unsupported; response includes an `Allow` header | `method_not_allowed` |
| `409` | Duplicate record email or last-admin guard | `duplicate_record`, `last_admin_required` |
| `413` | Record body exceeds the 1 MiB limit | `request_too_large` |
| `500` | Unexpected record or key-management error | `internal_error` |
| `503` | Storage, authentication, audit, or readiness dependency unavailable | `storage_unavailable`, `authentication_unavailable`, `audit_unavailable`, `not_ready` |

API-key create/role request bodies are limited to 16 KiB; an oversized or malformed key-management JSON body currently returns `400 invalid_json`. Error messages do not contain API keys, hashes, passwords, record contents, or database connection details. All documented responses include `X-Request-ID`.
