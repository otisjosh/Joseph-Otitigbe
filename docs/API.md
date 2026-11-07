# Atlas API

All responses use JSON except the empty `GET /healthz` response. Error responses use the same shape:
```json
{"error":{"code":"permission_denied","message":"the API key does not have permission for this operation"}}
```

## Authentication

Send an API key on every route except `GET /healthz`:
```http
Authorization: Bearer atlas_<public-id>.<secret>
```

API keys have a random public selector and a 256-bit random secret. Only the SHA-256 hash of the secret is stored in PostgreSQL. The raw key is returned once by provisioning and cannot be retrieved later.

## Roles

| Role | Permissions |
|---|---|
| `reader` | `records:read` |
| `writer` | `records:read`, `records:write` |
| `admin` | Reader and writer permissions, plus `keys:manage` |

## Endpoints

### Public health

- `GET /healthz` — liveness response; no API key required.

### Records

- `GET /records/{id}` — requires `records:read`; returns a record.
- `POST /records` — requires `records:write`; creates a record.

Request:
```json
{"name":"Ada Lovelace","email":"ada@example.com"}
```

Existing record response and validation behavior are preserved. Duplicate email returns `409`; malformed input or IDs return `400`; missing records return `404`; storage failures return `503`.

### Admin: API keys and role assignments

All endpoints below require `keys:manage`.

- `GET /roles` — list built-in roles and permissions.
- `GET /api-keys` — list safe key metadata, including revoked keys.
- `POST /api-keys` — provision a key. Request: `{"name":"reporting job","role":"reader"}`. Returns `201`, metadata, and the raw `api_key` once. Response has `Cache-Control: no-store`.
- `PATCH /api-keys/{id}/role` — change an active key's role. Request: `{"role":"writer"}`.
- `DELETE /api-keys/{id}` — revoke an active key. Revoked keys cannot authenticate again. The last active administrator key cannot be revoked or downgraded; these attempts return `409 last_admin_required`.

The one-time CLI bootstrap uses `DATABASE_URL` and the same key generator:
`go run ./cmd/atlas provision-key --name initial-admin --role admin`.
The CLI writes the key once to stdout and does not log it.

### Authentication and authorization errors

- `401 authentication_required` — bearer key is missing.
- `401 invalid_api_key` — bearer key is malformed, unknown, incorrect, or revoked.
- `403 permission_denied` — key is valid but its role lacks the required permission.
- `503 authentication_unavailable` — PostgreSQL could not validate or manage a key.

Error messages do not contain API keys or stored hashes.
