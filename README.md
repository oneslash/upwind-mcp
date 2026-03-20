# Upwind MCP

An MCP server for Upwind that exposes a read-only security and inventory surface over the official Go MCP SDK.

## What it exposes

The first release is intended to cover:

- Inventory search and asset lookups
- Threat story search and detail views
- Vulnerability findings
- Configuration findings, frameworks, and rules
- SBOM package queries
- API security endpoint listing

## Build and run

This repository contains the server source under `cmd/upwind-mcp`.

Requirements:

- Go `1.26.x`

Run over `stdio` directly from source:

```bash
go run ./cmd/upwind-mcp
```

Build a local binary:

```bash
go build -o upwind-mcp ./cmd/upwind-mcp
./upwind-mcp
```

If you prefer `just` over a Makefile:

```bash
just build
just run
just run-http
just docker-build
just docker-run
```

`just` loads `.env` automatically when present. `just docker-run` starts Streamable HTTP on `127.0.0.1:8080` with a hardened `docker run` profile and requires `UPWIND_MCP_HTTP_BEARER_TOKEN`.

## Transports

`stdio` is the default transport.

```bash
go run ./cmd/upwind-mcp
```

Streamable HTTP is opt-in for local integrations and tooling.

```bash
go run ./cmd/upwind-mcp serve-http
```

By default, HTTP mode only allows loopback binds such as `127.0.0.1:8080` or `localhost:8080`. If you set `UPWIND_MCP_HTTP_ADDR` to a non-loopback address, you must also pass `--public-bind`.

```bash
go run ./cmd/upwind-mcp serve-http --public-bind
```

Legacy standalone SSE is intentionally not supported.

## Configuration

Configure Upwind access and server behavior with environment variables. `upwind-mcp` also reads a local `.env` file automatically when present. For each setting, the process environment takes precedence and `.env` is used only as a fallback.

- `UPWIND_REGION` default `us`; supported values are `us`, `eu`, and `me`
- `UPWIND_BASE_URL` optional override for the Upwind API base URL
- `UPWIND_ORGANIZATION_ID`
- `UPWIND_CLIENT_ID`
- `UPWIND_CLIENT_SECRET`
- `UPWIND_REQUEST_TIMEOUT` default `30s`
- `UPWIND_MCP_HTTP_ADDR` default `127.0.0.1:8080`
- `UPWIND_MCP_HTTP_PATH` default `/mcp`
- `UPWIND_MCP_HTTP_BEARER_TOKEN` required for HTTP mode

## Example usage

`stdio`:

```bash
cat > .env <<'EOF'
UPWIND_ORGANIZATION_ID=org_...
UPWIND_CLIENT_ID=...
UPWIND_CLIENT_SECRET=...
EOF

go run ./cmd/upwind-mcp
```

HTTP:

```bash
cat > .env <<'EOF'
UPWIND_ORGANIZATION_ID=org_...
UPWIND_CLIENT_ID=...
UPWIND_CLIENT_SECRET=...
UPWIND_MCP_HTTP_BEARER_TOKEN=local-dev-token
EOF

go run ./cmd/upwind-mcp serve-http
```

## Security

HTTP mode is local-first and protected by a shared bearer token. Upwind credentials stay in environment variables only and are never printed back by the server.

See [docs/security.md](docs/security.md) for the transport and deployment guidance.
