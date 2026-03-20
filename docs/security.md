# Security Notes

This server is intentionally narrow in scope: it exposes read-only Upwind data through MCP and avoids write operations in the first release.

## Transport choices

Use `stdio` by default for local MCP clients. It keeps the attack surface small and fits the standard subprocess-style MCP workflow.

Use Streamable HTTP only when you need an HTTP endpoint for local tooling or integration tests. The HTTP listener should stay on loopback by default, and the implementation should keep the MCP SDK's localhost and cross-origin protections enabled.

Legacy standalone SSE is excluded on purpose. The current MCP transport model is `stdio` plus Streamable HTTP, and the docs and code should stay aligned with that.

## HTTP authentication

HTTP mode uses a shared bearer token passed in `UPWIND_MCP_HTTP_BEARER_TOKEN`.

This is appropriate for local access and simple automation, but it is not a substitute for full OAuth-based MCP authorization. The token should be treated like a secret:

- Do not commit it to the repository
- Do not print it in logs
- Do not echo it in diagnostics or errors

## Upwind credentials

Upwind API credentials are also environment variables:

- `UPWIND_CLIENT_ID`
- `UPWIND_CLIENT_SECRET`
- `UPWIND_ORGANIZATION_ID`

The server should obtain Upwind access tokens using the client-credentials flow and keep them in memory only until refresh is needed. It should never expose raw access tokens in responses or logs.

## Deployment boundary

The first deployment model is local-first. If the server is later exposed remotely, it should move to a full OAuth-aligned protected-resource flow, with explicit origin and identity handling instead of relying only on a shared bearer token.
