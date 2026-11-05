# Remote MCP server (`mcp-gateway`, #28)

`mcp-gateway` is what Claude, ChatGPT and Gemini (web) talk to: a Go process
that speaks Streamable HTTP + OAuth 2.1 on the front and the [#27 control-plane
API](API.md#http-control-plane-api-27) on the back. It holds no engine state —
every tool call is one sandbox-api call made with the operator's bearer token.

```
assistant cloud ──HTTPS──> reverse proxy ──HTTP──> mcp-gateway ──HTTP──> sandbox-api ──> sandboxd
(public URL, OAuth)        (operator TLS)   127.0.0.1:8090   Unix or TCP+Bearer
```

It is deliberately standard-library-only Go: no module downloads, no supply
chain beyond the toolchain, reproducible offline builds.

## Quick start (local development)

```sh
# 1. sandbox-api is already running (see API.md). Mint the operator token once:
sandbox-api new-token operator     # shown once; append the entry to api-tokens.conf

# 2. Build and run the gateway against it:
go build -o /tmp/mcp-gateway ./src/mcp_gateway
printf '%s\n' 'THE-TOKEN' >/tmp/mcp-api-token && chmod 600 /tmp/mcp-api-token
/tmp/mcp-gateway --public-url http://127.0.0.1:8090 --store /tmp/mcp-store.json \
    --api http://127.0.0.1:8088 --api-token-file /tmp/mcp-api-token \
    --test-client local:dev-secret
```

Point MCP Inspector at `http://127.0.0.1:8090/mcp`. For scripted checks, mint
a token without a browser via the testing grant (see below).

Loopback `http` is allowed; anything else must be `https` (the gateway refuses
to start otherwise). There is no MCP without TLS on the open internet: put a
reverse proxy (nginx, Caddy) in front and pass its public origin as
`--public-url`. That URL is the OAuth issuer and the token audience, so it must
be stable — changing it invalidates every grant.

## Production setup

1. Terminate TLS at the proxy and forward to the gateway's loopback listener.
2. `--public-url https://mcp.example.org` (exactly the public origin).
3. `--store /var/lib/mcp-gateway/state.json` (created 0600; refused if more
   open). It holds client registrations and token hashes. Back it up with the
   host, like any credential-adjacent file.
4. `--api` pointing at sandbox-api (Unix socket when co-located, TCP+token
   otherwise) and `--api-token-file` (0600) holding the operator's bearer token.
5. `systemd/mcp-gateway.service`. Every flag also reads `SANDBOX_MCP_<NAME>`
   from the environment (see [Configuration](CONFIGURATION.md)).

## OAuth 2.1

The gateway is its own authorization server. A client connecting for the first
time runs, all automatically:

1. `POST /mcp` without a token → `401` with `WWW-Authenticate` naming
   `/.well-known/oauth-protected-resource` (RFC 9728).
2. The resource metadata names the authorization server (this gateway); the
   client reads `/.well-known/oauth-authorization-server` (RFC 8414).
3. The client identifies with a Client ID Metadata Document (preferred) or
   Dynamic Client Registration (RFC 7591, kept for older clients).
4. Authorization code + **PKCE S256 (required, never `plain`)**; the user
   approves on the consent page after proving principal ownership with their
   sandbox-api token — checked live, never stored.
5. Code, refresh and scope handling at `/oauth/token`, with the RFC 8707
   `resource` indicator bound to this server's `/mcp` URL.

Token lifetimes: codes 10 minutes (single use), access tokens 1 hour, refresh
tokens 30 days with rotation — presenting a rotated refresh token revokes the
whole grant. Access tokens are opaque 256-bit values, hashed at rest.

**Scopes.** Two, requested at authorize time and shown on the consent page:

| Scope | Grants the tools that… |
|---|---|
| `sandbox:read` | list/inspect sessions, read files, stat, ls |
| `sandbox:write` | create/run/write/mkdir/delete files, renew, destroy |

**M2 limit: one operator principal.** Every grant acts with the configured
`--api-token-file` bearer token. Per-user principals arrive with
multi-tenancy (#17); until then, all OAuth users share the operator's
sessions namespace (keys still isolate conversations from each other, since
session ids derive from the key).

**Testing grant.** `--test-client id:secret` enables `client_credentials`
(access token only, no refresh). It is unadvertised in metadata and meant for
self-host checks and the e2e suite — never enable it with a weak secret on a
public server.

## Tools

Twelve tools, 1:1 onto the #27 API (the nine the issue names plus stat, mkdir
and file delete). Schemas carry `readOnly`/`destructive` annotations so
clients can confirm writes.

| Tool | Scope | Effect |
|---|---|---|
| `create_session` | write | create-or-attach by key (options mirror the API) |
| `list_sessions` | read | sessions with state and expiry |
| `get_status` | read | one session's detail |
| `run` | write | shell `command` or `argv`, stdin, timeouts, idempotency key |
| `read_file` | read | file bytes as text or base64 (≤ 4 MiB) |
| `write_file` | write | bytes as text or base64, `append`/`exclusive` |
| `list_files` | read | directory listing |
| `get_file_stat` | read | type, size, mode, mtime |
| `make_directory` | write | mkdir with `parents` and `mode` |
| `delete_file` | write | remove a path (`recursive` for directories) |
| `renew` | write | extend the workspace deadline |
| `destroy_session` | write | release the VM; the workspace stays until its TTL |

Runtime failures (unknown session, engine error) come back as failed results
(`isError: true`) so the model reads them; bad arguments are JSON-RPC
`-32602`; a token without the tool's scope is `-32001`.

Output arrives when the command finishes, like the API underneath it — live
tailing is #34.

## Protocol notes

- **Stateless.** The gateway never issues `Mcp-Session-Id`; every request
  stands alone. `initialize` is still answered (protocol versions `2025-11-25`
  and `2026-07-28`), `GET`/`DELETE /mcp` are `405`.
- **SSE or JSON** per `Accept`: `text/event-stream` gets one `message` event
  with the full response; anything else gets plain JSON.
- **Origin rule** (DNS-rebinding): missing and loopback origins pass; anything
  else must equal the public origin or the call is `403`.

## Self-signed dev mode

`--tls-self-signed` serves HTTPS with an ephemeral ECDSA certificate (loopback
SANs only, 24 h, key never on disk) and logs its SHA-256 fingerprint for
clients to pin. It refuses a non-loopback `--listen`: a dev cert on a public
socket would look secure without being so. For real deployments, terminate TLS
at the proxy instead.

## Troubleshooting

- `401` on `/mcp`: no token, an expired token, or a token minted for another
  resource. Re-run the flow; check the grant still exists in the store.
- Consent loops back with "did not authenticate": the pasted API token is
  wrong or sandbox-api is unreachable from the gateway.
- `invalid_grant` on refresh: the refresh token was already rotated (each one
  is single-use) — or replayed, in which case the grant is revoked and the
  client must re-authorize.
- A CIMD client that never gets past authorize: the gateway fetches the
  client document over public HTTPS only (no redirects, 64 KiB cap). Serve it
  from a public URL or register with DCR instead.
