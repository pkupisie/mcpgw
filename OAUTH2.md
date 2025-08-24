# OAuth2 Configuration

This MCP Gateway now supports dual OAuth2 flows in both Express.js and Cloudflare Worker deployments:

1. **Client → Gateway Flow**: Clients authenticate with the gateway first
2. **Gateway → Upstream Flow**: Gateway authenticates with the upstream MCP server

## Express.js Server

### Environment Variables

#### Required for Client → Gateway OAuth2:
- `OAUTH2_CLIENT_ID`: Client ID for applications connecting to this gateway
- `OAUTH2_CLIENT_SECRET`: Client secret for applications connecting to this gateway
- `OAUTH2_REDIRECT_URI`: Redirect URI (defaults to `http://localhost:PORT/oauth/callback`)

#### Optional for Gateway → Upstream OAuth2:
- `OAUTH2_UPSTREAM_CLIENT_ID`: Client ID for gateway to authenticate with upstream
- `OAUTH2_UPSTREAM_CLIENT_SECRET`: Client secret for upstream authentication
- `OAUTH2_UPSTREAM_AUTH_URL`: Upstream OAuth2 authorization endpoint
- `OAUTH2_UPSTREAM_TOKEN_URL`: Upstream OAuth2 token endpoint

### Usage

#### Basic Setup (Client → Gateway only)
```bash
export UPSTREAM_BASE=https://mcp.example.com
export OAUTH2_CLIENT_ID=your-client-id
export OAUTH2_CLIENT_SECRET=your-client-secret
node mcp-sse-mitm.js
```

#### Full Setup (Both flows)
```bash
export UPSTREAM_BASE=https://mcp.example.com
export OAUTH2_CLIENT_ID=your-client-id
export OAUTH2_CLIENT_SECRET=your-client-secret
export OAUTH2_UPSTREAM_CLIENT_ID=upstream-client-id
export OAUTH2_UPSTREAM_CLIENT_SECRET=upstream-client-secret
export OAUTH2_UPSTREAM_AUTH_URL=https://mcp.example.com/oauth/authorize
export OAUTH2_UPSTREAM_TOKEN_URL=https://mcp.example.com/oauth/token
node mcp-sse-mitm.js
```

## Cloudflare Worker

### Environment Variables

Configure in `wrangler.json` under `vars`:

```json
{
  "vars": {
    "OAUTH2_CLIENT_ID": "your-worker-client-id",
    "OAUTH2_CLIENT_SECRET": "your-worker-client-secret",
    "OAUTH2_UPSTREAM_CLIENT_ID": "upstream-client-id",
    "OAUTH2_UPSTREAM_CLIENT_SECRET": "upstream-client-secret"
  }
}
```

### Usage

```bash
# Development
wrangler dev

# Production deployment
wrangler deploy
```

### Key Differences from Express.js

- **Stateless**: Uses JWT tokens instead of in-memory sessions
- **No persistent storage**: All state is encoded in tokens
- **Base32 domain routing**: OAuth2 works with the domain-based routing system

## API Endpoints

### OAuth2 Flow Endpoints
- `GET /oauth/authorize` - Start OAuth2 authorization
- `POST /oauth/authorize` - Handle authorization decision
- `POST /oauth/token` - Exchange authorization code for access token
- `GET /oauth/callback` - Handle upstream OAuth2 callback

### Protected Endpoints (require authentication)
- `GET /v1/sse` - SSE proxy (requires Bearer token)
- `POST /v1/*` - API proxy (requires Bearer token)

## Flow Diagram

```
Client App → Gateway → Upstream Server
    ↓         ↓           ↓
 OAuth2   OAuth2     Original API
   Flow     Flow      (with tokens)
```

1. Client initiates OAuth2 with gateway
2. User authorizes in browser
3. Client receives access token
4. Client makes API calls with token
5. Gateway authenticates with upstream (if configured)
6. Gateway forwards request with upstream token
7. Response flows back to client

## Implementation Details

### Express.js
- **Session Storage**: In-memory Map (use Redis in production)
- **Token Format**: Random hex strings
- **State Management**: Server-side sessions with expiration

### Cloudflare Worker
- **Session Storage**: JWT tokens (stateless)
- **Token Format**: Base64-encoded JSON
- **State Management**: Client-side with token validation

## Security Considerations

- All tokens have expiration times
- State parameters prevent CSRF attacks
- Authorization codes are single-use
- Secrets are properly redacted in logs
- HTTPS required for production

## Testing

Run the comprehensive test suite:
```bash
# Express.js server test
node /tmp/test-oauth2-flow.js

# Worker configuration test  
node /tmp/test-worker-oauth2.js
```