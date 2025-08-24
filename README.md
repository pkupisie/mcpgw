# MCP OAuth Gateway

A production-ready authentication gateway implementing CLIENT → GW → SERVER dual OAuth layers with PKCE security, now enhanced with **hostname-based MCP server routing**.

## Architecture

- **CLIENT**: Claude.ai, ChatGPT, or browser-based UI for local login
- **GATEWAY**: Node.js/TypeScript Fastify server handling dual auth flows + hostname routing
- **SERVER**: Multiple MCP servers (OAuth 2.1 + PKCE per server)

## Key Features

### Hostname-Based MCP Server Routing
- **Single Gateway for Multiple MCP Servers**: Route to different servers via encoded hostnames
- **Base32 Encoded Domains**: `<base32(mcp.atlassian.com)>-enc.copernicusone.com/` routes to Atlassian MCP
- **Per-Server OAuth**: Independent OAuth 2.1 + PKCE flows for each MCP server
- **WebSocket Support**: Full WebSocket tunneling with authentication
- **Dynamic Server Discovery**: Add new MCP servers via configuration

### Authentication Flow
1. **Local Auth**: Static user/pass → signed session cookie
2. **Per-Server OAuth**: Authorization Code + PKCE → encrypted token storage per server
3. **Smart Proxying**: Automatic Bearer token injection for target server
4. **Token Refresh**: Automatic refresh token handling per server

## Getting Started

### Prerequisites
- Node.js 18+ (or 20+), npm
- Browsers for Playwright (optional for testing)

### Quick Start
```bash
# Install dependencies
npm ci

# Optional: install browsers for testing
npm run pw:install

# Run mock IdP (port 4000) - for testing
npm run dev:mock

# Run gateway (port 3000)
npm run dev:gw

# Open http://localhost:3000
```

## Configuration

Copy `.env.example` to `.env` and configure:

### Basic Settings
```env
GW_BASE_URL=http://localhost:3000
DOMAIN_ROOT=copernicusone.com
LOCAL_USER=admin
LOCAL_PASSWORD=password123
SESSION_SECRET=your-session-secret-here
TOKEN_ENCRYPTION_KEY=64-hex-char-key
```

### MCP Server Registry
Configure multiple MCP servers as JSON:
```env
MCP_SERVERS='[
  {
    "domain": "mcp.atlassian.com",
    "name": "Atlassian MCP",
    "authzEndpoint": "https://auth.atlassian.com/oauth/authorize",
    "tokenEndpoint": "https://auth.atlassian.com/oauth/token",
    "clientId": "your-client-id",
    "clientSecret": "your-client-secret",
    "scopes": "read:jira-work write:jira-work"
  },
  {
    "domain": "api.github.com", 
    "name": "GitHub MCP",
    "authzEndpoint": "https://github.com/login/oauth/authorize",
    "tokenEndpoint": "https://github.com/login/oauth/access_token",
    "clientId": "your-github-client-id",
    "scopes": "repo read:user"
  }
]'
```

## Usage with Claude.ai/ChatGPT

1. **Configure MCP Server**: Add your MCP server to the registry
2. **Generate Encoded URL**: Visit dashboard → "Add New Server" → enter domain
3. **Get Encoded URL**: Copy the encoded URL (e.g., `https://abc123xyz-enc.copernicusone.com/`)
4. **Connect in Claude.ai**: Use the encoded URL as your MCP server endpoint
5. **Authenticate**: First request will redirect to OAuth flow
6. **Use MCP Services**: All subsequent requests automatically include authentication

## API Endpoints

### Dashboard & Management
- `GET /` - Dashboard with server status and URL generation
- `GET /encode?domain=mcp.example.com` - Generate encoded URLs
- `POST /login` - Local authentication
- `POST /logout` - Sign out

### OAuth Flow
- `POST /upstream/start` - Initiate OAuth for specific server
- `GET /oauth/start/:server` - Direct OAuth initiation link
- `GET /oauth/callback` - OAuth callback handler

### Hostname-Based Routing
- `ALL https://<base32(domain)>-enc.copernicusone.com/*` - Proxy to MCP server
- Supports HTTP, WebSocket, and SSE protocols
- Automatic Bearer token injection
- Token refresh on 401 responses

## Security Features

- **AES-256-GCM** token encryption at rest
- **CSRF protection** (header + form body support)
- **Rate limiting** on auth endpoints
- **Secure session cookies** (httpOnly, SameSite)
- **OAuth 2.1 PKCE** (S256) implementation
- **Per-server token isolation**
- **MCP server allowlist** support

## Testing

```bash
# Run headless tests
npm test

# Run headed tests
npm run test:headed
```

## Deployment

### Development
```bash
npm run dev:gw  # Start gateway on port 3000
npm run dev:mock  # Start mock IdP for testing
```

### Production
```bash
npm run build  # Build both applications
docker build -t mcpgw-gw apps/gw  # Build container
```

## Legacy Compatibility

The gateway maintains backward compatibility with single-server configurations using the original environment variables (`UPSTREAM_AUTHORIZATION_ENDPOINT`, etc.).

## Project Structure

```
apps/gw/          # Gateway server (Fastify + TypeScript)
apps/mock-idp/    # Mock IdP server for testing
src/worker.js     # Original Cloudflare Worker (unchanged)
tests/            # Playwright E2E tests
```

