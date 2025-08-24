# MCP OAuth Gateway

A production-ready authentication gateway implementing CLIENT → GATEWAY → MCP SERVER architecture with OAuth 2.1 + PKCE security, deployed as a Cloudflare Worker.

## Business Architecture

**Target Users**: Developers using Claude.ai, ChatGPT, or other AI assistants that support MCP (Model Context Protocol)

**Problem Solved**: AI assistants need secure, authenticated access to multiple MCP servers (Atlassian, GitHub, etc.) without exposing OAuth credentials or handling complex authentication flows.

**Solution**: A single OAuth gateway that handles authentication for multiple MCP servers via hostname-based routing.

## Technical Architecture

```
Claude.ai/ChatGPT → Cloudflare Worker → MCP Server (Atlassian/GitHub/etc)
     (CLIENT)           (GATEWAY)              (SERVER)
```

### Deployment: Cloudflare Worker
- **Production**: Single Worker handling all traffic
- **Zero-config scaling**: Cloudflare's global edge network
- **Built-in KV storage**: For session management
- **WebSocket support**: Full bidirectional tunneling

### Hostname-Based MCP Server Routing
- **Format**: `{base32(domain)}-enc.copernicusone.com`
- **Example**: `mcp.atlassian.com` → `nvrxaltborwgc43tnfqw4ltdn5wq-enc.copernicusone.com`
- **Per-Server OAuth**: Independent authentication per MCP server
- **Dynamic Discovery**: Add new servers via dashboard

## Business Logic Flow

### 1. MCP Server Registration
```javascript
// Configure in Cloudflare Worker secrets
MCP_SERVERS = '[
  {
    "domain": "mcp.atlassian.com",
    "name": "Atlassian MCP", 
    "authzEndpoint": "https://auth.atlassian.com/oauth/authorize",
    "tokenEndpoint": "https://auth.atlassian.com/oauth/token",
    "clientId": "your-client-id",
    "scopes": "read:jira-work write:jira-work"
  }
]'
```

### 2. AI Assistant Integration
1. **Developer Setup**: Visit `https://copernicusone.com` dashboard
2. **URL Generation**: Enter MCP server domain → get encoded URL
3. **Claude.ai Configuration**: Use encoded URL as MCP server endpoint
4. **First Request**: Redirects to OAuth flow for that specific server
5. **Subsequent Requests**: Automatic Bearer token injection

### 3. Authentication & Authorization
- **Gateway Auth**: Simple user/password (configurable via secrets)
- **MCP Server Auth**: OAuth 2.1 + PKCE per server
- **Token Storage**: Encrypted in Cloudflare KV with TTL
- **Security**: CSRF protection, rate limiting, secure cookies

## Commands

### Development & Testing
- `npm run dev` - Start local development server with Wrangler
- `npm run build:worker` - Build TypeScript to JavaScript
- `npm run deploy` - Build and deploy to Cloudflare
- `npm test` - Run Playwright E2E tests
- `npm run dev:gw` - Start Node.js gateway (alternative architecture)

### Cloudflare Setup
1. **Create KV Namespace**: `wrangler kv:namespace create "SESSIONS"`
2. **Update wrangler.json**: Add your KV namespace ID
3. **Set Secrets**: `wrangler secret put LOCAL_USER`
4. **Deploy**: `npm run deploy`

## Environment Configuration

### Cloudflare Worker Secrets (via `wrangler secret put`)
```bash
wrangler secret put LOCAL_USER
wrangler secret put LOCAL_PASSWORD
wrangler secret put SESSION_SECRET
wrangler secret put TOKEN_ENCRYPTION_KEY
wrangler secret put MCP_SERVERS
```

### Cloudflare Worker Variables (in wrangler.json)
```json
{
  "vars": {
    "DOMAIN_ROOT": "copernicusone.com",
    "LOG_LEVEL": "info"
  }
}
```

## Key Implementation Details

### Security Features
- **OAuth 2.1 PKCE (S256)**: Industry-standard security
- **Token Encryption**: AES-256-GCM for stored tokens
- **Session Management**: Cloudflare KV with TTL expiration
- **CSRF Protection**: Double-submit cookie pattern
- **Rate Limiting**: Built-in Cloudflare protection

### API Endpoints
- `GET /` - Dashboard with server status and URL generation
- `GET/POST /login` - Gateway authentication
- `GET /encode?domain=X` - Generate encoded URLs for MCP servers
- `GET /oauth/start?server=X` - Initiate OAuth for specific server
- `GET /oauth/callback` - OAuth callback handler
- `ALL /{base32}-enc.copernicusone.com/*` - MCP server proxy with auth

### WebSocket Support
- **Full tunneling**: Bidirectional message passing
- **Authentication**: Bearer token injection
- **Connection management**: Automatic cleanup on errors
- **Heartbeat**: Keep-alive for long-running connections

## Business Value Proposition

### For Developers
- **Single Integration Point**: One gateway for all MCP servers
- **No OAuth Complexity**: Gateway handles all authentication flows
- **Secure by Default**: Industry-standard security practices
- **AI Assistant Ready**: Works out-of-box with Claude.ai/ChatGPT

### For Organizations
- **Centralized Auth**: Control access to all MCP servers
- **Audit Trail**: All API calls logged and traceable
- **Zero Infrastructure**: Serverless deployment on Cloudflare
- **Global Performance**: Edge network reduces latency

## Alternative Architectures

### Node.js Fastify Gateway (`apps/gw/`)
- **Use Case**: Custom enterprise deployments
- **Features**: Full OAuth Gateway with WebSocket support
- **Deployment**: Docker, VPS, or serverless platforms
- **Development**: `npm run dev:gw`

### Mock IdP (`apps/mock-idp/`)
- **Use Case**: Local development and testing
- **Features**: OAuth 2.1 compliant mock server
- **Development**: `npm run dev:mock`

## Production Considerations

### Scaling
- **Cloudflare Workers**: Auto-scaling to millions of requests
- **KV Storage**: Eventually consistent, suitable for sessions
- **Global Edge**: Sub-100ms response times worldwide

### Monitoring
- **Cloudflare Analytics**: Built-in traffic and error monitoring
- **Custom Logs**: Structured logging to Cloudflare Logpush
- **Health Checks**: Built-in Worker health monitoring

### Security
- **TLS Termination**: Automatic HTTPS via Cloudflare
- **DDoS Protection**: Enterprise-grade built-in protection
- **WAF Rules**: Customizable web application firewall
- **Secret Management**: Cloudflare Worker secrets (encrypted at rest)

## Troubleshooting

### Common Issues
- **KV Namespace**: Ensure SESSIONS KV namespace is created and ID is correct
- **Secrets**: Verify all required secrets are set via `wrangler secret list`
- **MCP_SERVERS**: Ensure JSON format is valid in worker secrets
- **OAuth Redirects**: Verify redirect_uri matches deployed worker URL

### Development
- **Local Testing**: Use `npm run dev` for Wrangler dev server
- **Build Errors**: Check TypeScript compilation with `npm run build:worker`
- **Deploy Issues**: Verify wrangler.json configuration matches your account