# MCP OAuth Gateway

A production-ready Cloudflare Worker that provides secure OAuth authentication for multiple MCP servers via hostname-based routing.

## Business Architecture

**Target Users**: Developers using Claude.ai, ChatGPT, or other AI assistants that support MCP (Model Context Protocol)

**Problem Solved**: AI assistants need secure access to multiple MCP servers (Atlassian, GitHub, etc.) without exposing OAuth credentials or handling complex authentication flows.

**Solution**: A single OAuth gateway that handles browser-based authentication for multiple MCP servers via encoded hostnames.

## Technical Architecture

```
Claude.ai/ChatGPT → Cloudflare Worker → MCP Server (Atlassian/GitHub/etc)
     (CLIENT)           (GATEWAY)              (SERVER)
```

### Deployment: Cloudflare Worker
- **Production**: Single Worker handling all traffic  
- **Zero-config scaling**: Cloudflare's global edge network
- **In-memory sessions**: Ephemeral but simple (resets on worker restart)
- **Multi-domain support**: Works on both custom domain and *.workers.dev

### Hostname-Based MCP Server Routing
- **Format**: `{base32(domain)}-enc.copernicusone.com`
- **Example**: `mcp.atlassian.com` → `nvrxaltborwgc43tnfqw4ltdn5wq-enc.copernicusone.com`  
- **Per-Server OAuth**: Independent OAuth 2.1 + PKCE authentication per MCP server
- **Browser-Based Flow**: User logs in via web interface, then OAuth per server

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
1. **Developer Setup**: Visit `https://mcp.copernicusone.com` or `https://mcp.piotr-93c.workers.dev` dashboard
2. **Gateway Login**: Authenticate with LOCAL_USER/LOCAL_PASSWORD  
3. **URL Generation**: Enter MCP server domain → get encoded URL
4. **OAuth Setup**: Connect to each MCP server via browser-based OAuth flow
5. **Claude.ai Configuration**: Use encoded URLs as MCP server endpoints
6. **API Requests**: Automatic Bearer token injection for authenticated servers

### 3. Authentication & Authorization  
- **Gateway Auth**: Browser login with LOCAL_USER/LOCAL_PASSWORD
- **MCP Server Auth**: OAuth 2.1 + PKCE per server via browser
- **Session Storage**: In-memory Map (ephemeral, resets on restart)
- **Security**: CSRF protection, secure cookies, hostname validation

## Commands

### Development & Testing
- `npm run dev` - Start local development server with Wrangler
- `npm run build:worker` - Build TypeScript to JavaScript
- `npm run deploy` - Build and deploy to Cloudflare
- `npm test` - Run Playwright E2E tests
- `npm run dev:gw` - Start Node.js gateway (alternative architecture)

### Cloudflare Setup
1. **Set Secrets**: Configure required secrets
   ```bash
   wrangler secret put LOCAL_USER
   wrangler secret put LOCAL_PASSWORD  
   wrangler secret put MCP_SERVERS
   ```
2. **Deploy**: `npm run deploy`

## Environment Configuration

### Required Cloudflare Worker Secrets
```bash
# Gateway authentication
wrangler secret put LOCAL_USER
wrangler secret put LOCAL_PASSWORD

# MCP server OAuth configurations  
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
- **OAuth 2.1 PKCE (S256)**: Industry-standard security for MCP server auth
- **Session Management**: In-memory with automatic cleanup  
- **CSRF Protection**: Random token validation
- **Hostname Validation**: Dynamic redirect URLs prevent hijacking
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
- **In-Memory Sessions**: Fast but ephemeral (resets on worker restart)  
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

## Current Development Status

### 🚧 ACTIVE TODO: Atlassian OAuth Domain Allowlist Issue

**Problem**: Atlassian MCP server rejects redirect URIs from encoded domains despite successful dynamic client registration.

**Error**: `"The redirect URI is not allowed, the URL is not part of Atlassian allowlisted domains for registered MCP Clients. Redirect URI https://nvrxaltborwgc43tnfqw4ltdn5wq-enc.copernicusone.com/oauth/callback"`

**Current Status**: 
- ✅ Dynamic client registration implemented and working
- ✅ Registered client_id being used correctly  
- ❌ Atlassian still rejects encoded domain redirect URIs

**Next Steps**:
1. **Complete Landing Domain OAuth Callback Handler**:
   - Landing domain (`mcp.copernicusone.com`) receives OAuth callback from Atlassian
   - Extract tokens and server domain from callback
   - Redirect back to encoded domain to complete client authorization
   
2. **Update State Management**:
   - Store original encoded domain in OAuth state
   - Handle cross-domain session/token transfer
   
3. **Test Complete Flow**:
   - Claude → Encoded Domain → Atlassian (via landing domain redirect) → Landing Domain → Encoded Domain → Claude

**Implementation**: Currently using `https://mcp.copernicusone.com/oauth/callback` for upstream registration to satisfy Atlassian's domain allowlist.

### Commit Log
- `78a483d`: fix: use landing domain redirect URI for Atlassian OAuth registration

## Troubleshooting

### Common Issues
- **Domain Access**: Worker supports both `mcp.copernicusone.com` and `mcp.*.workers.dev`
- **Secrets**: Verify all required secrets are set via `wrangler secret list`
- **MCP_SERVERS**: Ensure JSON format is valid in worker secrets  
- **OAuth Redirects**: URLs dynamically use current hostname (no hardcoded domains)
- **Session Loss**: In-memory sessions reset on worker restart (re-login required)
- **Atlassian Domain Allowlist**: Use landing domain for OAuth callbacks due to Atlassian's domain restrictions

### Development
- **Local Testing**: Use `npm run dev` for Wrangler dev server
- **Build Errors**: Check TypeScript compilation with `npm run build:worker`
- **Deploy Issues**: Verify wrangler.json configuration matches your account