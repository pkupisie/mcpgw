/**
 * MCP OAuth Gateway - Cloudflare Worker
 * 
 * Simplified OAuth gateway implementing hostname-based routing with authentication
 * for MCP (Model Context Protocol) servers.
 * 
 * Architecture: Claude.ai/ChatGPT → Cloudflare Worker → MCP Server (with OAuth)
 */

/// <reference types="@cloudflare/workers-types" />

import { base32Encode, base32Decode } from './encoding';

// Types
interface MCPServerConfig {
  domain: string;
  name: string;
  authzEndpoint: string;
  tokenEndpoint: string;
  clientId: string;
  clientSecret?: string;
  scopes: string;
}

interface SessionData {
  csrf: string;
  localAuth: boolean;
  pendingResource?: string;
  oauth?: {
    [serverDomain: string]: {
      state?: string;
      pkceVerifier?: string;
      tokens?: {
        access_token: string;
        refresh_token?: string;
        expires_in?: number;
      };
      expiresAt?: number;
    };
  };
  localOAuthTokens?: {
    [domain: string]: {
      access_token: string;
      refresh_token?: string;
      expires_at: number;
      client_id: string;
    };
  };
  deviceCodes?: {
    [domain: string]: {
      [device_code: string]: {
        user_code: string;
        verification_uri: string;
        expires_at: number;
        client_id: string;
        scope: string;
        interval: number;
      };
    };
  };
  pendingClientAuth?: {
    client_id: string;
    redirect_uri: string;
    scope: string;
    state: string;
    code_challenge: string;
    code_challenge_method: string;
    resource: string;
    serverDomain: string;
  };
}

interface MCPRouteInfo {
  upstreamBase: URL;
  serverDomain: string;
}

// In-memory session storage (resets on worker restart)
const sessions = new Map<string, SessionData>();

// Global registered clients store (resets on worker restart)
const registeredClients = new Map<string, {
  client_id: string;
  client_secret?: string;
  registered_at: number;
}>();

// Global authorization code store
const authorizationCodes = new Map<string, {
  client_id: string;
  redirect_uri: string;
  scope: string;
  code_challenge: string;
  code_challenge_method: string;
  resource: string;
  domain: string;
  sessionId: string;
  expires_at: number;
}>();

// Global access token store
const accessTokens = new Map<string, {
  client_id: string;
  sessionId: string;
  domain: string;
  expires_at: number;
  scope: string;
}>();

// Environment bindings
interface Env {
  DOMAIN_ROOT: string;
  LOCAL_USER: string;
  LOCAL_PASSWORD: string;
  MCP_SERVERS: string;
  OAUTH_CODES: KVNamespace;
}

// Logging utilities
function generateRequestId(): string {
  return crypto.randomUUID();
}

// Structured logging helper
function log(data: any) {
  console.log(JSON.stringify(data));
}

// Summary line logging
function logSummary(endpoint: string, method: string, status: number, details: string) {
  console.log(`SUM ${endpoint} ${method} ${status} ${details}`);
}

// Request correlation tracking
const requestCorrelation = new Map<string, string>();

// Hostname parsing
function parseHostEncodedUpstream(hostname: string, domainRoot: string): MCPRouteInfo | null {
  const root = domainRoot.toLowerCase();
  const host = hostname.toLowerCase();
  
  if (!host.endsWith('.' + root)) return null;
  
  const parts = host.split('.');
  const rootParts = root.split('.');
  if (parts.length <= rootParts.length) return null;
  
  const encodedLabels = parts.slice(0, parts.length - rootParts.length);
  
  // Check for {base32}-enc format
  if (encodedLabels.length === 1) {
    const label = encodedLabels[0];
    if (label.endsWith('-enc')) {
      const base32Part = label.slice(0, -4);
      const decodedDomain = base32Decode(base32Part);
      
      if (decodedDomain) {
        try {
          let targetUrl: URL;
          if (decodedDomain.includes('://')) {
            targetUrl = new URL(decodedDomain);
          } else {
            targetUrl = new URL('https://' + decodedDomain);
          }
          
          return {
            upstreamBase: targetUrl,
            serverDomain: targetUrl.hostname
          };
        } catch {
          return null;
        }
      }
    }
  }
  
  return null;
}

// MCP request handler
export async function handleMCPRequest(request: Request, hostRoute: MCPRouteInfo, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const hostname = url.hostname;
  
  // Log ALL incoming requests for debugging
  console.log(`\n╔══ DOWNSTREAM REQUEST (Claude → Gateway) ══════════`);
  console.log(`║ URL: ${request.method} ${url.pathname}`);
  console.log(`║ Host: ${hostname}`);
  console.log(`║ Target Server: ${hostRoute.serverDomain}`);
  
  // Check if this is an MCP client trying to connect
  const mcpProtocolVersion = request.headers.get('mcp-protocol-version');
  const userAgent = request.headers.get('user-agent');
  const authHeader = request.headers.get('Authorization');
  
  console.log(`║ MCP Protocol: ${mcpProtocolVersion || 'not sent'}`);
  console.log(`║ User-Agent: ${userAgent || 'not sent'}`);
  console.log(`║ Authorization: ${authHeader ? `Bearer ${authHeader.slice(7, 20)}...` : 'none'}`);
  console.log(`╚════════════════════════════════════════════════════`);
  
  // If it's an MCP client without auth, check if it's accessing public endpoints
  if (mcpProtocolVersion && (!authHeader || !authHeader.startsWith('Bearer '))) {
    console.log('MCP client detected without OAuth');
    console.log(`MCP Protocol: ${mcpProtocolVersion}, Auth header: ${authHeader || 'none'}, User-Agent: ${userAgent}`);
    
    const url = new URL(request.url);
    
    // Handle .well-known and OAuth endpoints without authentication
    if (url.pathname.startsWith('/.well-known/oauth-authorization-server')) {
      console.log(`Serving OAuth discovery for: ${url.pathname}`);
      return handleOAuthDiscovery(request, hostRoute, env);
    }
    
    if (url.pathname.startsWith('/.well-known/oauth-protected-resource')) {
      console.log(`Serving protected resource metadata for: ${url.pathname}`);
      return handleProtectedResourceMetadata(request, hostRoute, env);
    }
    
    if (url.pathname.startsWith('/oauth/')) {
      console.log(`Allowing unauthenticated access to OAuth endpoint: ${url.pathname}`);
      // OAuth endpoints are handled elsewhere, let them through
    } else {
      // Require authentication for ALL MCP data endpoints including SSE
      console.log(`Requiring authentication for MCP endpoint: ${url.pathname}`);
      
      // Use different WWW-Authenticate format for /sse vs other endpoints
      const wwwAuthHeader = url.pathname === '/sse' 
        ? 'Bearer realm="mcp", scope="mcp read write"'
        : 'Bearer realm="OAuth", error="invalid_token", error_description="Missing or invalid access token"';
      
      const responseBody = JSON.stringify({ 
        error: 'invalid_token',
        error_description: 'Missing or invalid access token'
      });
      
      const responseHeaders = { 
        'Content-Type': 'application/json',
        'WWW-Authenticate': wwwAuthHeader
      };
      
      console.log(`\n╔══ DOWNSTREAM RESPONSE (Gateway → Claude) ═════════`);
      console.log(`║ Status: 401 Unauthorized`);
      console.log(`║ Path: ${url.pathname}`);
      console.log(`║ Headers:`);
      console.log(`║   Content-Type: ${responseHeaders['Content-Type']}`);
      console.log(`║   WWW-Authenticate: ${responseHeaders['WWW-Authenticate']}`);
      console.log(`║ Body: ${responseBody}`);
      console.log(`╚════════════════════════════════════════════════════`);
      
      return new Response(responseBody, { 
        status: 401,
        headers: responseHeaders
      });
    }
  }
  
  // Enhanced SSE handling with detailed logging
  if (url.pathname === '/sse') {
    const reqId = generateRequestId();
    const auth = request.headers.get('Authorization') ?? '';
    const hasAuth = !!auth;
    const isBearer = auth.startsWith('Bearer ');
    const token = isBearer ? auth.slice(7) : '';
    const tokenSnip = token ? token.slice(0, 8) : '';
    const acceptEncoding = request.headers.get('accept-encoding') ?? '';
    const compressionEnabled = acceptEncoding.includes('gzip') || acceptEncoding.includes('br');
    
    // Log SSE request details
    log({
      kind: 'sse_request',
      req_id: reqId,
      method: request.method,
      path: url.pathname,
      auth_present: hasAuth,
      bearer_prefix_ok: isBearer,
      token_snip: tokenSnip,
      ua: request.headers.get('User-Agent'),
      mcp_version: mcpProtocolVersion,
      compression_requested: compressionEnabled
    });
    
    // Check if no auth provided
    if (!isBearer) {
      const reason = !hasAuth ? 'missing_auth' : 'invalid_auth_format';
      const headers = {
        'Content-Type': 'application/json',
        'WWW-Authenticate': 'Bearer realm="mcp", scope="mcp read write"',
        'X-Request-Id': reqId // Include request ID for correlation
      };
      
      // Store request ID for later correlation
      requestCorrelation.set(hostname, reqId);
      
      log({
        kind: 'sse_response',
        req_id: reqId,
        status: 401,
        challenge_header_set: true,
        reason
      });
      
      logSummary('/sse', request.method, 401, `hasAuth=${hasAuth} reason=${reason} req=${reqId.slice(0, 8)}`);
      
      return new Response(JSON.stringify({ 
        error: 'invalid_token',
        error_description: reason
      }), { 
        status: 401,
        headers
      });
    }
    
    // Validate token
    const tokenData = accessTokens.get(token);
    const tokenValid = tokenData && tokenData.expires_at > Date.now();
    const validationReason = !tokenData ? 'token_not_found' : 
                            tokenData.expires_at < Date.now() ? 'token_expired' : 
                            'valid';
    
    log({
      kind: 'token_validation',
      req_id: reqId,
      ok: tokenValid,
      reason: validationReason,
      scopes: tokenData?.scope?.split(' '),
      exp: tokenData ? new Date(tokenData.expires_at).toISOString() : null,
      client_id: tokenData?.client_id
    });
    
    if (!tokenValid) {
      const headers = {
        'Content-Type': 'application/json',
        'WWW-Authenticate': 'Bearer error="invalid_token"',
      };
      
      log({
        kind: 'sse_response',
        req_id: reqId,
        status: 401,
        challenge_header_set: true,
        reason: validationReason
      });
      
      logSummary('/sse', request.method, 401, `token_invalid reason=${validationReason} req=${reqId.slice(0, 8)}`);
      
      return new Response(JSON.stringify({ 
        error: 'invalid_token',
        error_description: validationReason
      }), { 
        status: 401,
        headers
      });
    }
    
    // Token is valid - handle HEAD or GET
    if (request.method === 'HEAD') {
      const headers = {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization, MCP-Protocol-Version',
        'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS'
      };
      
      log({
        kind: 'sse_response',
        req_id: reqId,
        status: 200,
        content_type: headers['Content-Type'],
        cache_control: headers['Cache-Control'],
        compression_enabled: false // We don't compress HEAD responses
      });
      
      logSummary('/sse', 'HEAD', 200, `authenticated token_snip=${tokenSnip} req=${reqId.slice(0, 8)}`);
      
      return new Response(null, { status: 200, headers });
    }
    
    if (request.method === 'GET') {
      log({
        kind: 'sse_stream_starting',
        req_id: reqId,
        client_id: tokenData.client_id,
        scopes: tokenData.scope
      });
      
      logSummary('/sse', 'GET', 200, `stream_established token_snip=${tokenSnip} req=${reqId.slice(0, 8)}`);
      
      // Pass request ID to SSE handler for correlation
      return handleMCPSSE(request, hostRoute, env, reqId);
    }
  }
  
  // Handle authenticated clients for non-SSE endpoints
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const url = new URL(request.url);
    
    console.log(`\n╔══ AUTHENTICATED DOWNSTREAM REQUEST ════════════════`);
    console.log(`║ Path: ${url.pathname}`);
    console.log(`║ Method: ${request.method}`);
    console.log(`║ MCP Protocol: ${mcpProtocolVersion || 'NOT SENT (possible issue)'}`);
    console.log(`║ Bearer Token: ${authHeader.slice(7, 20)}...`);
    console.log(`╚════════════════════════════════════════════════════`);
  }
  
  // Removed public proxy mode - now requiring authentication for all MCP clients
  
  // If not an MCP client or public proxy failed, require local OAuth
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    const metadataUrl = `https://${hostname}/.well-known/oauth-authorization-server`;
    return new Response(JSON.stringify({ 
      error: 'Authentication required',
      error_description: 'Bearer token required',
      authorization_servers: [metadataUrl]
    }), { 
      status: 401,
      headers: { 
        'Content-Type': 'application/json',
        'WWW-Authenticate': `Bearer realm="MCP Gateway", authorization_uri="${metadataUrl}"`
      }
    });
  }
  
  const localToken = authHeader.slice(7); // Remove 'Bearer '
  
  // Look up token in global store
  const tokenData = accessTokens.get(localToken);
  
  if (!tokenData) {
    return new Response(JSON.stringify({ 
      error: 'invalid_token',
      error_description: 'Invalid token'
    }), { 
      status: 401,
      headers: { 
        'Content-Type': 'application/json',
        'WWW-Authenticate': 'Bearer error="invalid_token"'
      }
    });
  }
  
  // Check if token expired
  if (tokenData.expires_at < Date.now()) {
    // Clean up expired token
    accessTokens.delete(localToken);
    
    return new Response(JSON.stringify({ 
      error: 'invalid_token',
      error_description: 'Token expired'
    }), { 
      status: 401,
      headers: { 
        'Content-Type': 'application/json',
        'WWW-Authenticate': 'Bearer error="invalid_token"'
      }
    });
  }
  
  // Get the session for upstream token lookup
  const sessionWithToken = sessions.get(tokenData.sessionId);
  
  if (!sessionWithToken || !sessionWithToken.localAuth) {
    return new Response(JSON.stringify({ 
      error: 'invalid_token',
      error_description: 'Session not found or not authenticated'
    }), { 
      status: 401,
      headers: { 
        'Content-Type': 'application/json',
        'WWW-Authenticate': 'Bearer error="invalid_token"'
      }
    });
  }
  
  // Check upstream OAuth tokens for this server
  const serverData = sessionWithToken.oauth?.[hostRoute.serverDomain];
  let useUpstreamAuth = !!serverData?.tokens;
  
  // If no upstream auth configured, try without auth first (bypass mode)
  if (!useUpstreamAuth) {
    // Try to discover upstream OAuth capabilities
    const upstreamOAuthDiscovery = await discoverUpstreamOAuth(hostRoute.serverDomain);
    
    if (upstreamOAuthDiscovery) {
      // Upstream supports OAuth but we don't have tokens
      return new Response(JSON.stringify({ 
        error: 'upstream_auth_required',
        error_description: 'Upstream server authentication required',
        server: hostRoute.serverDomain,
        authUrl: `https://${getCurrentDomain(request)}/oauth/start?server=${encodeURIComponent(hostRoute.serverDomain)}`,
        upstreamOAuth: upstreamOAuthDiscovery
      }), { 
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    // No upstream OAuth discovered, try without auth (public server mode)
    useUpstreamAuth = false;
  }
  
  // Build upstream request
  const upstreamUrl = new URL(request.url.replace(request.url.split('/')[2], hostRoute.upstreamBase.host));
  
  const upstreamHeaders: Record<string, string> = {};
  request.headers.forEach((value, key) => {
    if (key.toLowerCase() !== 'host' && key.toLowerCase() !== 'authorization') {
      upstreamHeaders[key] = value;
    }
  });
  
  // Check if token needs refresh before using it
  if (useUpstreamAuth && serverData?.tokens) {
    // Proactively refresh token if it's expired or about to expire (within 5 minutes)
    if (isTokenExpired(serverData.expiresAt, 300)) {
      console.log(`\n╔══ UPSTREAM TOKEN REFRESH ══════════════════════════`);
      console.log(`║ Server: ${hostRoute.serverDomain}`);
      console.log(`║ Reason: Token expired or expiring within 5 minutes`);
      const refreshed = await refreshUpstreamToken(hostRoute.serverDomain, serverData, env);
      if (!refreshed) {
        console.error(`║ Result: FAILED - continuing with expired token`);
      } else {
        console.log(`║ Result: SUCCESS - new token acquired`);
      }
      console.log(`╚════════════════════════════════════════════════════`);
    }
    upstreamHeaders['Authorization'] = `Bearer ${serverData.tokens.access_token}`;
  }
  upstreamHeaders['Host'] = hostRoute.upstreamBase.hostname;

  // Check for WebSocket upgrade
  const upgradeHeader = request.headers.get('Upgrade');
  if (upgradeHeader === 'websocket') {
    return handleWebSocketUpgrade(request, hostRoute, upstreamHeaders);
  }
  
  const upstreamRequest = new Request(upstreamUrl.toString(), {
    method: request.method,
    headers: upstreamHeaders,
    body: request.body,
  });
  
  // Forward request to upstream
  console.log(`\n╔══ UPSTREAM REQUEST (Gateway → ${hostRoute.serverDomain}) ══`);
  console.log(`║ URL: ${request.method} ${upstreamUrl.toString()}`);
  console.log(`║ Auth: ${upstreamHeaders['Authorization'] ? `Bearer ${upstreamHeaders['Authorization'].slice(7, 20)}...` : 'No auth (bypass mode)'}`);
  console.log(`║ Headers sent: ${Object.keys(upstreamHeaders).join(', ')}`);
  console.log(`╚════════════════════════════════════════════════════`);
  
  const response = await fetch(upstreamRequest);
  
  console.log(`\n╔══ UPSTREAM RESPONSE ═══════════════════════════════`);
  console.log(`║ Status: ${response.status} ${response.statusText}`);
  console.log(`║ Headers: ${Array.from(response.headers.keys()).join(', ')}`);
  if (response.status === 401) {
    const wwwAuth = response.headers.get('WWW-Authenticate');
    console.log(`║ WWW-Authenticate: ${wwwAuth || 'not present'}`);
  }
  console.log(`╚════════════════════════════════════════════════════`);
  
  // Handle token refresh on 401
  if (response.status === 401 && serverData?.tokens?.refresh_token) {
    console.log(`\n╔══ UPSTREAM 401 - ATTEMPTING TOKEN REFRESH ════════`);
    console.log(`║ Server: ${hostRoute.serverDomain}`);
    const refreshed = await refreshUpstreamToken(hostRoute.serverDomain, serverData, env);
    if (refreshed) {
      console.log(`║ Refresh: SUCCESS - retrying request`);
      // Retry with new token
      upstreamHeaders['Authorization'] = `Bearer ${serverData.tokens.access_token}`;
      const retryRequest = new Request(upstreamUrl.toString(), {
        method: request.method,
        headers: upstreamHeaders,
        body: request.body,
      });
      const retryResponse = await fetch(retryRequest);
      console.log(`║ Retry Status: ${retryResponse.status} ${retryResponse.statusText}`);
      console.log(`╚════════════════════════════════════════════════════`);
      return retryResponse;
    } else {
      console.log(`║ Refresh: FAILED - returning 401 to client`);
      console.log(`╚════════════════════════════════════════════════════`);
    }
  }
  
  return response;
}

// Dashboard
export async function handleDashboard(request: Request, env: Env): Promise<Response> {
  const sessionId = getSessionId(request);
  const session = sessionId ? await getSession(sessionId, env) : null;
  
  if (!session || !session.localAuth) {
    return Response.redirect(`https://${getCurrentDomain(request)}/login`, 302);
  }
  
  // Parse MCP servers
  let mcpServers: MCPServerConfig[] = [];
  try {
    mcpServers = JSON.parse(env.MCP_SERVERS || '[]');
  } catch (e) {
    console.error('Failed to parse MCP_SERVERS:', e);
  }
  
  let serversHtml = '<h2>MCP Servers</h2>';
  if (mcpServers.length === 0) {
    serversHtml += '<p>No MCP servers configured.</p>';
  } else {
    serversHtml += '<ul>';
    for (const server of mcpServers) {
      const isConnected = !!(session.oauth?.[server.domain]?.tokens);
      const encodedHostname = generateEncodedHostname(server.domain, env.DOMAIN_ROOT);
      const encodedUrl = `https://${encodedHostname}/`;
      serversHtml += `
        <li>
          <strong>${server.name}</strong> (${server.domain}) 
          ${isConnected ? '✅ Connected' : '❌ Not connected'}
          <br><small>URL: <code>${encodedUrl}</code></small>
          ${!isConnected ? `<br><a href="/oauth/start?server=${encodeURIComponent(server.domain)}">Connect</a>` : ''}
        </li>`;
    }
    serversHtml += '</ul>';
  }
  
  const html = `<!doctype html><html><head><title>MCP Gateway</title></head><body>
    <h1>MCP OAuth Gateway</h1>
    <p>Domain root: <code>${env.DOMAIN_ROOT}</code></p>
    ${serversHtml}
    <h3>Add New Server</h3>
    <form method="GET" action="/encode">
      <label>Domain: <input name="domain" placeholder="mcp.example.com" required></label>
      <button type="submit">Generate URL</button>
    </form>
  </body></html>`;
  
  return new Response(html, {
    headers: { 'Content-Type': 'text/html' }
  });
}

// Login handlers
export function handleLoginPage(request: Request): Response {
  const returnTo = new URL(request.url).searchParams.get('return_to') || '';
  
  const html = `<!doctype html><html><body>
    <h1>MCP Gateway Login</h1>
    <form method="POST" action="/login">
      <label>User: <input name="user" required></label><br><br>
      <label>Pass: <input name="pass" type="password" required></label><br><br>
      <input type="hidden" name="return_to" value="${returnTo}">
      <button type="submit">Sign in</button>
    </form>
  </body></html>`;
  
  return new Response(html, {
    headers: { 'Content-Type': 'text/html' }
  });
}

export async function handleLogin(request: Request, env: Env): Promise<Response> {
  const formData = await request.formData();
  const user = formData.get('user') as string;
  const pass = formData.get('pass') as string;
  
  if (user !== env.LOCAL_USER || pass !== env.LOCAL_PASSWORD) {
    return new Response('Invalid credentials', { status: 401 });
  }
  
  // Create session
  const sessionId = generateSessionId();
  const session: SessionData = {
    csrf: generateRandomString(32),
    localAuth: true,
    oauth: {}
  };
  
  sessions.set(sessionId, session);
  
  // Clean up old sessions periodically (simple memory management)
  if (sessions.size > 1000) {
    // Remove oldest sessions when we hit 1000
    const entries = Array.from(sessions.entries());
    for (let i = 0; i < 100; i++) {
      sessions.delete(entries[i][0]);
    }
  }
  
  // Check for return_to parameter
  const returnTo = new URL(request.url).searchParams.get('return_to') || 
                   formData.get('return_to') as string || 
                   `https://${getCurrentDomain(request)}/`;
  
  return new Response(null, {
    status: 302,
    headers: {
      'Location': returnTo,
      'Set-Cookie': `session=${sessionId}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=28800`
    }
  });
}

// Local OAuth handlers for encoded domains
export async function handleOAuthDiscovery(request: Request, hostRoute: MCPRouteInfo, env: Env): Promise<Response> {
  const hostname = new URL(request.url).hostname;
  
  // MCP-compliant OAuth 2.0 Authorization Server Metadata (RFC 8414)
  const discovery = {
    issuer: `https://${hostname}`,
    authorization_endpoint: `https://${hostname}/oauth/authorize`,
    token_endpoint: `https://${hostname}/oauth/token`,
    device_authorization_endpoint: `https://${hostname}/oauth/device`,
    revocation_endpoint: `https://${hostname}/oauth/revoke`,
    introspection_endpoint: `https://${hostname}/oauth/introspect`,
    registration_endpoint: `https://${hostname}/oauth/register`,
    
    // MCP-required fields
    response_types_supported: ['code'],
    grant_types_supported: [
      'authorization_code', 
      'refresh_token', 
      'urn:ietf:params:oauth:grant-type:device_code'
    ],
    code_challenge_methods_supported: ['S256'], // PKCE required
    token_endpoint_auth_methods_supported: [
      'client_secret_post', 
      'client_secret_basic', 
      'none'
    ],
    device_authorization_endpoint_auth_methods_supported: [
      'client_secret_post', 
      'client_secret_basic', 
      'none'
    ],
    
    // Scopes - MCP spec doesn't define required scopes, but common ones
    scopes_supported: ['mcp', 'read', 'write'],
    
    // Additional OAuth 2.1 fields
    response_modes_supported: ['query', 'fragment'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
    
    // Resource server identification (RFC 8707)
    resource_parameter_supported: true,
    
    // Service documentation
    service_documentation: `https://${hostname}`,
    op_policy_uri: `https://${hostname}/privacy`,
    op_tos_uri: `https://${hostname}/terms`
  };
  
  return new Response(JSON.stringify(discovery, null, 2), {
    headers: { 
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Cache-Control': 'max-age=3600'
    }
  });
}

// Protected resource metadata (RFC 9728)
export async function handleProtectedResourceMetadata(request: Request, hostRoute: MCPRouteInfo, env: Env): Promise<Response> {
  const hostname = new URL(request.url).hostname;
  
  const metadata = {
    resource: `https://${hostname}`,
    authorization_servers: [`https://${hostname}`],
    scopes_supported: ['mcp', 'read', 'write'],
    bearer_methods_supported: ['authorization_header'],
    sse_endpoint: '/sse',
    resource_documentation: `https://${hostname}`,
    
    // Explicitly indicate that authentication is required
    authentication_required: true,
    
    // MCP-specific metadata
    mcp_version: '1.0',
    upstream_server: hostRoute.serverDomain,
    capabilities: ['tools', 'resources', 'prompts'],
    
    // Server identification for Claude
    server_name: `${hostRoute.serverDomain} (via MCP Gateway)`,
    description: `MCP OAuth Gateway proxying requests to ${hostRoute.serverDomain}`
  };
  
  // Log the protected resource metadata
  log({
    kind: 'well_known_protected_resource',
    path: request.url,
    body: metadata
  });
  
  logSummary('/.well-known/oauth-protected-resource', 'GET', 200, `bearer_methods=${metadata.bearer_methods_supported.join(',')}`);
  
  return new Response(JSON.stringify(metadata, null, 2), {
    headers: { 
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Cache-Control': 'max-age=3600'
    }
  });
}

// MCP SSE Handler
export async function handleMCPSSE(request: Request, hostRoute: MCPRouteInfo, env: Env, reqId?: string): Promise<Response> {
  console.log(`\n╔══ SSE STREAM ESTABLISHED ══════════════════════════════`);
  console.log(`║ Downstream: Claude → Gateway (authenticated)`);
  console.log(`║ Upstream: Gateway → ${hostRoute.serverDomain}`);
  console.log(`╚══════════════════════════════════════════════════════`);
  
  // Create a TransformStream for SSE
  const { readable, writable } = new TransformStream();
  const writer = writable.getWriter();
  const encoder = new TextEncoder();
  
  // Start the SSE stream
  const streamPromise = (async () => {
    try {
      // Send initial connection message
      await writer.write(encoder.encode(': ping\n\n'));
      
      // Send MCP initialize response
      const initResponse = {
        jsonrpc: '2.0',
        id: 1,
        result: {
          protocolVersion: '2025-06-18',
          capabilities: {
            tools: {},
            resources: {},
            prompts: {}
          },
          serverInfo: {
            name: `MCP Gateway for ${hostRoute.serverDomain}`,
            version: '1.0.0'
          }
        }
      };
      
      await writer.write(encoder.encode(`data: ${JSON.stringify(initResponse)}\n\n`));
      
      // Try to connect to upstream MCP SSE if available
      const upstreamSSE = await tryConnectUpstreamSSE(hostRoute, env);
      
      if (upstreamSSE) {
        // Proxy upstream SSE events
        const reader = upstreamSSE.getReader();
        const decoder = new TextDecoder();
        
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          
          const chunk = decoder.decode(value, { stream: true });
          await writer.write(encoder.encode(chunk));
        }
      } else {
        // No upstream SSE, keep connection alive with heartbeats
        const heartbeatInterval = setInterval(async () => {
          try {
            await writer.write(encoder.encode(': ping\n\n'));
          } catch (error) {
            clearInterval(heartbeatInterval);
          }
        }, 30000); // 30 second heartbeat
        
        // Clean up on connection close
        request.signal.addEventListener('abort', () => {
          clearInterval(heartbeatInterval);
          writer.close();
        });
      }
    } catch (error) {
      console.error('SSE stream error:', error);
      await writer.close();
    }
  })();
  
  // Return SSE response
  return new Response(readable, {
    headers: {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, MCP-Protocol-Version',
      'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS',
      'X-Accel-Buffering': 'no' // Disable buffering for SSE
    }
  });
}

// Try to connect to upstream MCP SSE endpoint
export async function tryConnectUpstreamSSE(hostRoute: MCPRouteInfo, env: Env): Promise<ReadableStream | null> {
  try {
    const upstreamUrl = new URL(hostRoute.upstreamBase);
    upstreamUrl.pathname = '/sse';
    
    const response = await fetch(upstreamUrl.toString(), {
      headers: {
        'Accept': 'text/event-stream',
        'MCP-Protocol-Version': '2025-06-18'
      }
    });
    
    if (response.ok && response.body) {
      console.log(`Connected to upstream SSE at ${upstreamUrl.toString()}`);
      return response.body;
    }
  } catch (error) {
    console.log(`No upstream SSE available for ${hostRoute.serverDomain}:`, error);
  }
  
  return null;
}

export async function handleLocalOAuth(request: Request, hostRoute: MCPRouteInfo, env: Env): Promise<Response> {
  const url = new URL(request.url);
  
  if (url.pathname === '/oauth/authorize') {
    if (request.method === 'GET') return handleLocalOAuthAuthorize(request, hostRoute, env);
    if (request.method === 'POST') return handleLocalOAuthAuthorizePost(request, hostRoute, env);
  }
  
  if (url.pathname === '/oauth/token') {
    if (request.method === 'POST') return handleLocalOAuthToken(request, hostRoute, env);
  }
  
  if (url.pathname === '/oauth/device') {
    if (request.method === 'POST') return handleLocalOAuthDevice(request, hostRoute, env);
  }
  
  if (url.pathname === '/oauth/revoke') {
    if (request.method === 'POST') return handleLocalOAuthRevoke(request, hostRoute, env);
  }
  
  if (url.pathname === '/oauth/introspect') {
    if (request.method === 'POST') return handleLocalOAuthIntrospect(request, hostRoute, env);
  }
  
  if (url.pathname === '/oauth/device/verify') {
    if (request.method === 'GET') return handleDeviceVerify(request, hostRoute, env);
    if (request.method === 'POST') return handleDeviceVerifyPost(request, hostRoute, env);
  }
  
  if (url.pathname === '/oauth/register') {
    if (request.method === 'POST') return handleClientRegistration(request, hostRoute, env);
  }
  
  if (url.pathname === '/oauth/callback') {
    return handleOAuthCallback(request, env);
  }
  
  return new Response('OAuth endpoint not found', { status: 404 });
}

export async function handleLocalOAuthAuthorize(request: Request, hostRoute: MCPRouteInfo, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const params = url.searchParams;
  
  const response_type = params.get('response_type');
  const client_id = params.get('client_id');
  const redirect_uri = params.get('redirect_uri');
  const scope = params.get('scope');
  const state = params.get('state');
  const code_challenge = params.get('code_challenge');
  const code_challenge_method = params.get('code_challenge_method');
  const resource = params.get('resource'); // RFC 8707 resource parameter
  
  // Validate required parameters
  if (response_type !== 'code') {
    return new Response('Only authorization code flow is supported', { status: 400 });
  }
  
  if (!client_id || !redirect_uri) {
    return new Response('Missing required parameters: client_id, redirect_uri', { status: 400 });
  }
  
  // Check if user is authenticated with gateway
  const sessionId = getSessionId(request);
  const session = sessionId ? await getSession(sessionId, env) : null;
  
  if (!session || !session.localAuth) {
    // Redirect to login with return URL
    const loginUrl = new URL(`https://${getCurrentDomain(request)}/login`);
    loginUrl.searchParams.set('return_to', request.url);
    return Response.redirect(loginUrl.toString(), 302);
  }
  
  // Show authorization consent page
  const hostname = new URL(request.url).hostname;
  const html = `<!doctype html><html><head><title>Authorize Application</title></head><body>
    <h1>Authorize MCP Access</h1>
    <p><strong>Application:</strong> ${client_id}</p>
    <p><strong>Server:</strong> ${hostRoute.serverDomain}</p>
    <p><strong>Scopes:</strong> ${scope || 'default'}</p>
    ${resource ? `<p><strong>Resource:</strong> ${resource}</p>` : ''}
    <form method="POST" action="/oauth/authorize">
      <input type="hidden" name="response_type" value="${response_type}">
      <input type="hidden" name="client_id" value="${client_id}">
      <input type="hidden" name="redirect_uri" value="${redirect_uri}">
      <input type="hidden" name="scope" value="${scope || ''}">
      <input type="hidden" name="state" value="${state || ''}">
      <input type="hidden" name="code_challenge" value="${code_challenge || ''}">
      <input type="hidden" name="code_challenge_method" value="${code_challenge_method || ''}">
      <input type="hidden" name="resource" value="${resource || ''}">
      <button type="submit" name="action" value="authorize">Authorize</button>
      <button type="submit" name="action" value="deny">Deny</button>
    </form>
  </body></html>`;
  
  return new Response(html, {
    headers: { 'Content-Type': 'text/html' }
  });
}

export async function handleLocalOAuthAuthorizePost(request: Request, hostRoute: MCPRouteInfo, env: Env): Promise<Response> {
  const formData = await request.formData();
  const action = formData.get('action');
  
  if (action !== 'authorize') {
    const redirect_uri = formData.get('redirect_uri') as string;
    const state = formData.get('state') as string;
    const errorUrl = new URL(redirect_uri);
    errorUrl.searchParams.set('error', 'access_denied');
    if (state) errorUrl.searchParams.set('state', state);
    return Response.redirect(errorUrl.toString(), 302);
  }
  
  // Generate authorization code
  const code = generateRandomString(32);
  const sessionId = getSessionId(request);
  const session = await getSession(sessionId!, env);
  
  if (!session) {
    return new Response('Session expired', { status: 401 });
  }
  
  // Check if we have upstream tokens for this server
  const upstreamTokens = session.oauth?.[hostRoute.serverDomain]?.tokens;
  
  if (!upstreamTokens) {
    // Save pending client authorization
    session.pendingClientAuth = {
      client_id: formData.get('client_id') as string,
      redirect_uri: formData.get('redirect_uri') as string,
      scope: formData.get('scope') as string,
      state: formData.get('state') as string,
      code_challenge: formData.get('code_challenge') as string,
      code_challenge_method: formData.get('code_challenge_method') as string,
      resource: formData.get('resource') as string,
      serverDomain: hostRoute.serverDomain
    };
    
    // Redirect to upstream OAuth
    return initiateUpstreamOAuth(request, hostRoute, session, env);
  }
  
  // Store authorization code data globally
  const hostname = new URL(request.url).hostname;
  
  const codeData = {
    client_id: formData.get('client_id') as string,
    redirect_uri: formData.get('redirect_uri') as string,
    scope: formData.get('scope') as string,
    code_challenge: formData.get('code_challenge') as string,
    code_challenge_method: formData.get('code_challenge_method') as string,
    resource: formData.get('resource') as string, // RFC 8707 resource parameter
    domain: hostname,
    sessionId: sessionId!,
    expires_at: Date.now() + 600000, // 10 minutes
    req_id_from_probe: requestCorrelation.get(hostname) || undefined // Correlate with original SSE probe
  };
  
  // Store code in KV with TTL for automatic expiration
  await env.OAUTH_CODES.put(
    code,
    JSON.stringify(codeData),
    { expirationTtl: 600 } // 10 minutes TTL
  );
  
  // Redirect back to client
  const redirectUrl = new URL(formData.get('redirect_uri') as string);
  redirectUrl.searchParams.set('code', code);
  const state = formData.get('state') as string;
  if (state) redirectUrl.searchParams.set('state', state);
  
  return Response.redirect(redirectUrl.toString(), 302);
}

export async function handleLocalOAuthToken(request: Request, hostRoute: MCPRouteInfo, env: Env): Promise<Response> {
  const formData = await request.formData();
  const grant_type = formData.get('grant_type');
  
  console.log(`\n╔══ DOWNSTREAM OAUTH TOKEN EXCHANGE (Claude → Gateway) ══`);
  console.log(`║ Grant Type: ${grant_type}`);
  
  if (grant_type === 'authorization_code') {
    const code = formData.get('code') as string;
    const client_id = formData.get('client_id') as string;
    const redirect_uri = formData.get('redirect_uri') as string;
    const code_verifier = formData.get('code_verifier') as string;
    
    console.log(`║ Code: ${code?.substring(0, 8)}...`);
    console.log(`║ Client ID: ${client_id}`);
    console.log(`║ Redirect URI: ${redirect_uri}`);
    
    // Look up code in KV store
    const codeDataStr = await env.OAUTH_CODES.get(code);
    
    if (!codeDataStr) {
      console.log(`Code lookup failed - code not found in KV`);
      console.log(`Looking for: ${code?.substring(0, 8)}...`);
      return new Response(JSON.stringify({ error: 'invalid_grant', error_description: 'Authorization code expired or not found' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    const codeData = JSON.parse(codeDataStr);
    console.log(`Code found in KV, client_id: ${codeData.client_id}`);
    
    // Validate client_id matches
    if (codeData.client_id !== client_id) {
      return new Response(JSON.stringify({ error: 'invalid_client', error_description: 'Client ID mismatch' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    // Validate redirect_uri matches
    if (codeData.redirect_uri !== redirect_uri) {
      return new Response(JSON.stringify({ error: 'invalid_grant', error_description: 'Redirect URI mismatch' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    // Delete code from KV after use (one-time use)
    await env.OAUTH_CODES.delete(code);
    
    // Verify PKCE if provided
    if (codeData.code_challenge && code_verifier) {
      const challenge = await sha256Base64Url(code_verifier);
      if (challenge !== codeData.code_challenge) {
        return new Response(JSON.stringify({ error: 'invalid_grant', error_description: 'PKCE verification failed' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        });
      }
    }
    
    // Generate tokens
    const access_token = `gw_access_${generateRandomString(32)}`;
    const refresh_token = `gw_refresh_${generateRandomString(32)}`;
    const expires_in = 3600; // 1 hour
    
    // Store access token globally
    accessTokens.set(access_token, {
      client_id: codeData.client_id,
      sessionId: codeData.sessionId,
      domain: codeData.domain,
      expires_at: Date.now() + (expires_in * 1000),
      scope: codeData.scope
    });
    
    const tokenResponse: any = {
      access_token,
      refresh_token,
      token_type: 'Bearer',
      expires_in,
      scope: codeData.scope
    };
    
    // Enhanced token issuance logging
    const expiresAt = new Date(Date.now() + expires_in * 1000);
    log({
      kind: 'token_issued',
      grant_type: 'authorization_code',
      client_id: codeData.client_id,
      access_token_snip: access_token.slice(0, 8),
      scopes_issued: codeData.scope.split(' '),
      audience: codeData.resource || null,
      expires_at: expiresAt.toISOString(),
      cache_control_set: true,
      correlates_req_id: codeData.req_id_from_probe || null
    });
    
    logSummary('/oauth/token', 'POST', 200, 
      `snip=${access_token.slice(0, 8)} scopes=${codeData.scope} exp=${expiresAt.toISOString()}`);
    
    console.log(`║ Token Response:`, JSON.stringify(tokenResponse, null, 2));
    console.log(`╚══════════════════════════════════════════════════════`);
    
    return new Response(JSON.stringify(tokenResponse), {
      headers: { 
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store'
      }
    });
  }
  
  if (grant_type === 'refresh_token') {
    const refresh_token = formData.get('refresh_token') as string;
    const hostname = new URL(request.url).hostname;
    
    // Find session with this refresh token
    let tokenData: any = null;
    let sessionWithToken: SessionData | null = null;
    
    for (const session of sessions.values()) {
      const localToken = session.localOAuthTokens?.[hostname];
      if (localToken?.refresh_token === refresh_token) {
        tokenData = localToken;
        sessionWithToken = session;
        break;
      }
    }
    
    if (!tokenData) {
      return new Response(JSON.stringify({ error: 'invalid_grant' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    // Generate new access token
    const access_token = `gw_access_${generateRandomString(32)}`;
    const expires_in = 3600;
    
    tokenData.access_token = access_token;
    tokenData.expires_at = Date.now() + (expires_in * 1000);
    
    return new Response(JSON.stringify({
      access_token,
      refresh_token,
      token_type: 'Bearer',
      expires_in
    }), {
      headers: { 
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store'
      }
    });
  }
  
  if (grant_type === 'urn:ietf:params:oauth:grant-type:device_code') {
    const device_code = formData.get('device_code') as string;
    const client_id = formData.get('client_id') as string;
    const hostname = new URL(request.url).hostname;
    
    if (!device_code || !client_id) {
      return new Response(JSON.stringify({ error: 'invalid_request' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    // Find device code in any session
    let deviceData: any = null;
    let sessionWithDevice: SessionData | null = null;
    
    for (const session of sessions.values()) {
      const deviceCodeData = session.deviceCodes?.[hostname]?.[device_code];
      if (deviceCodeData) {
        if (deviceCodeData.expires_at < Date.now()) {
          // Device code expired
          delete session.deviceCodes[hostname][device_code];
          return new Response(JSON.stringify({ error: 'expired_token' }), {
            status: 400,
            headers: { 'Content-Type': 'application/json' }
          });
        }
        
        if (deviceCodeData.client_id !== client_id) {
          return new Response(JSON.stringify({ error: 'invalid_client' }), {
            status: 400,
            headers: { 'Content-Type': 'application/json' }
          });
        }
        
        deviceData = deviceCodeData;
        sessionWithDevice = session;
        break;
      }
    }
    
    if (!deviceData || !sessionWithDevice) {
      return new Response(JSON.stringify({ error: 'invalid_grant' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    // Check if user has authorized this device code
    if (!sessionWithDevice.localAuth) {
      return new Response(JSON.stringify({ 
        error: 'authorization_pending',
        error_description: 'User has not yet authorized the device'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    // Generate tokens
    const access_token = `gw_access_${generateRandomString(32)}`;
    const refresh_token = `gw_refresh_${generateRandomString(32)}`;
    const expires_in = 3600;
    
    // Store tokens
    if (!sessionWithDevice.localOAuthTokens) {
      sessionWithDevice.localOAuthTokens = {};
    }
    
    sessionWithDevice.localOAuthTokens[hostname] = {
      access_token,
      refresh_token,
      expires_at: Date.now() + (expires_in * 1000),
      client_id: deviceData.client_id
    };
    
    // Clean up device code
    delete sessionWithDevice.deviceCodes[hostname][device_code];
    
    return new Response(JSON.stringify({
      access_token,
      refresh_token,
      token_type: 'Bearer',
      expires_in,
      scope: deviceData.scope
    }), {
      headers: { 
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store'
      }
    });
  }
  
  return new Response(JSON.stringify({ error: 'unsupported_grant_type' }), {
    status: 400,
    headers: { 'Content-Type': 'application/json' }
  });
}

export async function handleLocalOAuthRevoke(request: Request, hostRoute: MCPRouteInfo, env: Env): Promise<Response> {
  const formData = await request.formData();
  const token = formData.get('token') as string;
  const hostname = new URL(request.url).hostname;
  
  // Find and revoke token
  for (const session of sessions.values()) {
    const localToken = session.localOAuthTokens?.[hostname];
    if (localToken && (localToken.access_token === token || localToken.refresh_token === token)) {
      delete session.localOAuthTokens[hostname];
      break;
    }
  }
  
  return new Response('', { status: 200 });
}

export async function handleLocalOAuthDevice(request: Request, hostRoute: MCPRouteInfo, env: Env): Promise<Response> {
  const formData = await request.formData();
  const client_id = formData.get('client_id') as string;
  const scope = formData.get('scope') as string || 'mcp';
  
  if (!client_id) {
    return new Response(JSON.stringify({ error: 'invalid_request', error_description: 'client_id is required' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    });
  }
  
  const hostname = new URL(request.url).hostname;
  
  // Generate device code and user code
  const device_code = `device_${generateRandomString(32)}`;
  const user_code = generateUserCode(); // 6-digit code
  const expires_in = 1800; // 30 minutes
  const interval = 5; // Poll every 5 seconds
  
  // Create or get session for device codes
  let session: SessionData;
  const sessionId = getSessionId(request);
  if (sessionId) {
    session = await getSession(sessionId, env) || createDeviceSession();
  } else {
    session = createDeviceSession();
    const newSessionId = generateSessionId();
    sessions.set(newSessionId, session);
  }
  
  // Store device code
  if (!session.deviceCodes) {
    session.deviceCodes = {};
  }
  if (!session.deviceCodes[hostname]) {
    session.deviceCodes[hostname] = {};
  }
  
  session.deviceCodes[hostname][device_code] = {
    user_code,
    verification_uri: `https://${hostname}/oauth/device/verify`,
    expires_at: Date.now() + (expires_in * 1000),
    client_id,
    scope,
    interval
  };
  
  return new Response(JSON.stringify({
    device_code,
    user_code,
    verification_uri: `https://${hostname}/oauth/device/verify`,
    verification_uri_complete: `https://${hostname}/oauth/device/verify?user_code=${user_code}`,
    expires_in,
    interval
  }), {
    headers: { 
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*'
    }
  });
}

export async function handleLocalOAuthIntrospect(request: Request, hostRoute: MCPRouteInfo, env: Env): Promise<Response> {
  const formData = await request.formData();
  const token = formData.get('token') as string;
  const hostname = new URL(request.url).hostname;
  
  if (!token) {
    return new Response(JSON.stringify({ active: false }), {
      headers: { 'Content-Type': 'application/json' }
    });
  }
  
  // Find session with this token
  for (const session of sessions.values()) {
    const tokenData = session.localOAuthTokens?.[hostname];
    if (tokenData?.access_token === token) {
      const active = tokenData.expires_at > Date.now();
      return new Response(JSON.stringify({
        active,
        client_id: tokenData.client_id,
        exp: Math.floor(tokenData.expires_at / 1000),
        scope: 'mcp'
      }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }
  }
  
  return new Response(JSON.stringify({ active: false }), {
    headers: { 'Content-Type': 'application/json' }
  });
}

export function createDeviceSession(): SessionData {
  return {
    csrf: generateRandomString(32),
    localAuth: false,
    oauth: {},
    deviceCodes: {}
  };
}

export function generateUserCode(): string {
  // Generate 6-digit user code
  return Math.random().toString(10).slice(2, 8).padStart(6, '0');
}

export async function handleDeviceVerify(request: Request, hostRoute: MCPRouteInfo, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const user_code = url.searchParams.get('user_code') || '';
  
  const html = `<!doctype html><html><head><title>Device Authorization</title></head><body>
    <h1>Device Authorization</h1>
    <p>To complete device authorization, please enter the code displayed on your device:</p>
    <form method="POST" action="/oauth/device/verify">
      <label>Device Code: <input name="user_code" value="${user_code}" placeholder="123456" required></label><br><br>
      <button type="submit">Verify Device</button>
    </form>
    <p><a href="https://${getCurrentDomain(request)}/login">Sign in first</a> if not already authenticated.</p>
  </body></html>`;
  
  return new Response(html, {
    headers: { 'Content-Type': 'text/html' }
  });
}

// RFC 7591 Dynamic Client Registration
export async function handleClientRegistration(request: Request, hostRoute: MCPRouteInfo, env: Env): Promise<Response> {
  try {
    const registrationData = await request.json() as any;
    
    // Generate client credentials
    const client_id = generateRandomString(16);
    const client_secret = generateRandomString(32);
    const issued_at = Math.floor(Date.now() / 1000);
    
    // Basic validation of required fields
    const redirect_uris = registrationData.redirect_uris;
    if (!redirect_uris || !Array.isArray(redirect_uris) || redirect_uris.length === 0) {
      return new Response(JSON.stringify({
        error: 'invalid_redirect_uri',
        error_description: 'redirect_uris is required and must be a non-empty array'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    // Create client registration response (RFC 7591)
    const response = {
      client_id,
      client_secret,
      client_id_issued_at: issued_at,
      client_secret_expires_at: 0, // Non-expiring
      redirect_uris: redirect_uris,
      client_name: registrationData.client_name || 'MCP Client',
      client_uri: registrationData.client_uri,
      logo_uri: registrationData.logo_uri,
      scope: registrationData.scope || 'mcp',
      grant_types: registrationData.grant_types || ['authorization_code', 'refresh_token'],
      response_types: registrationData.response_types || ['code'],
      token_endpoint_auth_method: registrationData.token_endpoint_auth_method || 'client_secret_post'
    };
    
    return new Response(JSON.stringify(response), {
      status: 201,
      headers: { 
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store',
        'Pragma': 'no-cache'
      }
    });
    
  } catch (error) {
    return new Response(JSON.stringify({
      error: 'invalid_request',
      error_description: 'Invalid JSON in request body'
    }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

export async function handleDeviceVerifyPost(request: Request, hostRoute: MCPRouteInfo, env: Env): Promise<Response> {
  const formData = await request.formData();
  const user_code = formData.get('user_code') as string;
  const hostname = new URL(request.url).hostname;
  
  if (!user_code) {
    return new Response('User code is required', { status: 400 });
  }
  
  // Check if user is authenticated
  const sessionId = getSessionId(request);
  const session = sessionId ? await getSession(sessionId, env) : null;
  
  if (!session || !session.localAuth) {
    // Redirect to login with return URL
    const returnUrl = `/oauth/device/verify?user_code=${encodeURIComponent(user_code)}`;
    return Response.redirect(`https://${hostname}/login?return_to=${encodeURIComponent(returnUrl)}`, 302);
  }
  
  // Find device code with this user code
  let deviceFound = false;
  for (const [sessionKey, deviceSession] of sessions.entries()) {
    const devices = deviceSession.deviceCodes?.[hostname];
    if (devices) {
      for (const [device_code, deviceData] of Object.entries(devices)) {
        if (deviceData.user_code === user_code) {
          if (deviceData.expires_at < Date.now()) {
            delete deviceSession.deviceCodes[hostname][device_code];
            return new Response('Device code has expired. Please try again.', { status: 400 });
          }
          
          // Authorize this device code
          deviceSession.localAuth = true;
          deviceSession.csrf = session.csrf; // Copy authenticated session data
          deviceFound = true;
          break;
        }
      }
    }
  }
  
  if (!deviceFound) {
    return new Response('Invalid device code. Please check the code and try again.', { status: 400 });
  }
  
  return new Response(`<!doctype html><html><head><title>Device Authorized</title></head><body>
    <h1>Device Authorized Successfully</h1>
    <p>Your device has been authorized. You can now return to your MCP client.</p>
    <p>The authorization will complete automatically.</p>
  </body></html>`, {
    headers: { 'Content-Type': 'text/html' }
  });
}

// Initiate upstream OAuth flow
export async function initiateUpstreamOAuth(request: Request, hostRoute: MCPRouteInfo, session: SessionData, env: Env): Promise<Response> {
  // Discover upstream OAuth endpoints
  const upstreamOAuth = await discoverUpstreamOAuth(hostRoute.serverDomain);
  
  if (!upstreamOAuth) {
    return new Response('Upstream server does not support OAuth', { status: 400 });
  }
  
  // Check if we have a registered client for this server
  let clientCredentials = registeredClients.get(hostRoute.serverDomain);
  const currentDomain = getCurrentDomain(request);
  
  // Use the encoded domain as redirect URI - test if dynamic registration resolved allowlist issue
  const redirectUri = `https://${currentDomain}/oauth/callback`;
  
  console.log(`Checking for registered client for ${hostRoute.serverDomain}:`, clientCredentials ? 'Found existing client' : 'No existing client');
  console.log('All registered clients:', Array.from(registeredClients.entries()));
  console.log(`Using encoded domain redirect URI: ${redirectUri}`);
  
  if (!clientCredentials) {
    // Register client if server supports dynamic registration
    if (upstreamOAuth.registration_endpoint) {
      try {
        clientCredentials = await registerUpstreamClient(hostRoute.serverDomain, redirectUri, upstreamOAuth);
      } catch (error) {
        console.error('Failed to register client:', error);
        return new Response('Client registration failed: ' + (error as Error).message, { status: 400 });
      }
    } else {
      // Fall back to default client ID if no registration endpoint
      clientCredentials = { 
        client_id: 'mcp-gateway',
        registered_at: Date.now()
      };
      // Store the fallback client for consistency
      registeredClients.set(hostRoute.serverDomain, clientCredentials);
    }
  }
  
  // Generate PKCE parameters for gateway → upstream flow
  const state = generateRandomString(32);
  const verifier = generateRandomString(32);
  const challenge = await sha256Base64Url(verifier);
  
  // Store upstream OAuth state and client credentials in session
  if (!session.oauth) {
    session.oauth = {};
  }
  if (!session.oauth[hostRoute.serverDomain]) {
    session.oauth[hostRoute.serverDomain] = {};
  }
  
  session.oauth[hostRoute.serverDomain].state = state;
  session.oauth[hostRoute.serverDomain].pkceVerifier = verifier;
  
  // Build upstream authorization URL
  const authUrl = new URL(upstreamOAuth.authorization_endpoint);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('client_id', clientCredentials.client_id);
  authUrl.searchParams.set('redirect_uri', redirectUri);
  authUrl.searchParams.set('state', `${hostRoute.serverDomain}:${state}`);
  authUrl.searchParams.set('code_challenge', challenge);
  authUrl.searchParams.set('code_challenge_method', 'S256');
  
  // Align scopes with what downstream clients request
  // If upstream supports the exact scopes, use them; otherwise map appropriately
  const requestedScopes = ['mcp', 'read', 'write'];
  const supportedScopes = upstreamOAuth.scopes_supported || [];
  let scopesToRequest = requestedScopes.filter(s => supportedScopes.includes(s));
  
  // If no matching scopes, fall back to all supported scopes or 'openid'
  if (scopesToRequest.length === 0) {
    scopesToRequest = supportedScopes.length > 0 ? supportedScopes : ['openid'];
  }
  
  const scope = scopesToRequest.join(' ');
  authUrl.searchParams.set('scope', scope);
  
  // Add resource parameter if we're tracking one
  const pendingResource = session.pendingResource || `https://${hostRoute.serverDomain}`;
  if (pendingResource) {
    authUrl.searchParams.set('resource', pendingResource);
    session.pendingResource = pendingResource; // Store for token exchange
  }
  
  // Enhanced logging for upstream OAuth
  log({
    kind: 'upstream_oauth_authorize',
    server: hostRoute.serverDomain,
    client_id: clientCredentials.client_id,
    redirect_uri: redirectUri,
    scopes_requested: scopesToRequest,
    resource: pendingResource || null,
    has_pkce: true,
    authorization_url: authUrl.toString()
  });
  
  logSummary('/oauth/start', 'GET', 302, 
    `upstream=${hostRoute.serverDomain} scopes=${scope} resource=${pendingResource ? 'yes' : 'no'}`);
  
  return Response.redirect(authUrl.toString(), 302);
}

// Register client with upstream OAuth server (RFC 7591)
export async function registerUpstreamClient(
  serverDomain: string, 
  redirectUri: string,
  discovery: any
): Promise<{ client_id: string; client_secret?: string; registered_at: number }> {
  const registrationData = {
    redirect_uris: [redirectUri],
    client_name: `MCP Gateway for ${new URL(redirectUri).hostname}`,
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    token_endpoint_auth_method: 'client_secret_post',
    scope: discovery.scopes_supported?.join(' ') || 'openid'
  };
  
  console.log(`Registering client for ${serverDomain} with redirect URI: ${redirectUri}`);
  console.log('Registration data:', JSON.stringify(registrationData, null, 2));
  console.log('Registration endpoint:', discovery.registration_endpoint);
  
  const response = await fetch(discovery.registration_endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
      'User-Agent': 'MCP-OAuth-Gateway/1.0'
    },
    body: JSON.stringify(registrationData)
  });
  
  if (!response.ok) {
    const errorText = await response.text();
    console.error(`Client registration failed for ${serverDomain}:`, response.status, errorText);
    throw new Error(`Client registration failed: ${response.status} ${errorText}`);
  }
  
  const result = await response.json() as any;
  
  // Store registered client
  registeredClients.set(serverDomain, {
    client_id: result.client_id,
    client_secret: result.client_secret,
    registered_at: Date.now()
  });
  
  console.log(`Successfully registered client for ${serverDomain}:`, result.client_id);
  
  return {
    client_id: result.client_id,
    client_secret: result.client_secret,
    registered_at: Date.now()
  };
}

// Dynamic upstream OAuth discovery
export async function discoverUpstreamOAuth(domain: string): Promise<any | null> {
  try {
    const discoveryUrl = `https://${domain}/.well-known/oauth-authorization-server`;
    const response = await fetch(discoveryUrl, {
      method: 'GET',
      headers: {
        'Accept': 'application/json',
        'User-Agent': 'MCP-OAuth-Gateway/1.0'
      }
    });
    
    if (response.ok) {
      const discovery = await response.json() as any;
      // Validate required OAuth endpoints
      if (discovery.authorization_endpoint && discovery.token_endpoint) {
        return discovery;
      }
    }
  } catch (error) {
    // Discovery failed, server likely doesn't support OAuth
    console.log(`OAuth discovery failed for ${domain}:`, error);
  }
  
  return null;
}

// Upstream OAuth handlers
export async function handleOAuthStart(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const serverDomain = url.searchParams.get('server');
  
  console.log(`\n╔══ UPSTREAM OAUTH START (Gateway → ${serverDomain}) ══`);
  
  if (!serverDomain) {
    console.log(`║ Error: Missing server parameter`);
    console.log(`╚══════════════════════════════════════════════════════`);
    return new Response('Missing server parameter', { status: 400 });
  }
  
  // Try to get MCP server config, or discover dynamically
  let serverConfig: MCPServerConfig | null = null;
  
  try {
    const mcpServers: MCPServerConfig[] = JSON.parse(env.MCP_SERVERS || '[]');
    serverConfig = mcpServers.find(s => s.domain === serverDomain) || null;
  } catch (e) {
    console.error('Failed to parse MCP_SERVERS:', e);
  }
  
  // If no pre-configured server, try dynamic discovery
  if (!serverConfig) {
    const upstreamOAuth = await discoverUpstreamOAuth(serverDomain);
    if (!upstreamOAuth) {
      return new Response('Server does not support OAuth or is not configured', { status: 400 });
    }
    
    // Create dynamic server config
    serverConfig = {
      domain: serverDomain,
      name: `Dynamic: ${serverDomain}`,
      authzEndpoint: upstreamOAuth.authorization_endpoint,
      tokenEndpoint: upstreamOAuth.token_endpoint,
      clientId: 'mcp-gateway', // Default client ID
      scopes: upstreamOAuth.scopes_supported?.[0] || 'openid'
    };
  }
  
  // Get or create session
  const sessionId = getSessionId(request);
  if (!sessionId) {
    return new Response('Session required', { status: 401 });
  }
  
  const session = await getSession(sessionId, env);
  if (!session || !session.localAuth) {
    return new Response('Authentication required', { status: 401 });
  }
  
  // Generate OAuth URL
  const state = generateRandomString(16);
  const verifier = generateRandomString(32);
  const challenge = await sha256Base64Url(verifier);
  
  // Store PKCE verifier and state in session
  if (!session.oauth) {
    session.oauth = {};
  }
  if (!session.oauth[serverDomain]) {
    session.oauth[serverDomain] = {};
  }
  
  session.oauth[serverDomain].state = state;
  session.oauth[serverDomain].pkceVerifier = verifier;
  
  const authUrl = new URL(serverConfig.authzEndpoint);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('client_id', serverConfig.clientId);
  authUrl.searchParams.set('redirect_uri', `https://${getCurrentDomain(request)}/oauth/callback`);
  authUrl.searchParams.set('scope', serverConfig.scopes);
  authUrl.searchParams.set('state', `${serverDomain}:${state}`);
  authUrl.searchParams.set('code_challenge', challenge);
  authUrl.searchParams.set('code_challenge_method', 'S256');
  
  // Add resource parameter for pre-configured servers
  const resource = `https://${serverDomain}`;
  authUrl.searchParams.set('resource', resource);
  session.pendingResource = resource;
  
  // Log upstream OAuth for pre-configured server
  log({
    kind: 'upstream_oauth_authorize',
    server: serverDomain,
    client_id: serverConfig.clientId,
    redirect_uri: `https://${getCurrentDomain(request)}/oauth/callback`,
    scopes_requested: serverConfig.scopes.split(' '),
    resource: resource,
    has_pkce: true,
    authorization_url: authUrl.toString()
  });
  
  logSummary('/oauth/start', 'GET', 302, 
    `upstream=${serverDomain} scopes=${serverConfig.scopes} resource=yes`);
  
  return Response.redirect(authUrl.toString(), 302);
}

export async function handleOAuthCallback(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state');
  const error = url.searchParams.get('error');
  
  if (error) {
    return new Response(`OAuth error: ${error}`, { status: 400 });
  }
  
  if (!code || !state) {
    return new Response('Missing required callback parameters', { status: 400 });
  }
  
  // Parse state to get server domain
  const [serverDomain, expectedState] = state.split(':', 2);
  if (!serverDomain || !expectedState) {
    return new Response('Invalid state parameter', { status: 400 });
  }
  
  // Get session
  const sessionId = getSessionId(request);
  if (!sessionId) {
    return new Response('Session required', { status: 401 });
  }
  
  const session = await getSession(sessionId, env);
  if (!session || !session.localAuth) {
    return new Response('Authentication required', { status: 401 });
  }
  
  // Verify state and get PKCE verifier
  const oauthData = session.oauth?.[serverDomain];
  if (!oauthData || oauthData.state !== expectedState) {
    return new Response('Invalid state - possible CSRF attack', { status: 400 });
  }
  
  if (!oauthData.pkceVerifier) {
    return new Response('PKCE verifier not found', { status: 400 });
  }
  
  // Get client credentials for this server
  const clientCredentials = registeredClients.get(serverDomain);
  if (!clientCredentials) {
    return new Response('No registered client found for server', { status: 400 });
  }
  
  // Discover upstream OAuth endpoints to get token endpoint
  const upstreamOAuth = await discoverUpstreamOAuth(serverDomain);
  if (!upstreamOAuth || !upstreamOAuth.token_endpoint) {
    return new Response('Server does not support OAuth or token endpoint not found', { status: 400 });
  }
  
  // Exchange code for tokens
  const tokenRequestBody = new URLSearchParams();
  tokenRequestBody.append('grant_type', 'authorization_code');
  tokenRequestBody.append('code', code);
  tokenRequestBody.append('redirect_uri', `https://${getCurrentDomain(request)}/oauth/callback`);
  tokenRequestBody.append('client_id', clientCredentials.client_id);
  tokenRequestBody.append('code_verifier', oauthData.pkceVerifier);
  
  // Add resource parameter if we stored one
  if (session.pendingResource) {
    tokenRequestBody.append('resource', session.pendingResource);
  }
  
  if (clientCredentials.client_secret) {
    tokenRequestBody.append('client_secret', clientCredentials.client_secret);
  }
  
  // Log token exchange request
  log({
    kind: 'upstream_oauth_token_request',
    server: serverDomain,
    grant_type: 'authorization_code',
    client_id: clientCredentials.client_id,
    has_code_verifier: true,
    has_resource: !!session.pendingResource,
    resource: session.pendingResource || null
  });
  
  try {
    const tokenResponse = await fetch(upstreamOAuth.token_endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json',
        'Cache-Control': 'no-cache'
      },
      body: tokenRequestBody.toString()
    });
    
    if (!tokenResponse.ok) {
      const errorText = await tokenResponse.text();
      log({
        kind: 'upstream_oauth_token_error',
        server: serverDomain,
        status: tokenResponse.status,
        error: errorText
      });
      console.error('Token exchange failed:', errorText);
      return new Response(`Token exchange failed: ${tokenResponse.status}`, { status: 400 });
    }
    
    const tokenData = await tokenResponse.json() as any;
    
    // Parse JWT to extract audience if it's a JWT
    let audience = null;
    let scopes = tokenData.scope || null;
    if (tokenData.access_token && tokenData.access_token.includes('.')) {
      try {
        const [, payload] = tokenData.access_token.split('.');
        const decoded = JSON.parse(atob(payload));
        audience = decoded.aud || null;
        scopes = decoded.scope || scopes;
      } catch (e) {
        // Not a JWT or malformed, ignore
      }
    }
    
    // Check for refresh token rotation
    const refreshTokenRotated = tokenData.refresh_token && 
                              tokenData.refresh_token !== oauthData.tokens?.refresh_token;
    
    // Log successful token response
    log({
      kind: 'upstream_oauth_token_response',
      server: serverDomain,
      access_token_snip: tokenData.access_token.slice(0, 8),
      scopes_granted: scopes ? scopes.split(' ') : null,
      audience: audience,
      has_refresh_token: !!tokenData.refresh_token,
      refresh_token_rotated: refreshTokenRotated,
      expires_in: tokenData.expires_in || 3600
    });
    
    // Store tokens
    oauthData.tokens = {
      access_token: tokenData.access_token,
      refresh_token: tokenData.refresh_token || oauthData.tokens?.refresh_token, // Keep old if not rotated
      expires_in: tokenData.expires_in || 3600
    };
    oauthData.expiresAt = Date.now() + (tokenData.expires_in || 3600) * 1000;
    
    logSummary('/oauth/callback', 'GET', 200, 
      `upstream=${serverDomain} token_obtained scopes=${scopes || 'unknown'} aud=${audience || 'none'}`);
    
    // Clear PKCE data
    delete oauthData.state;
    delete oauthData.pkceVerifier;
    
    // Check if we have a pending client authorization to complete
    if (session.pendingClientAuth) {
      // Resume the client authorization flow
      const pendingAuth = session.pendingClientAuth;
      
      // Generate authorization code for the client
      const clientCode = generateRandomString(32);
      
      const codeData = {
        client_id: pendingAuth.client_id,
        redirect_uri: pendingAuth.redirect_uri,
        scope: pendingAuth.scope,
        code_challenge: pendingAuth.code_challenge,
        code_challenge_method: pendingAuth.code_challenge_method,
        resource: pendingAuth.resource,
        domain: getCurrentDomain(request), // Should be the encoded hostname
        sessionId: sessionId!,
        expires_at: Date.now() + 600000, // 10 minutes
        req_id_from_probe: requestCorrelation.get(getCurrentDomain(request)) || undefined // Correlate with original SSE probe
      };
      
      // Store code in KV with TTL for automatic expiration
      await env.OAUTH_CODES.put(
        clientCode,
        JSON.stringify(codeData),
        { expirationTtl: 600 } // 10 minutes TTL
      );
      console.log(`Stored authorization code in KV: ${clientCode.substring(0, 8)}...`);
      
      // Build redirect URL back to client
      const clientRedirectUrl = new URL(pendingAuth.redirect_uri);
      clientRedirectUrl.searchParams.set('code', clientCode);
      if (pendingAuth.state) {
        clientRedirectUrl.searchParams.set('state', pendingAuth.state);
      }
      
      console.log(`Redirecting back to Claude with code: ${clientCode}`);
      console.log(`Redirect URL: ${clientRedirectUrl.toString()}`);
      console.log(`Pending auth was: ${JSON.stringify(pendingAuth, null, 2)}`);
      
      // Clear pending authorization
      delete session.pendingClientAuth;
      
      return Response.redirect(clientRedirectUrl.toString(), 302);
    }
    
    // No pending client auth, redirect to dashboard
    return Response.redirect(`https://${getCurrentDomain(request)}/`, 302);
    
  } catch (error) {
    console.error('Token exchange error:', error);
    return new Response('Token exchange failed', { status: 500 });
  }
}

// Helper function to check if a token is expired or about to expire
export function isTokenExpired(expiresAt: number | undefined, bufferSeconds: number = 300): boolean {
  if (!expiresAt) return true; // If no expiration time, consider it expired
  return Date.now() > (expiresAt - bufferSeconds * 1000); // Check if expired or expires within buffer
}

export async function refreshUpstreamToken(serverDomain: string, serverData: any, env: Env): Promise<boolean> {
  if (!serverData.tokens?.refresh_token) {
    log({
      kind: 'upstream_refresh_skip',
      server: serverDomain,
      reason: 'no_refresh_token'
    });
    return false;
  }
  
  const oldRefreshToken = serverData.tokens.refresh_token;
  
  // Get server config
  let mcpServers: MCPServerConfig[] = [];
  try {
    mcpServers = JSON.parse(env.MCP_SERVERS || '[]');
  } catch (e) {
    console.error('Failed to parse MCP_SERVERS:', e);
    return false;
  }
  
  const serverConfig = mcpServers.find(s => s.domain === serverDomain);
  if (!serverConfig) {
    // Try dynamic discovery for token endpoint
    const upstreamOAuth = await discoverUpstreamOAuth(serverDomain);
    if (!upstreamOAuth?.token_endpoint) {
      log({
        kind: 'upstream_refresh_error',
        server: serverDomain,
        reason: 'config_not_found'
      });
      return false;
    }
    
    // Use discovered endpoint with registered client
    const clientCredentials = registeredClients.get(serverDomain);
    if (!clientCredentials) {
      log({
        kind: 'upstream_refresh_error',
        server: serverDomain,
        reason: 'no_registered_client'
      });
      return false;
    }
    
    const refreshRequestBody = new URLSearchParams();
    refreshRequestBody.append('grant_type', 'refresh_token');
    refreshRequestBody.append('refresh_token', oldRefreshToken);
    refreshRequestBody.append('client_id', clientCredentials.client_id);
    
    if (clientCredentials.client_secret) {
      refreshRequestBody.append('client_secret', clientCredentials.client_secret);
    }
    
    log({
      kind: 'upstream_refresh_request',
      server: serverDomain,
      client_id: clientCredentials.client_id,
      used_refresh_token_snip: oldRefreshToken.slice(0, 8)
    });
    
    try {
      const refreshResponse = await fetch(upstreamOAuth.token_endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Accept': 'application/json',
          'Cache-Control': 'no-cache'
        },
        body: refreshRequestBody.toString()
      });
      
      if (!refreshResponse.ok) {
        const errorText = await refreshResponse.text();
        log({
          kind: 'upstream_refresh_error',
          server: serverDomain,
          status: refreshResponse.status,
          error: errorText
        });
        return false;
      }
      
      const tokenData = await refreshResponse.json() as any;
      
      // Check for refresh token rotation
      const refreshTokenRotated = tokenData.refresh_token && 
                                tokenData.refresh_token !== oldRefreshToken;
      
      log({
        kind: 'upstream_refresh_response',
        server: serverDomain,
        new_access_token_snip: tokenData.access_token.slice(0, 8),
        refresh_token_rotated: refreshTokenRotated,
        expires_in: tokenData.expires_in || 3600
      });
      
      // Update tokens
      serverData.tokens.access_token = tokenData.access_token;
      if (tokenData.refresh_token) {
        serverData.tokens.refresh_token = tokenData.refresh_token;
      }
      serverData.tokens.expires_in = tokenData.expires_in || 3600;
      serverData.expiresAt = Date.now() + (tokenData.expires_in || 3600) * 1000;
      
      logSummary('refresh_token', 'POST', 200, 
        `upstream=${serverDomain} rotated=${refreshTokenRotated}`);
      
      return true;
    } catch (error) {
      log({
        kind: 'upstream_refresh_error',
        server: serverDomain,
        error: error.message
      });
      return false;
    }
  }
  
  // Use configured server
  const refreshRequestBody = new URLSearchParams();
  refreshRequestBody.append('grant_type', 'refresh_token');
  refreshRequestBody.append('refresh_token', oldRefreshToken);
  refreshRequestBody.append('client_id', serverConfig.clientId);
  
  if (serverConfig.clientSecret) {
    refreshRequestBody.append('client_secret', serverConfig.clientSecret);
  }
  
  log({
    kind: 'upstream_refresh_request',
    server: serverDomain,
    client_id: serverConfig.clientId,
    used_refresh_token_snip: oldRefreshToken.slice(0, 8)
  });
  
  try {
    const refreshResponse = await fetch(serverConfig.tokenEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json',
        'Cache-Control': 'no-cache'
      },
      body: refreshRequestBody.toString()
    });
    
    if (!refreshResponse.ok) {
      const errorText = await refreshResponse.text();
      log({
        kind: 'upstream_refresh_error',
        server: serverDomain,
        status: refreshResponse.status,
        error: errorText
      });
      return false;
    }
    
    const tokenData = await refreshResponse.json() as any;
    
    // Check for refresh token rotation
    const refreshTokenRotated = tokenData.refresh_token && 
                              tokenData.refresh_token !== oldRefreshToken;
    
    log({
      kind: 'upstream_refresh_response',
      server: serverDomain,
      new_access_token_snip: tokenData.access_token.slice(0, 8),
      refresh_token_rotated: refreshTokenRotated,
      expires_in: tokenData.expires_in || 3600
    });
    
    // Update tokens
    serverData.tokens.access_token = tokenData.access_token;
    if (tokenData.refresh_token) {
      serverData.tokens.refresh_token = tokenData.refresh_token;
    }
    serverData.tokens.expires_in = tokenData.expires_in || 3600;
    serverData.expiresAt = Date.now() + (tokenData.expires_in || 3600) * 1000;
    
    logSummary('refresh_token', 'POST', 200, 
      `upstream=${serverDomain} rotated=${refreshTokenRotated}`);
    
    return true;
    
  } catch (error: any) {
    log({
      kind: 'upstream_refresh_error',
      server: serverDomain,
      error: error.message
    });
    return false;
  }
}

export async function handleWebSocketUpgrade(request: Request, hostRoute: MCPRouteInfo, upstreamHeaders: Record<string, string>): Promise<Response> {
  // Create upstream WebSocket URL
  const upstreamUrl = new URL(request.url.replace(request.url.split('/')[2], hostRoute.upstreamBase.host));
  upstreamUrl.protocol = upstreamUrl.protocol === 'https:' ? 'wss:' : 'ws:';
  
  // Add authorization as query parameter since Cloudflare Workers WebSocket doesn't support custom headers
  const bearerToken = upstreamHeaders['Authorization']?.replace('Bearer ', '');
  if (bearerToken) {
    upstreamUrl.searchParams.set('access_token', bearerToken);
  }
  
  // Create WebSocket pair
  const webSocketPair = new WebSocketPair();
  const [client, server] = Object.values(webSocketPair);
  
  // Accept the client connection
  server.accept();
  
  // Connect to upstream WebSocket
  try {
    const upstreamWs = new WebSocket(upstreamUrl.toString());
    
    // Forward messages from client to upstream
    server.addEventListener('message', event => {
      if (upstreamWs.readyState === WebSocket.OPEN) {
        upstreamWs.send(event.data);
      }
    });
    
    // Forward messages from upstream to client
    upstreamWs.addEventListener('message', event => {
      if (server.readyState === WebSocket.OPEN) {
        server.send(event.data);
      }
    });
    
    // Handle connection events
    server.addEventListener('close', () => {
      upstreamWs.close();
    });
    
    upstreamWs.addEventListener('close', () => {
      server.close();
    });
    
    server.addEventListener('error', (event) => {
      console.error('Client WebSocket error:', event);
      upstreamWs.close();
    });
    
    upstreamWs.addEventListener('error', (event) => {
      console.error('Upstream WebSocket error:', event);
      server.close();
    });
    
    return new Response(null, {
      status: 101,
      webSocket: client,
    });
    
  } catch (error) {
    console.error('WebSocket connection failed:', error);
    server.close();
    return new Response('WebSocket connection failed', { status: 500 });
  }
}

// Encode handler
export async function handleEncode(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const domain = url.searchParams.get('domain');
  
  if (!domain) {
    return new Response('Missing domain parameter', { status: 400 });
  }
  
  const encodedHostname = generateEncodedHostname(domain, env.DOMAIN_ROOT);
  const encodedUrl = `https://${encodedHostname}/`;
  
  const html = `<!doctype html><html><head><title>Encoded MCP URL</title></head><body>
    <h1>MCP URL Generator</h1>
    <h2>Results for: ${domain}</h2>
    <p><strong>Encoded URL:</strong><br><code>${encodedUrl}</code></p>
    <p>Format: <code>{base32(domain)}-enc.${env.DOMAIN_ROOT}</code></p>
    <p>Use this URL in Claude.ai or ChatGPT to connect to the MCP server.</p>
    <p><a href="/">← Back to Dashboard</a></p>
  </body></html>`;
  
  return new Response(html, {
    headers: { 'Content-Type': 'text/html' }
  });
}

// Utility functions
export function generateEncodedHostname(domain: string, domainRoot: string): string {
  const encoded = base32Encode(domain);
  return `${encoded}-enc.${domainRoot}`;
}

export function getCurrentDomain(request: Request): string {
  return new URL(request.url).hostname;
}

export function getSessionId(request: Request): string | null {
  const cookieHeader = request.headers.get('Cookie');
  if (!cookieHeader) return null;
  
  const cookies: Record<string, string> = {};
  cookieHeader.split(';').forEach(c => {
    const [key, ...value] = c.trim().split('=');
    if (key && value.length > 0) {
      cookies[key] = value.join('=');
    }
  });
  
  return cookies.session || null;
}

export async function getSession(sessionId: string, env: Env): Promise<SessionData | null> {
  return sessions.get(sessionId) || null;
}

export function generateSessionId(): string {
  return generateRandomString(32);
}

export function generateRandomString(length: number): string {
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

export async function sha256Base64Url(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return btoa(String.fromCharCode(...new Uint8Array(hash)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

// Export the worker
export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    
    try {
      // Parse hostname to determine if this is an MCP route
      const hostRoute = parseHostEncodedUpstream(url.hostname, env.DOMAIN_ROOT);
      
      if (hostRoute) {
        // Handle CORS preflight requests
        if (request.method === 'OPTIONS') {
          return new Response(null, {
            headers: {
              'Access-Control-Allow-Origin': '*',
              'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
              'Access-Control-Allow-Headers': 'Content-Type, Authorization, MCP-Protocol-Version',
              'Access-Control-Max-Age': '86400'
            }
          });
        }
        
        // Handle all .well-known paths liberally
        if (url.pathname.startsWith('/.well-known/oauth-authorization-server')) {
          // Return OAuth discovery for any path under this prefix
          return handleOAuthDiscovery(request, hostRoute, env);
        }
        
        if (url.pathname.startsWith('/.well-known/oauth-protected-resource')) {
          // Return protected resource metadata for any path under this prefix
          return handleProtectedResourceMetadata(request, hostRoute, env);
        }
        
        // Add login handler for encoded domains
        if (url.pathname === '/login') {
          if (request.method === 'GET') return handleLoginPage(request);
          if (request.method === 'POST') return handleLogin(request, env);
        }
        
        if (url.pathname.startsWith('/oauth/')) {
          return handleLocalOAuth(request, hostRoute, env);
        }
        
        // This is an MCP server request
        return handleMCPRequest(request, hostRoute, env);
      }
      
      // Landing domain routes (handle custom domain, mcp.domain, and workers.dev)
      const hostname = url.hostname.toLowerCase();
      const domainRoot = env.DOMAIN_ROOT.toLowerCase();
      const isLandingDomain = hostname === domainRoot ||
                             hostname === `mcp.${domainRoot}` ||
                             (hostname.startsWith('mcp.') && hostname.includes('.workers.dev'));
      
      if (isLandingDomain) {
        if (url.pathname === '/' || url.pathname === '') {
          return handleDashboard(request, env);
        }
        
        if (url.pathname === '/login') {
          if (request.method === 'GET') return handleLoginPage(request);
          if (request.method === 'POST') return handleLogin(request, env);
        }
        
        if (url.pathname === '/encode') {
          return handleEncode(request, env);
        }
        
        if (url.pathname === '/oauth/start') {
          return handleOAuthStart(request, env);
        }
        
        if (url.pathname === '/oauth/callback') {
          return handleOAuthCallback(request, env);
        }
      }
      
      return new Response('Not found', { status: 404 });
    } catch (error) {
      console.error('Worker error:', error);
      return new Response('Internal server error', { status: 500 });
    }
  }
};
