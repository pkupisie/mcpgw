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
        
        // Check if this is a local OAuth request
        if (url.pathname === '/.well-known/oauth-authorization-server') {
          return handleOAuthDiscovery(request, hostRoute, env);
        }
        
        if (url.pathname === '/.well-known/oauth-authorization-server/sse') {
          return handleOAuthDiscovery(request, hostRoute, env);
        }
        
        if (url.pathname === '/.well-known/oauth-protected-resource') {
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
async function handleMCPRequest(request: Request, hostRoute: MCPRouteInfo, env: Env): Promise<Response> {
  const hostname = new URL(request.url).hostname;
  
  // Check if this is an MCP client trying to connect
  const mcpProtocolVersion = request.headers.get('mcp-protocol-version');
  const userAgent = request.headers.get('user-agent');
  const authHeader = request.headers.get('Authorization');
  
  // If it's an MCP client without auth, check if it's accessing public endpoints
  if (mcpProtocolVersion && (!authHeader || !authHeader.startsWith('Bearer '))) {
    console.log('MCP client detected without OAuth');
    console.log(`MCP Protocol: ${mcpProtocolVersion}, Auth header: ${authHeader || 'none'}, User-Agent: ${userAgent}`);
    
    const url = new URL(request.url);
    
    // Allow unauthenticated access to OAuth discovery and flow endpoints
    if (url.pathname.startsWith('/.well-known/') || url.pathname.startsWith('/oauth/')) {
      console.log(`Allowing unauthenticated access to public endpoint: ${url.pathname}`);
      // Continue to normal handling - these should be handled above this point
    } else {
      // Require authentication for actual MCP data endpoints
      console.log(`Requiring authentication for MCP data endpoint: ${url.pathname}`);
      return new Response(JSON.stringify({ 
        error: 'authentication_required',
        error_description: 'OAuth authentication is required for MCP data access',
        authUrl: `https://${getCurrentDomain(request)}/oauth/start?server=${encodeURIComponent(hostRoute.serverDomain)}`
      }), { 
        status: 401,
        headers: { 
          'Content-Type': 'application/json',
          'WWW-Authenticate': 'Bearer realm="MCP Gateway"'
        }
      });
    }
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
      console.log(`Token expired or expiring soon for ${hostRoute.serverDomain}, attempting refresh...`);
      const refreshed = await refreshUpstreamToken(hostRoute.serverDomain, serverData, env);
      if (!refreshed) {
        console.error(`Failed to refresh token for ${hostRoute.serverDomain}`);
        // Continue with expired token, will get 401 and retry
      }
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
  
  // Forward request
  console.log(`Forwarding MCP request to ${upstreamUrl.toString()}`);
  console.log(`Auth header: ${upstreamHeaders['Authorization'] ? 'Bearer token present' : 'No auth'}`);
  console.log(`Request method: ${request.method}`);
  
  const response = await fetch(upstreamRequest);
  console.log(`Upstream response status: ${response.status}`);
  
  // Handle token refresh on 401
  if (response.status === 401 && serverData.tokens.refresh_token) {
    const refreshed = await refreshUpstreamToken(hostRoute.serverDomain, serverData, env);
    if (refreshed) {
      // Retry with new token
      upstreamHeaders['Authorization'] = `Bearer ${serverData.tokens.access_token}`;
      const retryRequest = new Request(upstreamUrl.toString(), {
        method: request.method,
        headers: upstreamHeaders,
        body: request.body,
      });
      return await fetch(retryRequest);
    }
  }
  
  return response;
}

// Dashboard
async function handleDashboard(request: Request, env: Env): Promise<Response> {
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
function handleLoginPage(request: Request): Response {
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

async function handleLogin(request: Request, env: Env): Promise<Response> {
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
async function handleOAuthDiscovery(request: Request, hostRoute: MCPRouteInfo, env: Env): Promise<Response> {
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
async function handleProtectedResourceMetadata(request: Request, hostRoute: MCPRouteInfo, env: Env): Promise<Response> {
  const hostname = new URL(request.url).hostname;
  
  const metadata = {
    resource: `https://${hostname}`,
    authorization_servers: [`https://${hostname}/.well-known/oauth-authorization-server`],
    scopes_supported: ['mcp', 'read', 'write'],
    bearer_methods_supported: ['header', 'query'],
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

async function handleLocalOAuth(request: Request, hostRoute: MCPRouteInfo, env: Env): Promise<Response> {
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

async function handleLocalOAuthAuthorize(request: Request, hostRoute: MCPRouteInfo, env: Env): Promise<Response> {
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

async function handleLocalOAuthAuthorizePost(request: Request, hostRoute: MCPRouteInfo, env: Env): Promise<Response> {
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
    expires_at: Date.now() + 600000 // 10 minutes
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

async function handleLocalOAuthToken(request: Request, hostRoute: MCPRouteInfo, env: Env): Promise<Response> {
  const formData = await request.formData();
  const grant_type = formData.get('grant_type');
  
  console.log(`OAuth token request - grant_type: ${grant_type}`);
  
  if (grant_type === 'authorization_code') {
    const code = formData.get('code') as string;
    const client_id = formData.get('client_id') as string;
    const redirect_uri = formData.get('redirect_uri') as string;
    const code_verifier = formData.get('code_verifier') as string;
    
    console.log(`Token request params - code: ${code?.substring(0, 8)}..., client_id: ${client_id}, redirect_uri: ${redirect_uri}`);
    
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
    
    // Include resource parameter in response if provided (RFC 8707)
    if (codeData.resource) {
      tokenResponse.resource = codeData.resource;
    }
    
    console.log(`Sending token response to Claude:`, JSON.stringify(tokenResponse, null, 2));
    
    return new Response(JSON.stringify(tokenResponse), {
      headers: { 'Content-Type': 'application/json' }
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
      headers: { 'Content-Type': 'application/json' }
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
      headers: { 'Content-Type': 'application/json' }
    });
  }
  
  return new Response(JSON.stringify({ error: 'unsupported_grant_type' }), {
    status: 400,
    headers: { 'Content-Type': 'application/json' }
  });
}

async function handleLocalOAuthRevoke(request: Request, hostRoute: MCPRouteInfo, env: Env): Promise<Response> {
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

async function handleLocalOAuthDevice(request: Request, hostRoute: MCPRouteInfo, env: Env): Promise<Response> {
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

async function handleLocalOAuthIntrospect(request: Request, hostRoute: MCPRouteInfo, env: Env): Promise<Response> {
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

function createDeviceSession(): SessionData {
  return {
    csrf: generateRandomString(32),
    localAuth: false,
    oauth: {},
    deviceCodes: {}
  };
}

function generateUserCode(): string {
  // Generate 6-digit user code
  return Math.random().toString(10).slice(2, 8).padStart(6, '0');
}

async function handleDeviceVerify(request: Request, hostRoute: MCPRouteInfo, env: Env): Promise<Response> {
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
async function handleClientRegistration(request: Request, hostRoute: MCPRouteInfo, env: Env): Promise<Response> {
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

async function handleDeviceVerifyPost(request: Request, hostRoute: MCPRouteInfo, env: Env): Promise<Response> {
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
async function initiateUpstreamOAuth(request: Request, hostRoute: MCPRouteInfo, session: SessionData, env: Env): Promise<Response> {
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
  
  // Set scopes - use first available scope or 'openid' as fallback
  const scope = upstreamOAuth.scopes_supported?.[0] || 'openid';
  authUrl.searchParams.set('scope', scope);
  
  console.log(`Using client_id: ${clientCredentials.client_id} for upstream OAuth to ${hostRoute.serverDomain}`);
  console.log(`Authorization URL: ${authUrl.toString()}`);
  
  return Response.redirect(authUrl.toString(), 302);
}

// Register client with upstream OAuth server (RFC 7591)
async function registerUpstreamClient(
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
async function discoverUpstreamOAuth(domain: string): Promise<any | null> {
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
async function handleOAuthStart(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const serverDomain = url.searchParams.get('server');
  
  if (!serverDomain) {
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
  
  return Response.redirect(authUrl.toString(), 302);
}

async function handleOAuthCallback(request: Request, env: Env): Promise<Response> {
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
  
  if (clientCredentials.client_secret) {
    tokenRequestBody.append('client_secret', clientCredentials.client_secret);
  }
  
  try {
    const tokenResponse = await fetch(upstreamOAuth.token_endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json'
      },
      body: tokenRequestBody.toString()
    });
    
    if (!tokenResponse.ok) {
      const errorText = await tokenResponse.text();
      console.error('Token exchange failed:', errorText);
      return new Response(`Token exchange failed: ${tokenResponse.status}`, { status: 400 });
    }
    
    const tokenData = await tokenResponse.json() as any;
    
    // Store tokens
    oauthData.tokens = {
      access_token: tokenData.access_token,
      refresh_token: tokenData.refresh_token,
      expires_in: tokenData.expires_in || 3600
    };
    oauthData.expiresAt = Date.now() + (tokenData.expires_in || 3600) * 1000;
    
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
        expires_at: Date.now() + 600000 // 10 minutes
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
function isTokenExpired(expiresAt: number | undefined, bufferSeconds: number = 300): boolean {
  if (!expiresAt) return true; // If no expiration time, consider it expired
  return Date.now() > (expiresAt - bufferSeconds * 1000); // Check if expired or expires within buffer
}

async function refreshUpstreamToken(serverDomain: string, serverData: any, env: Env): Promise<boolean> {
  if (!serverData.tokens?.refresh_token) {
    return false;
  }
  
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
    console.error('Server config not found for:', serverDomain);
    return false;
  }
  
  const refreshRequestBody = new URLSearchParams();
  refreshRequestBody.append('grant_type', 'refresh_token');
  refreshRequestBody.append('refresh_token', serverData.tokens.refresh_token);
  refreshRequestBody.append('client_id', serverConfig.clientId);
  
  if (serverConfig.clientSecret) {
    refreshRequestBody.append('client_secret', serverConfig.clientSecret);
  }
  
  try {
    const refreshResponse = await fetch(serverConfig.tokenEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json'
      },
      body: refreshRequestBody.toString()
    });
    
    if (!refreshResponse.ok) {
      const errorText = await refreshResponse.text();
      console.error('Token refresh failed:', errorText);
      return false;
    }
    
    const tokenData = await refreshResponse.json() as any;
    
    // Update tokens
    serverData.tokens.access_token = tokenData.access_token;
    if (tokenData.refresh_token) {
      serverData.tokens.refresh_token = tokenData.refresh_token;
    }
    serverData.tokens.expires_in = tokenData.expires_in || 3600;
    serverData.expiresAt = Date.now() + (tokenData.expires_in || 3600) * 1000;
    
    console.log('Token refreshed successfully for:', serverDomain);
    return true;
    
  } catch (error) {
    console.error('Token refresh error:', error);
    return false;
  }
}

async function handleWebSocketUpgrade(request: Request, hostRoute: MCPRouteInfo, upstreamHeaders: Record<string, string>): Promise<Response> {
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
async function handleEncode(request: Request, env: Env): Promise<Response> {
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
function generateEncodedHostname(domain: string, domainRoot: string): string {
  const encoded = base32Encode(domain);
  return `${encoded}-enc.${domainRoot}`;
}

function getCurrentDomain(request: Request): string {
  return new URL(request.url).hostname;
}

function getSessionId(request: Request): string | null {
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

async function getSession(sessionId: string, env: Env): Promise<SessionData | null> {
  return sessions.get(sessionId) || null;
}

function generateSessionId(): string {
  return generateRandomString(32);
}

function generateRandomString(length: number): string {
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

async function sha256Base64Url(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return btoa(String.fromCharCode(...new Uint8Array(hash)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}