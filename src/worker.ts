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
}

interface MCPRouteInfo {
  upstreamBase: URL;
  serverDomain: string;
}

// In-memory session storage (resets on worker restart)
const sessions = new Map<string, SessionData>();

// Environment bindings
interface Env {
  DOMAIN_ROOT: string;
  LOCAL_USER: string;
  LOCAL_PASSWORD: string;
  MCP_SERVERS: string;
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
        
        if (url.pathname === '/.well-known/oauth-protected-resource') {
          return handleProtectedResourceMetadata(request, hostRoute, env);
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
          if (request.method === 'GET') return handleLoginPage();
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
  
  // If it's an MCP client without auth, try public proxy mode first
  if (mcpProtocolVersion && (!authHeader || !authHeader.startsWith('Bearer '))) {
    console.log('MCP client detected without OAuth, trying public proxy mode');
    
    // Try proxying to upstream without authentication
    const upstreamUrl = new URL(request.url.replace(request.url.split('/')[2], hostRoute.upstreamBase.host));
    
    const upstreamHeaders: Record<string, string> = {};
    request.headers.forEach((value, key) => {
      if (key.toLowerCase() !== 'host') {
        upstreamHeaders[key] = value;
      }
    });
    upstreamHeaders['Host'] = hostRoute.upstreamBase.hostname;

    const upstreamRequest = new Request(upstreamUrl.toString(), {
      method: request.method,
      headers: upstreamHeaders,
      body: request.body,
    });
    
    try {
      const response = await fetch(upstreamRequest);
      // If upstream works, return the response
      if (response.status !== 401) {
        return response;
      }
      // If upstream returns 401, fall through to OAuth requirement
    } catch (error) {
      console.log('Public proxy failed:', error);
    }
  }
  
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
  
  // Find session with this local token
  let sessionWithToken: SessionData | null = null;
  for (const session of sessions.values()) {
    const tokenData = session.localOAuthTokens?.[hostname];
    if (tokenData?.access_token === localToken) {
      if (tokenData.expires_at > Date.now()) {
        sessionWithToken = session;
        break;
      } else {
        // Token expired
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
    }
  }
  
  if (!sessionWithToken || !sessionWithToken.localAuth) {
    return new Response(JSON.stringify({ 
      error: 'invalid_token',
      error_description: 'Invalid or expired token'
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
  
  // Only add upstream auth if we have tokens
  if (useUpstreamAuth && serverData?.tokens) {
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
  const response = await fetch(upstreamRequest);
  
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
function handleLoginPage(): Response {
  const html = `<!doctype html><html><body>
    <h1>MCP Gateway Login</h1>
    <form method="POST" action="/login">
      <label>User: <input name="user" required></label><br><br>
      <label>Pass: <input name="pass" type="password" required></label><br><br>
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
    bearer_methods_supported: ['header'],
    resource_documentation: `https://${hostname}`,
    
    // MCP-specific metadata
    mcp_version: '1.0',
    upstream_server: hostRoute.serverDomain,
    capabilities: ['tools', 'resources', 'prompts']
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
  
  // Store authorization code data
  const hostname = new URL(request.url).hostname;
  if (!session.localOAuthTokens) {
    session.localOAuthTokens = {};
  }
  
  // Store code temporarily (in practice, use a separate code store)
  const codeData = {
    client_id: formData.get('client_id') as string,
    redirect_uri: formData.get('redirect_uri') as string,
    scope: formData.get('scope') as string,
    code_challenge: formData.get('code_challenge') as string,
    code_challenge_method: formData.get('code_challenge_method') as string,
    resource: formData.get('resource') as string, // RFC 8707 resource parameter
    domain: hostname,
    expires_at: Date.now() + 600000 // 10 minutes
  };
  
  // Store in session temporarily (TODO: use proper storage)
  (session as any)[`code_${code}`] = codeData;
  
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
  
  if (grant_type === 'authorization_code') {
    const code = formData.get('code') as string;
    const client_id = formData.get('client_id') as string;
    const redirect_uri = formData.get('redirect_uri') as string;
    const code_verifier = formData.get('code_verifier') as string;
    
    // Find session with this code (simplified - in practice use proper storage)
    let codeData: any = null;
    let sessionWithCode: SessionData | null = null;
    
    for (const [sessionId, session] of sessions.entries()) {
      const stored = (session as any)[`code_${code}`];
      if (stored && stored.expires_at > Date.now()) {
        codeData = stored;
        sessionWithCode = session;
        delete (session as any)[`code_${code}`]; // One-time use
        break;
      }
    }
    
    if (!codeData) {
      return new Response(JSON.stringify({ error: 'invalid_grant' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
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
    
    // Store tokens in session
    if (!sessionWithCode!.localOAuthTokens) {
      sessionWithCode!.localOAuthTokens = {};
    }
    
    sessionWithCode!.localOAuthTokens[codeData.domain] = {
      access_token,
      refresh_token,
      expires_at: Date.now() + (expires_in * 1000),
      client_id: codeData.client_id
    };
    
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
  
  // Try to get server config, or discover dynamically
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
      clientId: 'mcp-gateway',
      scopes: upstreamOAuth.scopes_supported?.[0] || 'openid'
    };
  }
  
  // Exchange code for tokens
  const tokenRequestBody = new URLSearchParams();
  tokenRequestBody.append('grant_type', 'authorization_code');
  tokenRequestBody.append('code', code);
  tokenRequestBody.append('redirect_uri', `https://${getCurrentDomain(request)}/oauth/callback`);
  tokenRequestBody.append('client_id', serverConfig.clientId);
  tokenRequestBody.append('code_verifier', oauthData.pkceVerifier);
  
  if (serverConfig.clientSecret) {
    tokenRequestBody.append('client_secret', serverConfig.clientSecret);
  }
  
  try {
    const tokenResponse = await fetch(serverConfig.tokenEndpoint, {
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
    
    // Redirect to dashboard
    return Response.redirect(`https://${getCurrentDomain(request)}/`, 302);
    
  } catch (error) {
    console.error('Token exchange error:', error);
    return new Response('Token exchange failed', { status: 500 });
  }
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