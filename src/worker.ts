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
      tokens?: {
        access_token: string;
        refresh_token?: string;
        expires_in?: number;
      };
      expiresAt?: number;
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
        // This is an MCP server request
        return handleMCPRequest(request, hostRoute, env);
      }
      
      // Landing domain routes (handle both custom domain and workers.dev)
      const isLandingDomain = url.hostname.toLowerCase() === env.DOMAIN_ROOT.toLowerCase() ||
                             url.hostname.toLowerCase().startsWith('mcp.') && url.hostname.includes('.workers.dev');
      
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
  // Get session
  const sessionId = getSessionId(request);
  if (!sessionId) {
    return new Response(JSON.stringify({ 
      error: 'Authentication required',
      loginUrl: `https://${env.DOMAIN_ROOT}/login`
    }), { 
      status: 401,
      headers: { 'Content-Type': 'application/json' }
    });
  }
  
  const session = await getSession(sessionId, env);
  if (!session || !session.localAuth) {
    return new Response(JSON.stringify({ 
      error: 'Authentication required',
      loginUrl: `https://${env.DOMAIN_ROOT}/login`
    }), { 
      status: 401,
      headers: { 'Content-Type': 'application/json' }
    });
  }
  
  // Check OAuth tokens for this server
  const serverData = session.oauth?.[hostRoute.serverDomain];
  if (!serverData?.tokens) {
    return new Response(JSON.stringify({ 
      error: 'OAuth required for server',
      server: hostRoute.serverDomain,
      authUrl: `https://${env.DOMAIN_ROOT}/oauth/start?server=${encodeURIComponent(hostRoute.serverDomain)}`
    }), { 
      status: 401,
      headers: { 'Content-Type': 'application/json' }
    });
  }
  
  // Build upstream request
  const upstreamUrl = new URL(request.url.replace(request.url.split('/')[2], hostRoute.upstreamBase.host));
  
  const upstreamHeaders: Record<string, string> = {};
  request.headers.forEach((value, key) => {
    upstreamHeaders[key] = value;
  });
  upstreamHeaders['Authorization'] = `Bearer ${serverData.tokens.access_token}`;
  upstreamHeaders['Host'] = hostRoute.upstreamBase.hostname;

  const upstreamRequest = new Request(upstreamUrl.toString(), {
    method: request.method,
    headers: upstreamHeaders,
    body: request.body,
  });
  
  // Forward request
  const response = await fetch(upstreamRequest);
  
  // Handle token refresh on 401
  if (response.status === 401 && serverData.tokens.refresh_token) {
    // TODO: Implement token refresh
    console.log('Token refresh needed for', hostRoute.serverDomain);
  }
  
  return response;
}

// Dashboard
async function handleDashboard(request: Request, env: Env): Promise<Response> {
  const sessionId = getSessionId(request);
  const session = sessionId ? await getSession(sessionId, env) : null;
  
  if (!session || !session.localAuth) {
    return Response.redirect(`https://${env.DOMAIN_ROOT}/login`, 302);
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
  
  const response = Response.redirect(`https://${env.DOMAIN_ROOT}/`, 302);
  response.headers.set('Set-Cookie', `session=${sessionId}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=28800`);
  
  return response;
}

// OAuth handlers
async function handleOAuthStart(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const serverDomain = url.searchParams.get('server');
  
  if (!serverDomain) {
    return new Response('Missing server parameter', { status: 400 });
  }
  
  // Get MCP server config
  let mcpServers: MCPServerConfig[] = [];
  try {
    mcpServers = JSON.parse(env.MCP_SERVERS || '[]');
  } catch (e) {
    return new Response('Server configuration error', { status: 500 });
  }
  
  const serverConfig = mcpServers.find(s => s.domain === serverDomain);
  if (!serverConfig) {
    return new Response('Unknown server', { status: 400 });
  }
  
  // Generate OAuth URL
  const state = generateRandomString(16);
  const verifier = generateRandomString(32);
  const challenge = await sha256Base64Url(verifier);
  
  const authUrl = new URL(serverConfig.authzEndpoint);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('client_id', serverConfig.clientId);
  authUrl.searchParams.set('redirect_uri', `https://${env.DOMAIN_ROOT}/oauth/callback`);
  authUrl.searchParams.set('scope', serverConfig.scopes);
  authUrl.searchParams.set('state', `${serverDomain}:${state}`);
  authUrl.searchParams.set('code_challenge', challenge);
  authUrl.searchParams.set('code_challenge_method', 'S256');
  
  // Store PKCE verifier (simplified - in production use KV or encrypt in state)
  // TODO: Store verifier securely
  
  return Response.redirect(authUrl.toString(), 302);
}

async function handleOAuthCallback(request: Request, env: Env): Promise<Response> {
  // TODO: Implement OAuth callback
  return new Response('OAuth callback - TODO: Implement token exchange', { status: 501 });
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