import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { randomBytes, createHmac, createCipheriv, createDecipheriv } from 'crypto';
import { z } from 'zod';
import { base32Encode, base32Decode, toBase64Url, sha256Base64Url, parseHostEncodedUpstream, selectUpstreamForRequest, generateEncodedHostname, type MCPRouteInfo } from './encoding.js';
import { serialize as setCookie, parse as parseCookie } from 'cookie';
import { request as undiciRequest } from 'undici';
import type { Dispatcher } from 'undici';
import WebSocket from 'ws';

// MCP Server Configuration
export interface MCPServerConfig {
  domain: string; // e.g., "mcp.atlassian.com"
  name: string; // display name
  authzEndpoint: string;
  tokenEndpoint: string;
  clientId: string;
  clientSecret?: string;
  scopes: string;
  redirectUri?: string; // optional override
}

// Per-server OAuth state
interface ServerOAuthData {
  state?: string;
  pkceVerifier?: string;
  tokens?: EncryptedTokens;
  expiresAt?: number; // epoch seconds
}

type SessionData = {
  csrf: string;
  localAuth: boolean;
  // Changed from single oauth to per-server oauth
  oauth?: {
    [serverDomain: string]: ServerOAuthData;
  };
  // Keep backward compatibility for now
  legacyOAuth?: {
    state?: string;
    pkceVerifier?: string;
    tokens?: EncryptedTokens;
    expiresAt?: number;
  };
};

type TokenSet = {
  access_token: string;
  refresh_token?: string;
  expires_in?: number;
  token_type?: string;
  scope?: string;
  id_token?: string;
};

type EncryptedTokens = { iv: string; tag: string; data: string };

const SESS_COOKIE = 'gw.sid';
const CSRF_COOKIE = 'gw.csrf';

const sessionStore = new Map<string, SessionData>();

// MCP Server Registry - in production this would come from a database
const mcpServers = new Map<string, MCPServerConfig>();

// Initialize MCP servers from environment
function initializeMCPServers() {
  // Parse MCP_SERVERS environment variable
  const serversJson = process.env.MCP_SERVERS;
  if (serversJson) {
    try {
      const servers = JSON.parse(serversJson) as MCPServerConfig[];
      for (const server of servers) {
        mcpServers.set(server.domain, server);
      }
    } catch (e) {
      console.error('Failed to parse MCP_SERVERS:', e);
    }
  }
  
  // Fallback to legacy single server config if no MCP_SERVERS
  if (mcpServers.size === 0 && process.env.UPSTREAM_AUTHORIZATION_ENDPOINT) {
    const legacyServer: MCPServerConfig = {
      domain: new URL(process.env.UPSTREAM_API_BASE || 'http://localhost:4000').hostname,
      name: 'Legacy Server',
      authzEndpoint: process.env.UPSTREAM_AUTHORIZATION_ENDPOINT,
      tokenEndpoint: process.env.UPSTREAM_TOKEN_ENDPOINT!,
      clientId: process.env.UPSTREAM_CLIENT_ID!,
      clientSecret: process.env.UPSTREAM_CLIENT_SECRET,
      scopes: process.env.UPSTREAM_SCOPES || 'openid profile',
    };
    mcpServers.set(legacyServer.domain, legacyServer);
  }
}

function getMCPServer(domain: string): MCPServerConfig | null {
  return mcpServers.get(domain) || null;
}

function isAllowedMCPServer(domain: string): boolean {
  // Check if server is in registry
  if (mcpServers.has(domain)) return true;
  
  // Check allowlist from environment
  const allowlist = process.env.MCP_SERVER_ALLOWLIST?.split(',').map(s => s.trim()) || [];
  if (allowlist.length === 0) return true; // No allowlist means allow all registered servers
  return allowlist.includes(domain);
}

function envRequired(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`Missing env ${name}`);
  return v;
}

function hmacSign(value: string): string {
  const secret = envRequired('SESSION_SECRET');
  return createHmac('sha256', Buffer.from(secret, 'utf8')).update(value).digest('hex');
}

function encryptJSON(obj: unknown): EncryptedTokens {
  const key = Buffer.from(envRequired('TOKEN_ENCRYPTION_KEY'), 'hex');
  if (key.length !== 32) throw new Error('TOKEN_ENCRYPTION_KEY must be 32 bytes hex');
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const plaintext = Buffer.from(JSON.stringify(obj), 'utf8');
  const enc = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { iv: iv.toString('base64url'), tag: tag.toString('base64url'), data: enc.toString('base64url') };
}

function decryptJSON<T>(enc: EncryptedTokens): T {
  const key = Buffer.from(envRequired('TOKEN_ENCRYPTION_KEY'), 'hex');
  const iv = Buffer.from(enc.iv, 'base64url');
  const tag = Buffer.from(enc.tag, 'base64url');
  const data = Buffer.from(enc.data, 'base64url');
  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  const dec = Buffer.concat([decipher.update(data), decipher.final()]);
  return JSON.parse(dec.toString('utf8')) as T;
}

function genId(bytes = 16): string { return randomBytes(bytes).toString('base64url'); }

function setSessionCookie(reply: FastifyReply, sid: string) {
  const signed = `${sid}.${hmacSign(sid)}`;
  const secure = (process.env.COOKIE_SECURE || 'false').toLowerCase() === 'true';
  const cookie = setCookie(SESS_COOKIE, signed, {
    httpOnly: true,
    sameSite: 'lax',
    secure,
    path: '/',
    maxAge: 60 * 60 * 8,
  });
  reply.header('Set-Cookie', cookie);
}

function clearSessionCookie(reply: FastifyReply) {
  const cookie = setCookie(SESS_COOKIE, '', { httpOnly: true, sameSite: 'lax', secure: false, path: '/', maxAge: 0 });
  reply.header('Set-Cookie', cookie);
}

function setCsrf(reply: FastifyReply, csrf: string) {
  const cookie = setCookie(CSRF_COOKIE, csrf, { httpOnly: false, sameSite: 'lax', secure: false, path: '/', maxAge: 60 * 60 * 8 });
  reply.header('Set-Cookie', cookie);
}

function getSession(request: FastifyRequest): { sid: string | null, sess: SessionData | null } {
  const cookies = parseCookie(request.headers.cookie || '');
  const raw = cookies[SESS_COOKIE];
  if (!raw) return { sid: null, sess: null };
  const [sid, sig] = raw.split('.');
  if (!sid || !sig) return { sid: null, sess: null };
  if (hmacSign(sid) !== sig) return { sid: null, sess: null };
  const sess = sessionStore.get(sid) || null;
  return { sid, sess };
}

function requireCsrf(request: FastifyRequest, reply: FastifyReply, sess: SessionData): boolean {
  // Check header first (for API calls), then body (for form submissions)
  let token = request.headers['x-csrf-token'] as string;
  if (!token && request.body && typeof request.body === 'object') {
    token = (request.body as any)._csrf;
  }
  if (typeof token !== 'string' || token !== sess.csrf) {
    reply.status(403).send({ error: 'CSRF token missing/invalid' });
    return false;
  }
  return true;
}

export async function createGw(app: FastifyInstance) {
  // Initialize MCP servers from environment
  initializeMCPServers();
  
  const cfg = {
    baseUrl: process.env.GW_BASE_URL || 'http://localhost:3000',
    domainRoot: process.env.DOMAIN_ROOT || 'mcpgw.localhost',
    localUser: envRequired('LOCAL_USER'),
    localPassword: envRequired('LOCAL_PASSWORD'),
    // Legacy config - only used if no MCP servers configured
    authzEndpoint: process.env.UPSTREAM_AUTHORIZATION_ENDPOINT || '',
    tokenEndpoint: process.env.UPSTREAM_TOKEN_ENDPOINT || '',
    clientId: process.env.UPSTREAM_CLIENT_ID || '',
    clientSecret: process.env.UPSTREAM_CLIENT_SECRET || '',
    scopes: process.env.UPSTREAM_SCOPES || 'openid profile',
    redirectUri: process.env.REDIRECT_URI || `${process.env.GW_BASE_URL || 'http://localhost:3000'}/oauth/callback`,
  };
  
  // Helper to check if this is a hostname-encoded MCP route
  function getHostRoute(request: FastifyRequest): MCPRouteInfo | null {
    const hostname = request.hostname || request.headers.host?.split(':')[0] || '';
    return parseHostEncodedUpstream(hostname, cfg.domainRoot);
  }
  
  // Handle MCP server requests (proxy with OAuth)
  async function handleMCPRequest(req: FastifyRequest, reply: FastifyReply, hostRoute: MCPRouteInfo) {
    const { sess } = getSession(req);
    
    // Check if server is allowed
    if (!isAllowedMCPServer(hostRoute.serverDomain)) {
      return reply.status(403).send({ error: 'MCP server not allowed', server: hostRoute.serverDomain });
    }
    
    // Require authentication for all MCP requests
    if (!sess || !sess.localAuth) {
      return reply.status(401).send({ error: 'Authentication required' });
    }
    
    const serverData = sess.oauth?.[hostRoute.serverDomain];
    if (!serverData?.tokens) {
      return reply.status(401).send({ 
        error: 'OAuth required for server', 
        server: hostRoute.serverDomain,
        authUrl: `/oauth/start/${encodeURIComponent(hostRoute.serverDomain)}`
      });
    }
    
    try {
      const tokens = decryptJSON<TokenSet>(serverData.tokens);
      const reqUrl = new URL(req.url, `http://${req.headers.host}`);
      const upstreamUrl = selectUpstreamForRequest(hostRoute.upstreamBase, reqUrl);
      
      // Handle WebSocket upgrade
      if (req.headers.upgrade === 'websocket') {
        return handleWebSocketUpgrade(req, reply, upstreamUrl, tokens);
      }
      
      const response = await undiciRequest(upstreamUrl.toString(), {
        method: req.method as Dispatcher.HttpMethod,
        headers: {
          ...Object.fromEntries(
            Object.entries(req.headers).filter(([k]) => 
              !['host', 'connection', 'authorization'].includes(k.toLowerCase())
            )
          ),
          'Authorization': `Bearer ${tokens.access_token}`,
          'Host': upstreamUrl.hostname,
        },
        body: ['GET', 'HEAD'].includes(req.method) ? undefined : req.body as any,
      });
      
      // Handle token refresh on 401
      if (response.statusCode === 401 && tokens.refresh_token) {
        const refreshed = await tryRefreshServer(sess, hostRoute.serverDomain);
        if (refreshed) {
          const newTokens = decryptJSON<TokenSet>(sess.oauth![hostRoute.serverDomain]!.tokens!);
          const retry = await undiciRequest(upstreamUrl.toString(), {
            method: req.method as Dispatcher.HttpMethod,
            headers: {
              ...Object.fromEntries(
                Object.entries(req.headers).filter(([k]) => 
                  !['host', 'connection', 'authorization'].includes(k.toLowerCase())
                )
              ),
              'Authorization': `Bearer ${newTokens.access_token}`,
              'Host': upstreamUrl.hostname,
            },
            body: ['GET', 'HEAD'].includes(req.method) ? undefined : req.body as any,
          });
          
          reply.status(retry.statusCode);
          for (const [key, value] of Object.entries(retry.headers)) {
            reply.header(key, value as string);
          }
          return retry.body.pipe(reply.raw);
        }
      }
      
      reply.status(response.statusCode);
      for (const [key, value] of Object.entries(response.headers)) {
        reply.header(key, value as string);
      }
      return response.body.pipe(reply.raw);
      
    } catch (error) {
      req.log.error({ error, server: hostRoute.serverDomain }, 'MCP request failed');
      return reply.status(502).send({ error: 'Upstream request failed' });
    }
  }
  
  // Handle WebSocket upgrade for MCP requests
  async function handleWebSocketUpgrade(req: FastifyRequest, reply: FastifyReply, upstreamUrl: URL, tokens: TokenSet) {
    const wsRid = randomBytes(4).toString('hex');
    req.log.info({ wsRid, upstream: upstreamUrl.hostname }, 'WebSocket upgrade starting');
    
    try {
      // Create upstream WebSocket connection
      const upstreamWsUrl = upstreamUrl.toString().replace(/^http/, 'ws');
      const upstreamWs = new WebSocket(upstreamWsUrl, {
        headers: {
          'Authorization': `Bearer ${tokens.access_token}`,
        },
      });
      
      await new Promise((resolve, reject) => {
        upstreamWs.once('open', resolve);
        upstreamWs.once('error', reject);
      });
      
      // Accept client WebSocket
      reply.hijack();
      const clientWs = reply.raw as any;
      
      let msgCount = { fromUpstream: 0, fromClient: 0 };
      
      // Pipe messages bidirectionally
      upstreamWs.on('message', (data: any) => {
        msgCount.fromUpstream++;
        try {
          clientWs.send(data);
          if (msgCount.fromUpstream % 100 === 0) {
            req.log.debug({ wsRid, fromUpstream: msgCount.fromUpstream, fromClient: msgCount.fromClient }, 'WebSocket messages');
          }
        } catch (e: any) {
          req.log.error({ wsRid, error: e?.message || 'Unknown error' }, 'Client send failed');
          upstreamWs.close();
        }
      });
      
      clientWs.on('message', (data: any) => {
        msgCount.fromClient++;
        try {
          upstreamWs.send(data);
          if (msgCount.fromClient % 100 === 0) {
            req.log.debug({ wsRid, fromUpstream: msgCount.fromUpstream, fromClient: msgCount.fromClient }, 'WebSocket messages');
          }
        } catch (e: any) {
          req.log.error({ wsRid, error: e?.message || 'Unknown error' }, 'Upstream send failed');
          clientWs.close();
        }
      });
      
      // Handle close events
      upstreamWs.on('close', (code: any, reason: any) => {
        req.log.info({ wsRid, code, reason: reason?.toString() || 'No reason', totalMessages: msgCount.fromUpstream + msgCount.fromClient }, 'Upstream WebSocket closed');
        clientWs.close(code, reason);
      });
      
      clientWs.on('close', (code: any, reason: any) => {
        req.log.info({ wsRid, code, reason: reason?.toString() || 'No reason', totalMessages: msgCount.fromUpstream + msgCount.fromClient }, 'Client WebSocket closed');
        upstreamWs.close(code, reason);
      });
      
      // Handle error events
      upstreamWs.on('error', (error: any) => {
        req.log.error({ wsRid, error: error?.message || 'Unknown error' }, 'Upstream WebSocket error');
        clientWs.close(1011, 'Upstream error');
      });
      
      clientWs.on('error', (error: any) => {
        req.log.error({ wsRid, error: error?.message || 'Unknown error' }, 'Client WebSocket error');
        upstreamWs.close(1011, 'Client error');
      });
      
      req.log.info({ wsRid }, 'WebSocket tunnel established');
      
    } catch (error) {
      req.log.error({ wsRid, error }, 'WebSocket upgrade failed');
      reply.status(502).send({ error: 'WebSocket upgrade failed' });
    }
  }

  // Landing/dashboard
  app.get('/', async (req, reply) => {
    // Check if this is a hostname-encoded route
    const hostRoute = getHostRoute(req);
    if (hostRoute) {
      // This is a MCP server request, handle it
      return handleMCPRequest(req, reply, hostRoute);
    }
    
    const { sess } = getSession(req);
    if (!sess || !sess.localAuth) {
      return reply.redirect('/login');
    }
    
    // Build server status list
    let serversHtml = '<h2>MCP Servers</h2>';
    if (mcpServers.size === 0) {
      serversHtml += '<p>No MCP servers configured.</p>';
    } else {
      serversHtml += '<ul>';
      for (const [domain, server] of mcpServers.entries()) {
        const isConnected = !!(sess.oauth?.[domain]?.tokens);
        const encodedHostname = generateEncodedHostname(domain, cfg.domainRoot);
        const encodedUrl = `https://${encodedHostname}/`;
        serversHtml += `
          <li>
            <strong>${server.name}</strong> (${domain}) 
            ${isConnected ? '✅ Connected' : '❌ Not connected'}
            <br><small>URL: <code>${encodedUrl}</code></small>
            ${!isConnected ? `<br><form style="display:inline" method="POST" action="/upstream/start"><input type="hidden" name="_csrf" value="${sess.csrf}"><input type="hidden" name="server" value="${domain}"><button>Connect</button></form>` : ''}
          </li>`;
      }
      serversHtml += '</ul>';
    }
    
    // Legacy server support
    const legacyConnected = !!(sess.legacyOAuth?.tokens);
    if (cfg.authzEndpoint) {
      serversHtml += `
        <h3>Legacy Server</h3>
        <p>Status: ${legacyConnected ? '✅ Connected' : '❌ Not connected'}</p>
        ${!legacyConnected ? `<form method="POST" action="/upstream/start"><input type="hidden" name="_csrf" value="${sess.csrf}"><button>Connect to Legacy Server</button></form>` : ''}
      `;
    }
    
    const html = `<!doctype html><html><head><title>MCP Gateway</title></head><body>
      <h1>MCP Gateway Dashboard</h1>
      <p>Local session: ✅</p>
      <p>Domain root: <code>${cfg.domainRoot}</code></p>
      ${serversHtml}
      <form method="POST" action="/logout"><input type="hidden" name="_csrf" value="${sess.csrf}"><button>Logout</button></form>
      
      <h3>Add New Server</h3>
      <form method="GET" action="/encode">
        <label>Domain: <input name="domain" placeholder="mcp.example.com" required></label>
        <button type="submit">Generate URL</button>
      </form>
    </body></html>`;
    reply.type('text/html').send(html);
  });

  // Login pages
  app.get('/login', async (req, reply) => {
    const html = `<!doctype html><html><body>
    <h1>Local Sign-in</h1>
    <form method="POST" action="/login">
      <label>User: <input name="user"></label><br>
      <label>Pass: <input name="pass" type="password"></label><br>
      <button type="submit">Sign in</button>
    </form></body></html>`;
    reply.type('text/html').send(html);
  });

  app.post('/login', async (req, reply) => {
    const body = (req as any).body || {};
    const user = String(body.user || '');
    const pass = String(body.pass || '');
    const ipKey = `login:${req.ip}`;
    // Simple in-memory rate limiting (per-process)
    const now = Date.now();
    const limit = (app as any)._loginLimit || ((app as any)._loginLimit = new Map());
    const ent = limit.get(ipKey) || { c: 0, t: now };
    if (now - ent.t > 60_000) { ent.c = 0; ent.t = now; }
    ent.c++;
    limit.set(ipKey, ent);
    if (ent.c > 10) {
      return reply.status(429).send('Too many attempts');
    }

    if (user !== cfg.localUser || pass !== cfg.localPassword) {
      reply.status(401).send('Invalid credentials');
      return;
    }
    const sid = genId(24);
    const csrf = genId(24);
    sessionStore.set(sid, { csrf, localAuth: true });
    setSessionCookie(reply, sid);
    setCsrf(reply, csrf);
    reply.redirect('/');
  });

  app.post('/logout', async (req, reply) => {
    const { sid, sess } = getSession(req);
    if (!sid || !sess) return reply.redirect('/login');
    if (!requireCsrf(req, reply, sess)) return;
    sessionStore.delete(sid);
    clearSessionCookie(reply);
    reply.redirect('/login');
  });
  
  // Encoding endpoint for generating MCP URLs
  app.get('/encode', async (req, reply) => {
    const { sess } = getSession(req);
    if (!sess || !sess.localAuth) {
      return reply.redirect('/login');
    }
    
    const domain = (req.query as any)?.domain as string;
    if (!domain) {
      return reply.status(400).send('Missing domain parameter');
    }
    
    try {
      const encodedHostname = generateEncodedHostname(domain, cfg.domainRoot);
      const encodedUrl = `https://${encodedHostname}/`;
      
      const html = `<!doctype html><html><head><title>Encoded MCP URL</title></head><body>
        <h1>MCP URL Generator</h1>
        <h2>Results for: ${domain}</h2>
        <p><strong>Encoded URL:</strong><br><code>${encodedUrl}</code></p>
        <p>Format: <code>{base32(domain)}-enc.${cfg.domainRoot}</code></p>
        <p>Use this URL in Claude.ai or ChatGPT to connect to the MCP server.</p>
        <p><a href="/">← Back to Dashboard</a></p>
      </body></html>`;
      
      reply.type('text/html').send(html);
    } catch (error) {
      reply.status(400).send('Invalid domain');
    }
  });

  // Upstream OAuth start - support both legacy and per-server
  app.post('/upstream/start', async (req, reply) => {
    const { sid, sess } = getSession(req);
    if (!sid || !sess || !sess.localAuth) return reply.status(401).send('Not logged in');
    if (!requireCsrf(req, reply, sess)) return;

    const body = req.body as any || {};
    const serverDomain = body.server as string;
    
    let serverConfig: MCPServerConfig | null = null;
    if (serverDomain) {
      serverConfig = getMCPServer(serverDomain);
      if (!serverConfig) {
        return reply.status(400).send({ error: 'Unknown MCP server', server: serverDomain });
      }
    } else if (cfg.authzEndpoint) {
      // Legacy mode - use environment config
      serverConfig = {
        domain: 'legacy',
        name: 'Legacy Server',
        authzEndpoint: cfg.authzEndpoint,
        tokenEndpoint: cfg.tokenEndpoint,
        clientId: cfg.clientId,
        clientSecret: cfg.clientSecret,
        scopes: cfg.scopes,
        redirectUri: cfg.redirectUri,
      };
    } else {
      return reply.status(400).send({ error: 'No server specified and no legacy config' });
    }

    const state = genId(16);
    const verifier = toBase64Url(randomBytes(32).toString('base64')) || genId(32);
    const challenge = await sha256Base64Url(verifier);
    
    // Store state per server
    if (serverDomain) {
      sess.oauth = sess.oauth || {};
      sess.oauth[serverDomain] = { state, pkceVerifier: verifier };
    } else {
      sess.legacyOAuth = { state, pkceVerifier: verifier };
    }
    sessionStore.set(sid, sess);

    const redirectUri = serverConfig.redirectUri || cfg.redirectUri;
    const url = new URL(serverConfig.authzEndpoint);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('client_id', serverConfig.clientId);
    url.searchParams.set('redirect_uri', redirectUri);
    url.searchParams.set('scope', serverConfig.scopes);
    url.searchParams.set('state', `${serverDomain || 'legacy'}:${state}`);
    url.searchParams.set('code_challenge', challenge);
    url.searchParams.set('code_challenge_method', 'S256');

    reply.status(302).header('location', url.toString()).send();
  });
  
  // OAuth start for specific server (GET route for direct links)
  app.get('/oauth/start/:server', async (req, reply) => {
    const { sess } = getSession(req);
    if (!sess || !sess.localAuth) return reply.status(401).send('Not logged in');
    
    const serverDomain = (req.params as any).server;
    const serverConfig = getMCPServer(serverDomain);
    if (!serverConfig) {
      return reply.status(400).send({ error: 'Unknown MCP server', server: serverDomain });
    }
    
    const html = `<!doctype html><html><head><title>Connect to ${serverConfig.name}</title></head><body>
      <h1>Connect to ${serverConfig.name}</h1>
      <p>Server: ${serverConfig.domain}</p>
      <p>This will redirect you to the OAuth provider for authentication.</p>
      <form method="POST" action="/upstream/start">
        <input type="hidden" name="_csrf" value="${sess.csrf}">
        <input type="hidden" name="server" value="${serverDomain}">
        <button type="submit">Connect</button>
      </form>
      <p><a href="/">← Back to Dashboard</a></p>
    </body></html>`;
    
    reply.type('text/html').send(html);
  });

  // OAuth callback
  app.get('/oauth/callback', async (req, reply) => {
    const { sid, sess } = getSession(req);
    if (!sid || !sess || !sess.localAuth) return reply.status(401).send('Not logged in');
    const url = new URL((req as any).raw.url, cfg.baseUrl);
    const code = url.searchParams.get('code');
    const stateParam = url.searchParams.get('state');
    if (!code || !stateParam) return reply.status(400).send('Missing code/state');
    
    // Parse state to determine which server this is for
    const [serverDomain, state] = stateParam.split(':', 2);
    if (!serverDomain || !state) return reply.status(400).send('Invalid state format');
    
    let serverConfig: MCPServerConfig | null = null;
    let verifier: string | undefined;
    
    if (serverDomain === 'legacy') {
      // Legacy mode
      if (state !== sess.legacyOAuth?.state) return reply.status(400).send('Invalid legacy state');
      verifier = sess.legacyOAuth?.pkceVerifier;
      serverConfig = {
        domain: 'legacy',
        name: 'Legacy Server',
        authzEndpoint: cfg.authzEndpoint,
        tokenEndpoint: cfg.tokenEndpoint,
        clientId: cfg.clientId,
        clientSecret: cfg.clientSecret,
        scopes: cfg.scopes,
        redirectUri: cfg.redirectUri,
      };
    } else {
      // Per-server mode
      serverConfig = getMCPServer(serverDomain);
      if (!serverConfig) return reply.status(400).send('Unknown server');
      if (state !== sess.oauth?.[serverDomain]?.state) return reply.status(400).send('Invalid server state');
      verifier = sess.oauth?.[serverDomain]?.pkceVerifier;
    }
    
    if (!verifier) return reply.status(400).send('Missing PKCE');

    // Token exchange
    const form = new URLSearchParams();
    form.set('grant_type', 'authorization_code');
    form.set('code', code);
    form.set('redirect_uri', serverConfig.redirectUri || cfg.redirectUri);
    form.set('client_id', serverConfig.clientId);
    form.set('code_verifier', verifier);
    if (serverConfig.clientSecret) form.set('client_secret', serverConfig.clientSecret);

    try {
      const resp = await undiciRequest(serverConfig.tokenEndpoint, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: form.toString(),
      });
      const tokens = await resp.body.json() as TokenSet;
      if (resp.statusCode !== 200 || !tokens.access_token) {
        req.log.error({ status: resp.statusCode, tokens: Object.keys(tokens), server: serverDomain }, 'Token exchange failed');
        return reply.status(400).send('Token exchange failed');
      }
      
      const now = Math.floor(Date.now() / 1000);
      const expiresAt = tokens.expires_in ? now + tokens.expires_in : now + 3600;
      
      if (serverDomain === 'legacy') {
        sess.legacyOAuth = {
          tokens: encryptJSON(tokens),
          state: undefined,
          pkceVerifier: undefined,
          expiresAt,
        };
      } else {
        sess.oauth = sess.oauth || {};
        sess.oauth[serverDomain] = {
          tokens: encryptJSON(tokens),
          state: undefined,
          pkceVerifier: undefined,
          expiresAt,
        };
      }
      
      sessionStore.set(sid, sess);
      reply.redirect('/');
    } catch (error) {
      req.log.error({ error, server: serverDomain }, 'Token exchange error');
      return reply.status(500).send('Token exchange error');
    }
  });

  // API proxy (legacy)
  app.get('/api/*', async (req, reply) => {
    const { sess } = getSession(req);
    if (!sess || !sess.localAuth || !sess.legacyOAuth?.tokens) return reply.status(401).send('Not logged in');
    const tokens = decryptJSON<TokenSet>(sess.legacyOAuth.tokens);
    const upstreamUrl = new URL(process.env.UPSTREAM_API_BASE || 'http://localhost:4000');
    const path = (req.params as any['*']) as string;
    upstreamUrl.pathname = `/api/${path}`;
    const res1 = await undiciRequest(upstreamUrl.toString(), {
      method: 'GET',
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    });
    if (res1.statusCode === 401 && tokens.refresh_token) {
      const ok = await tryRefresh(sess);
      if (ok) {
        const refreshed = decryptJSON<TokenSet>(sess.legacyOAuth!.tokens!);
        const res2 = await undiciRequest(upstreamUrl.toString(), {
          method: 'GET',
          headers: { Authorization: `Bearer ${refreshed.access_token}` },
        });
        reply.status(res2.statusCode).headers(res2.headers as any);
        return res2.body.pipe(reply.raw);
      }
    }
    reply.status(res1.statusCode).headers(res1.headers as any);
    return res1.body.pipe(reply.raw);
  });

  // SSE proxy (legacy)
  app.get('/sse/*', async (req, reply) => {
    const { sess } = getSession(req);
    if (!sess || !sess.localAuth || !sess.legacyOAuth?.tokens) return reply.status(401).send('Not logged in');
    const tokens = decryptJSON<TokenSet>(sess.legacyOAuth.tokens);
    const upstreamUrl = new URL(process.env.UPSTREAM_API_BASE || 'http://localhost:4000');
    const path = (req.params as any['*']) as string;
    upstreamUrl.pathname = `/sse/${path}`;
    const res = await undiciRequest(upstreamUrl.toString(), {
      method: 'GET',
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    });
    reply
      .header('Content-Type', 'text/event-stream')
      .header('Cache-Control', 'no-cache')
      .header('Connection', 'keep-alive')
      .status(200);

    const heartbeatMs = Number(process.env.SSE_HEARTBEAT_MS || 12000);
    const interval = setInterval(() => {
      reply.raw.write(`: ping\n\n`);
    }, heartbeatMs);
    req.raw.on('close', () => clearInterval(interval));

    res.body.on('data', (chunk: Buffer) => reply.raw.write(chunk));
    res.body.on('end', () => reply.raw.end());
    res.body.on('error', () => reply.raw.end());
  });

  // Legacy token refresh
  async function tryRefresh(sess: SessionData): Promise<boolean> {
    try {
      if (!sess.legacyOAuth?.tokens) return false;
      const tokens = decryptJSON<TokenSet>(sess.legacyOAuth.tokens);
      if (!tokens.refresh_token) return false;
      const form = new URLSearchParams();
      form.set('grant_type', 'refresh_token');
      form.set('refresh_token', tokens.refresh_token);
      form.set('client_id', cfg.clientId);
      if (cfg.clientSecret) form.set('client_secret', cfg.clientSecret);
      const resp = await undiciRequest(cfg.tokenEndpoint, {
        method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: form.toString()
      });
      if (resp.statusCode !== 200) return false;
      const next = await resp.body.json() as TokenSet;
      const now = Math.floor(Date.now() / 1000);
      sess.legacyOAuth = { tokens: encryptJSON(next), expiresAt: now + (next.expires_in || 3600) };
      return true;
    } catch (e) { return false; }
  }
  
  // Per-server token refresh
  async function tryRefreshServer(sess: SessionData, serverDomain: string): Promise<boolean> {
    try {
      const serverData = sess.oauth?.[serverDomain];
      if (!serverData?.tokens) return false;
      const tokens = decryptJSON<TokenSet>(serverData.tokens);
      if (!tokens.refresh_token) return false;
      
      const serverConfig = getMCPServer(serverDomain);
      if (!serverConfig) return false;
      
      const form = new URLSearchParams();
      form.set('grant_type', 'refresh_token');
      form.set('refresh_token', tokens.refresh_token);
      form.set('client_id', serverConfig.clientId);
      if (serverConfig.clientSecret) form.set('client_secret', serverConfig.clientSecret);
      
      const resp = await undiciRequest(serverConfig.tokenEndpoint, {
        method: 'POST', 
        headers: { 'content-type': 'application/x-www-form-urlencoded' }, 
        body: form.toString()
      });
      if (resp.statusCode !== 200) return false;
      
      const next = await resp.body.json() as TokenSet;
      const now = Math.floor(Date.now() / 1000);
      sess.oauth![serverDomain] = { tokens: encryptJSON(next), expiresAt: now + (next.expires_in || 3600) };
      return true;
    } catch (e) { return false; }
  }
  
  // Catch-all route for hostname-encoded requests
  app.all('*', async (req, reply) => {
    const hostRoute = getHostRoute(req);
    if (hostRoute) {
      return handleMCPRequest(req, reply, hostRoute);
    }
    
    // Not a hostname route and no matching endpoint
    reply.status(404).send({ error: 'Not found' });
  });
}
