// mcp-sse-mitm.js (Express 5 compatible)
const express = require('express');
const cors = require('cors');
const { randomUUID } = require('crypto');
const fs = require('fs');
const http = require('http');
const https = require('https');
const crypto = require('crypto');

const UPSTREAM_BASE = process.env.UPSTREAM_BASE;
const PORT = Number(process.env.PORT || 8787);
const HTTPS_ENABLED = /^(1|true|yes)$/i.test(String(process.env.HTTPS || '0'));
const TLS_CERT_FILE = process.env.TLS_CERT_FILE;
const TLS_KEY_FILE = process.env.TLS_KEY_FILE;
const TLS_PASSPHRASE = process.env.TLS_PASSPHRASE;
const TLS_MIN_VERSION = process.env.TLS_MIN_VERSION || 'TLSv1.2';

// OAuth2 configuration
const OAUTH2_CLIENT_ID = process.env.OAUTH2_CLIENT_ID;
const OAUTH2_CLIENT_SECRET = process.env.OAUTH2_CLIENT_SECRET;
const OAUTH2_REDIRECT_URI = process.env.OAUTH2_REDIRECT_URI || `http://localhost:${PORT}/oauth/callback`;
const OAUTH2_UPSTREAM_CLIENT_ID = process.env.OAUTH2_UPSTREAM_CLIENT_ID;
const OAUTH2_UPSTREAM_CLIENT_SECRET = process.env.OAUTH2_UPSTREAM_CLIENT_SECRET;
const OAUTH2_UPSTREAM_AUTH_URL = process.env.OAUTH2_UPSTREAM_AUTH_URL;
const OAUTH2_UPSTREAM_TOKEN_URL = process.env.OAUTH2_UPSTREAM_TOKEN_URL;

if (!UPSTREAM_BASE) {
  console.error('Set UPSTREAM_BASE, e.g. https://mcp.atlassian.com');
  process.exit(1);
}
const ALLOW_PATHS = (process.env.ALLOW_PATHS || '/v1/tools/call,/v1/tools/list')
  .split(',').map(s => s.trim()).filter(Boolean);

const HOP_BY_HOP = new Set([
  'connection','keep-alive','proxy-authenticate','proxy-authorization',
  'te','trailers','transfer-encoding','upgrade'
]);
const FORBIDDEN_FORWARD = new Set([
  'host','accept-encoding','content-length','transfer-encoding','te','trailer',
  'proxy','proxy-authorization','proxy-authenticate','sec-fetch-mode','sec-fetch-site',
  'sec-fetch-dest','sec-ch-ua','sec-ch-ua-mobile','sec-ch-ua-platform','sec-gpc'
]);

const app = express();
app.disable('x-powered-by');
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true })); // For OAuth2 form handling

// In-memory session storage (in production, use Redis or similar)
const sessions = new Map(); // sessionId -> { clientToken, upstreamToken, state, expires }
const oauth2States = new Map(); // state -> { sessionId, expires }

const DEBUG_MAX_BODY = parseInt(process.env.DEBUG_MAX_BODY || '8192', 10);

function redactHeaders(hdrs) {
  const out = {};
  for (const [k, v] of Object.entries(hdrs || {})) {
    const kl = k.toLowerCase();
    if (kl === 'authorization') out[k] = 'Bearer ********';
    else if (kl === 'cookie' || kl === 'set-cookie') out[k] = '********';
    else out[k] = v;
  }
  return out;
}

function trunc(str, n = DEBUG_MAX_BODY) {
  if (typeof str !== 'string') return str;
  return str.length > n ? str.slice(0, n) + `… [+${str.length - n} more]` : str;
}

// Global request logger (all methods/paths)
app.use((req, res, next) => {
  const rid = randomUUID();
  req.rid = rid;
  const start = Date.now();
  const info = {
    id: rid,
    ts: new Date().toISOString(),
    method: req.method,
    path: req.path,
    url: req.originalUrl,
    ip: req.ip,
    query: req.query,
    headers: redactHeaders(req.headers),
  };
  if (req.body && Object.keys(req.body).length) {
    try { info.body = redact(req.body); } catch { info.body = '[unprintable body]'; }
  } else if (req.headers['content-length']) {
    info.body = `[unparsed body len=${req.headers['content-length']}]`;
  }
  console.log('[req]', JSON.stringify(info));

  res.on('finish', () => {
    const elapsed = Date.now() - start;
    console.log('[res]', JSON.stringify({ id: rid, status: res.statusCode, elapsed_ms: elapsed, length: res.getHeader('content-length') || null }));
  });
  next();
});

function redact(obj) {
  if (typeof obj === 'string') {
    return obj
      .replace(/(AKIA[0-9A-Z]{16})/g, 'AKIA**************')
      .replace(/(secret|token|api[-_]?key)["']?\s*[:=]\s*["']?[A-Za-z0-9\/+=._-]{8,}/gi, '$1: ********');
  }
  if (Array.isArray(obj)) return obj.map(redact);
  if (obj && typeof obj === 'object') {
    const out = {};
    for (const k of Object.keys(obj)) {
      out[k] = /(pass(word)?|secret|token|api[-_]?key)/i.test(k) ? '********' : redact(obj[k]);
    }
    return out;
  }
  return obj;
}

const INJECTION_RX = [
  /ignore (all|previous) (rules|instructions)/i,
  /exfiltrate|leak|dump (secrets|keys|credentials|pii)/i,
  /(aws|gcp|azure).*(access|secret).*(key)/i
];

function looksInjected(val) {
  if (typeof val === 'string') return INJECTION_RX.some(rx => rx.test(val));
  if (Array.isArray(val)) return val.some(looksInjected);
  if (val && typeof val === 'object') return Object.values(val).some(looksInjected);
  return false;
}

function copyHeaders(src, dst) {
  for (const [k, v] of src.entries()) {
    if (HOP_BY_HOP.has(k.toLowerCase())) continue;
    dst[k] = v;
  }
  return dst;
}

function buildForwardHeaders(reqHeaders, opts = {}) {
  const out = new Headers();
  const allow = new Set([
    'authorization','content-type','accept','user-agent','origin','referer'
  ]);
  for (const [key, value] of Object.entries(reqHeaders)) {
    const k = key.toLowerCase();
    if (HOP_BY_HOP.has(k) || FORBIDDEN_FORWARD.has(k) || k.startsWith('proxy-') || k.startsWith('sec-')) continue;
    if (allow.has(k) || k.startsWith('x-')) {
      if (typeof value === 'string') out.set(key, value);
      else if (Array.isArray(value)) out.set(key, value.join(', '));
    }
  }
  if (opts.forceAccept) out.set('Accept', opts.forceAccept);
  if (opts.upstreamToken) {
    out.set('Authorization', `Bearer ${opts.upstreamToken}`);
  }
  out.set('x-mcp-proxy', 'true');
  return out;
}

// Authentication middleware
function authenticateRequest(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or invalid authorization header' });
  }

  const token = authHeader.slice(7);
  
  // Find session by client token
  let sessionId = null;
  let session = null;
  for (const [sid, sess] of sessions.entries()) {
    if (sess.clientToken === token) {
      sessionId = sid;
      session = sess;
      break;
    }
  }

  if (!session) {
    console.log(`[auth] No session found for token: ${token.substring(0, 16)}...`);
    return res.status(401).json({ error: 'Invalid or expired token' });
  }

  if (session.expires < Date.now()) {
    console.log(`[auth] Session expired for token: ${token.substring(0, 16)}...`);
    return res.status(401).json({ error: 'Invalid or expired token' });
  }

  console.log(`[auth] Session ${sessionId} found, state: ${session.state}`);

  // Check if we need upstream authentication
  if (session.state === 'authenticated' && !session.upstreamToken && 
      OAUTH2_UPSTREAM_AUTH_URL && OAUTH2_UPSTREAM_CLIENT_ID) {
    console.log(`[auth] Upstream auth required for session ${sessionId}`);
    // Initiate upstream OAuth2 flow
    const state = generateState();
    oauth2States.set(state, {
      sessionId,
      expires: Date.now() + 10 * 60 * 1000,
    });

    const upstreamAuthUrl = new URL(OAUTH2_UPSTREAM_AUTH_URL);
    upstreamAuthUrl.searchParams.set('client_id', OAUTH2_UPSTREAM_CLIENT_ID);
    upstreamAuthUrl.searchParams.set('redirect_uri', OAUTH2_REDIRECT_URI + '?flow=upstream');
    upstreamAuthUrl.searchParams.set('response_type', 'code');
    upstreamAuthUrl.searchParams.set('state', state);
    upstreamAuthUrl.searchParams.set('scope', 'read write');

    return res.status(302).json({
      error: 'upstream_authentication_required',
      auth_url: upstreamAuthUrl.toString(),
      message: 'Please complete upstream authentication by visiting the auth_url'
    });
  }

  // If upstream OAuth2 is not configured, allow requests with just client auth
  if (session.state === 'authenticated' && !OAUTH2_UPSTREAM_AUTH_URL) {
    console.log(`[auth] No upstream auth configured, marking session ${sessionId} as fully authenticated`);
    session.state = 'fully_authenticated'; // No upstream auth needed
  }

  if (session.state !== 'fully_authenticated') {
    console.log(`[auth] Session ${sessionId} not fully authenticated, state: ${session.state}`);
    return res.status(401).json({ error: 'Authentication incomplete' });
  }

  console.log(`[auth] Session ${sessionId} fully authenticated`);
  req.session = session;
  req.sessionId = sessionId;
  next();
}

function upstreamURL(path, search = '') {
  return `${UPSTREAM_BASE}${path}${search || ''}`;
}

// OAuth2 utility functions
function generateState() {
  return crypto.randomBytes(32).toString('hex');
}

function generateSessionId() {
  return randomUUID();
}

function cleanupExpiredSessions() {
  const now = Date.now();
  for (const [sessionId, session] of sessions.entries()) {
    if (session.expires < now) {
      sessions.delete(sessionId);
    }
  }
  for (const [state, stateData] of oauth2States.entries()) {
    if (stateData.expires < now) {
      oauth2States.delete(state);
    }
  }
}

// Clean up expired sessions every 5 minutes
setInterval(cleanupExpiredSessions, 5 * 60 * 1000);

async function exchangeCodeForToken(code, redirectUri, clientId, clientSecret, tokenUrl) {
  const params = new URLSearchParams({
    grant_type: 'authorization_code',
    code: code,
    redirect_uri: redirectUri,
    client_id: clientId,
    client_secret: clientSecret,
  });

  const response = await fetch(tokenUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Accept': 'application/json',
    },
    body: params.toString(),
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Token exchange failed: ${response.status} ${errorText}`);
  }

  return await response.json();
}

// OAuth2 authorization endpoint for client → gateway flow
app.get('/oauth/authorize', (req, res) => {
  const rid = randomUUID();
  console.log(`[${rid}] OAuth2 authorize request`);

  if (!OAUTH2_CLIENT_ID) {
    return res.status(500).json({ error: 'OAuth2 not configured' });
  }

  const state = generateState();
  const sessionId = generateSessionId();
  
  // Store state for validation
  oauth2States.set(state, {
    sessionId,
    expires: Date.now() + 10 * 60 * 1000, // 10 minutes
  });

  // Create session
  sessions.set(sessionId, {
    state: 'pending',
    expires: Date.now() + 60 * 60 * 1000, // 1 hour
  });

  // For simplicity, we'll create a basic authorize page or redirect
  // In a real implementation, this would show a login form
  const authorizeUrl = new URL(req.originalUrl, `http://localhost:${PORT}`);
  const clientId = authorizeUrl.searchParams.get('client_id');
  const redirectUri = authorizeUrl.searchParams.get('redirect_uri');
  const scope = authorizeUrl.searchParams.get('scope') || 'read';
  const clientState = authorizeUrl.searchParams.get('state') || '';

  if (clientId !== OAUTH2_CLIENT_ID) {
    return res.status(400).json({ error: 'Invalid client_id' });
  }

  // Simple authorization page
  res.send(`
    <html>
      <body>
        <h2>Authorize MCP Gateway</h2>
        <p>Application requests access with scope: ${scope}</p>
        <form method="post" action="/oauth/authorize">
          <input type="hidden" name="state" value="${state}" />
          <input type="hidden" name="client_state" value="${clientState}" />
          <input type="hidden" name="redirect_uri" value="${redirectUri}" />
          <input type="hidden" name="scope" value="${scope}" />
          <button type="submit" name="action" value="allow">Allow</button>
          <button type="submit" name="action" value="deny">Deny</button>
        </form>
      </body>
    </html>
  `);
});

// OAuth2 authorization handling (POST)
app.post('/oauth/authorize', (req, res) => {
  const rid = randomUUID();
  const { state, client_state, redirect_uri, scope, action } = req.body;

  console.log(`[${rid}] OAuth2 authorize action: ${action}`);

  const stateData = oauth2States.get(state);
  if (!stateData || stateData.expires < Date.now()) {
    return res.status(400).json({ error: 'Invalid or expired state' });
  }

  oauth2States.delete(state);
  const session = sessions.get(stateData.sessionId);
  if (!session) {
    return res.status(400).json({ error: 'Session not found' });
  }

  if (action === 'deny') {
    sessions.delete(stateData.sessionId);
    const errorUrl = new URL(redirect_uri);
    errorUrl.searchParams.set('error', 'access_denied');
    if (client_state) errorUrl.searchParams.set('state', client_state);
    return res.redirect(errorUrl.toString());
  }

  // Generate authorization code
  const code = crypto.randomBytes(32).toString('hex');
  session.code = code;
  session.redirect_uri = redirect_uri;
  session.scope = scope;
  session.state = 'authorized';

  // Redirect with code
  const callbackUrl = new URL(redirect_uri);
  callbackUrl.searchParams.set('code', code);
  if (client_state) callbackUrl.searchParams.set('state', client_state);
  
  console.log(`[${rid}] OAuth2 authorization granted, redirecting to: ${callbackUrl.toString()}`);
  res.redirect(callbackUrl.toString());
});

// OAuth2 token endpoint for client → gateway flow
app.post('/oauth/token', async (req, res) => {
  const rid = randomUUID();
  console.log(`[${rid}] OAuth2 token request`);

  const { grant_type, code, redirect_uri, client_id, client_secret } = req.body;

  if (grant_type !== 'authorization_code') {
    return res.status(400).json({ error: 'unsupported_grant_type' });
  }

  if (client_id !== OAUTH2_CLIENT_ID || client_secret !== OAUTH2_CLIENT_SECRET) {
    return res.status(401).json({ error: 'invalid_client' });
  }

  // Find session by code
  let sessionId = null;
  let session = null;
  for (const [sid, sess] of sessions.entries()) {
    if (sess.code === code && sess.redirect_uri === redirect_uri) {
      sessionId = sid;
      session = sess;
      break;
    }
  }

  if (!session || session.state !== 'authorized') {
    return res.status(400).json({ error: 'invalid_grant' });
  }

  // Generate access token
  const accessToken = crypto.randomBytes(32).toString('hex');
  const refreshToken = crypto.randomBytes(32).toString('hex');
  
  session.clientToken = accessToken;
  session.refreshToken = refreshToken;
  
  // If no upstream OAuth2 is configured, mark as fully authenticated
  if (!OAUTH2_UPSTREAM_AUTH_URL || !OAUTH2_UPSTREAM_CLIENT_ID) {
    session.state = 'fully_authenticated';
  } else {
    session.state = 'authenticated';
  }
  
  delete session.code; // Code is single-use

  console.log(`[${rid}] OAuth2 token granted for session: ${sessionId}`);

  res.json({
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: 3600,
    refresh_token: refreshToken,
    scope: session.scope,
  });
});

// OAuth2 callback endpoint (for gateway → upstream flow)
app.get('/oauth/callback', async (req, res) => {
  const rid = randomUUID();
  const { code, state, error } = req.query;

  console.log(`[${rid}] OAuth2 upstream callback`);

  if (error) {
    console.error(`[${rid}] OAuth2 upstream error: ${error}`);
    return res.status(400).json({ error: `Upstream OAuth2 error: ${error}` });
  }

  const stateData = oauth2States.get(state);
  if (!stateData || stateData.expires < Date.now()) {
    return res.status(400).json({ error: 'Invalid or expired state' });
  }

  oauth2States.delete(state);
  const session = sessions.get(stateData.sessionId);
  if (!session) {
    return res.status(400).json({ error: 'Session not found' });
  }

  try {
    // Exchange code for upstream token
    const tokenData = await exchangeCodeForToken(
      code,
      OAUTH2_REDIRECT_URI + '?flow=upstream',
      OAUTH2_UPSTREAM_CLIENT_ID,
      OAUTH2_UPSTREAM_CLIENT_SECRET,
      OAUTH2_UPSTREAM_TOKEN_URL
    );

    session.upstreamToken = tokenData.access_token;
    session.upstreamRefreshToken = tokenData.refresh_token;
    session.state = 'fully_authenticated';

    console.log(`[${rid}] OAuth2 upstream authentication complete for session: ${stateData.sessionId}`);

    res.send(`
      <html>
        <body>
          <h2>Authentication Complete</h2>
          <p>You are now authenticated with both the gateway and upstream server.</p>
          <p>You can close this window and return to your application.</p>
        </body>
      </html>
    `);
  } catch (error) {
    console.error(`[${rid}] OAuth2 upstream token exchange failed:`, error.message);
    res.status(500).json({ error: 'Failed to complete upstream authentication' });
  }
});

// GET /v1/sse (SSE proxy)
app.get('/v1/sse', authenticateRequest, async (req, res) => {
  const rid = randomUUID();
  try {
    const headers = buildForwardHeaders(req.headers, { 
      forceAccept: 'text/event-stream',
      upstreamToken: req.session.upstreamToken
    });

    const search = req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : '';
    const upstream = await fetch(upstreamURL('/v1/sse', search), { method: 'GET', headers, redirect: 'manual' });

    if (!upstream.ok) {
      const body = await upstream.text().catch(() => '');
      console.warn(`[${rid}] SSE upstream status`, upstream.status);
      res.status(upstream.status);
      res.setHeader('Content-Type', upstream.headers.get('content-type') || 'text/plain; charset=utf-8');
      return res.send(body || `Upstream returned ${upstream.status}`);
    }
    if (!upstream.body) {
      console.error(`[${rid}] SSE upstream missing body`);
      return res.status(502).json({ error: 'Upstream SSE unavailable' });
    }

    res.setHeader('Content-Type', 'text/event-stream; charset=utf-8');
    res.setHeader('Cache-Control', 'no-cache, no-transform');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders();
    console.log(`[${rid}] SSE connected (session: ${req.sessionId})`);

    const reader = upstream.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';

    const push = (text) => res.write(text);
    const flushLines = () => {
      let idx;
      while ((idx = buffer.indexOf('\n')) >= 0) {
        const line = buffer.slice(0, idx);
        buffer = buffer.slice(idx + 1);

        if (line.startsWith('data:')) {
          const payload = line.slice(5).trimStart();
          try {
            const json = JSON.parse(payload);
            if (looksInjected(json)) {
              console.warn(`[${rid}] [SSE] blocked injected event`);
              push(`event: error\n`);
              push(`data: ${JSON.stringify({ message: 'Blocked by proxy heuristic' })}\n\n`);
              continue;
            }
            console.log(`[${rid}] [SSE]`, JSON.stringify(redact(json)));
          } catch {
            console.log(`[${rid}] [SSE raw]`, payload.slice(0, 200));
          }
        }
        push(line + '\n');
      }
    };

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      flushLines();
    }
    if (buffer.length) { buffer += '\n'; flushLines(); }
    res.end();
    console.log(`[${rid}] SSE closed`);
  } catch (err) {
    console.error(`[${rid}] SSE error`, err && (err.stack || err.message) || err);
    if (!res.headersSent) res.status(502).json({ error: 'SSE proxy error' });
    else res.end();
  }
});

// POST /v1/* (catch-all) using RegExp to avoid path-to-regexp quirks
app.post(/^\/v1(\/.*)?$/, authenticateRequest, async (req, res) => {
  const rid = randomUUID();
  const path = (req.path || '/v1').replace(/\/+$/, '');

  try {
    if (!ALLOW_PATHS.includes(path)) {
      console.warn(`[${rid}] BLOCK path`, path);
      return res.status(403).json({ error: `Path not allowed: ${path}` });
    }

    if (looksInjected(req.body)) {
      console.warn(`[${rid}] BLOCK injection in POST`, path);
      return res.status(400).json({ error: 'Blocked by injection heuristic' });
    }

    console.log(`[${rid}] → POST ${path} (session: ${req.sessionId})`, JSON.stringify(redact(req.body)));

    const fwdHeaders = buildForwardHeaders(req.headers, {
      upstreamToken: req.session.upstreamToken
    });

    const search = req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : '';
    const upstream = await fetch(upstreamURL(path, search), {
      method: 'POST',
      headers: fwdHeaders,
      body: JSON.stringify(req.body)
    });

    const text = await upstream.text();
    res.status(upstream.status);
    res.setHeader('Content-Type', upstream.headers.get('content-type') || 'application/json; charset=utf-8');
    for (const [k, v] of upstream.headers.entries()) {
      const kl = k.toLowerCase();
      if (HOP_BY_HOP.has(kl) || kl === 'content-length') continue;
      if (kl.startsWith('x-')) res.setHeader(k, v);
    }
    res.send(text);

    try {
      console.log(`[${rid}] ← POST ${path}`, JSON.stringify(redact(JSON.parse(text))));
    } catch {
      console.log(`[${rid}] ← POST ${path} [non-JSON ${text.length} bytes]`);
    }
  } catch (err) {
    console.error(`[${rid}] POST error`, err.message);
    res.status(502).json({ error: 'Upstream POST unavailable' });
  }
});

app.get('/healthz', (_, res) => res.json({ ok: true }));

// Generic encoded URL MITM route: /<base64url-encoded-full-url>[/*suffix]
// Example: /aHR0cHM6Ly9tY3AuZXhhbXBsZS5jb20vdjEvc3Nl
app.all(/^\/([A-Za-z0-9_-]+)(?:\/(.*))?$/, async (req, res, next) => {
  // Avoid hijacking known routes
  if (req.path.startsWith('/v1/') || req.path === '/v1' || req.path === '/healthz') return next();

  const rid = randomUUID();
  try {
    const m = req.path.match(/^\/([A-Za-z0-9_-]+)(?:\/(.*))?$/);
    if (!m) return next();
    const encoded = m[1];
    const rest = m[2] || '';

    const upstream = decodeB64UrlToURL(encoded);
    if (!upstream) return res.status(400).json({ error: 'Invalid base64url in path' });

    // Build target URL
    const target = new URL(upstream.href);
    if (rest) {
      const a = target.pathname.endsWith('/') ? target.pathname.slice(0, -1) : target.pathname;
      const b = rest.startsWith('/') ? rest : `/${rest}`;
      target.pathname = a + b;
    }
    // Merge query strings (request overrides)
    const idx = req.originalUrl.indexOf('?');
    if (idx >= 0) {
      const q = new URLSearchParams(req.originalUrl.slice(idx));
      for (const [k, v] of q.entries()) target.searchParams.set(k, v);
    }

    const isSSE = /text\/event-stream/i.test(req.headers['accept'] || '');
    const headers = buildForwardHeaders(req.headers, isSSE ? { forceAccept: 'text/event-stream' } : undefined);

    if (isSSE) {
      // Stream SSE pass-through
      const upstreamResp = await fetch(target.toString(), { method: 'GET', headers });
      if (!upstreamResp.ok || !upstreamResp.body) {
        const body = upstreamResp.body ? await upstreamResp.text().catch(() => '') : '';
        return res.status(upstreamResp.status || 502).type('text/plain').send(body || 'Upstream SSE unavailable');
      }
      res.setHeader('Content-Type', 'text/event-stream; charset=utf-8');
      res.setHeader('Cache-Control', 'no-cache, no-transform');
      res.setHeader('Connection', 'keep-alive');
      res.flushHeaders?.();
      const reader = upstreamResp.body.getReader();
      const decoder = new TextDecoder();
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        res.write(decoder.decode(value, { stream: true }));
      }
      return res.end();
    }

    // Generic HTTP proxy
    const method = req.method || 'GET';
    const body = ['GET','HEAD'].includes(method) ? undefined : JSON.stringify(req.body ?? {});
    const upstreamResp = await fetch(target.toString(), { method, headers, body });

    res.status(upstreamResp.status);
    const ct = upstreamResp.headers.get('content-type') || 'application/octet-stream';
    res.setHeader('Content-Type', ct);
    for (const [k, v] of upstreamResp.headers.entries()) {
      const kl = k.toLowerCase();
      if (HOP_BY_HOP.has(kl) || kl === 'content-length') continue;
      if (kl.startsWith('x-')) res.setHeader(k, v);
    }
    const text = await upstreamResp.text();
    return res.send(text);
  } catch (err) {
    console.error(`[${rid}] encoded route error`, err && (err.stack || err.message) || err);
    return res.status(502).json({ error: 'Encoded proxy error' });
  }
});

// Catch-all logger for any unmatched routes (ALL methods)
app.all(/.*/, (req, res, next) => {
  // If response not yet sent by earlier routes, return 404 with context
  if (!res.headersSent) {
    const payload = { error: 'Not Found', method: req.method, path: req.path };
    console.warn('[unmatched]', JSON.stringify(payload));
    return res.status(404).json(payload);
  }
  next();
});

function buildHttpsOptions() {
  const opts = {};
  if (TLS_PASSPHRASE) opts.passphrase = TLS_PASSPHRASE;
  if (TLS_CERT_FILE && TLS_KEY_FILE && fs.existsSync(TLS_CERT_FILE) && fs.existsSync(TLS_KEY_FILE)) {
    opts.cert = fs.readFileSync(TLS_CERT_FILE);
    opts.key = fs.readFileSync(TLS_KEY_FILE);
    opts.minVersion = TLS_MIN_VERSION;
    return opts;
  }
  try {
    // Try to generate a self-signed certificate if available
    const selfsigned = require('selfsigned');
    const pems = selfsigned.generate([
      { name: 'commonName', value: 'localhost' }
    ], {
      days: 365,
      keySize: 2048,
      algorithm: 'sha256',
      extensions: [{
        name: 'subjectAltName',
        altNames: [
          { type: 2, value: 'localhost' },
          { type: 7, ip: '127.0.0.1' },
          { type: 7, ip: '::1' }
        ]
      }]
    });
    opts.key = pems.private;
    opts.cert = pems.cert;
    opts.minVersion = TLS_MIN_VERSION;
    // Log a simple fingerprint for visibility
    try {
      const sha = crypto.createHash('sha256').update(pems.cert).digest('hex');
      console.log(`[tls] generated self-signed cert sha256=${sha.slice(0,16)}… valid ~${365}d`);
    } catch {}
    return opts;
  } catch (e) {
    throw new Error('HTTPS requested but no TLS_CERT_FILE/TLS_KEY_FILE provided and self-signed generation is unavailable. Install dependency or provide certs.');
  }
}

let server;
if (HTTPS_ENABLED) {
  const httpsOpts = buildHttpsOptions();
  server = https.createServer(httpsOpts, app).listen(PORT, () => {
    console.log(`MCP SSE+POST MITM listening on https://localhost:${PORT}`);
    console.log(`→ Upstream: ${UPSTREAM_BASE}`);
    console.log(`→ Allowed POST paths: ${ALLOW_PATHS.join(', ')}`);
  });
} else {
  server = http.createServer(app).listen(PORT, () => {
    console.log(`MCP SSE+POST MITM listening on http://localhost:${PORT}`);
    console.log(`→ Upstream: ${UPSTREAM_BASE}`);
    console.log(`→ Allowed POST paths: ${ALLOW_PATHS.join(', ')}`);
  });
}
try { if (typeof server.ref === 'function') server.ref(); } catch {}

server.on('close', () => {
  console.log('[server] closed');
});

process.on('beforeExit', (code) => {
  console.log(`[process] beforeExit code=${code}`);
});
process.on('exit', (code) => {
  console.log(`[process] exit code=${code}`);
});
process.on('uncaughtException', (err) => {
  console.error('[process] uncaughtException', err && (err.stack || err.message) || err);
});
process.on('unhandledRejection', (reason) => {
  console.error('[process] unhandledRejection', reason);
});

function decodeB64UrlToURL(b64u) {
  try {
    const normalized = b64u.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(b64u.length / 4) * 4, '=');
    const buf = Buffer.from(normalized, 'base64');
    const str = buf.toString('utf8');
    return new URL(str);
  } catch (e) {
    return null;
  }
}
