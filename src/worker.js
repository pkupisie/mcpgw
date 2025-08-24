// Cloudflare Worker: Prod-grade MITM for MCP (SSE, HTTP, WebSocket)
// Usage: https://your.worker.host/<base64url-encoded-full-upstream-url>[?extra=query]
// Example: encode("https://mcp.atlassian.com/v1/sse") -> path segment
// Notes:
// - Supports SSE pass-through (text/event-stream) with streaming
// - Supports generic HTTP proxying for all methods
// - Supports WebSocket tunneling when request/target upgrades to websocket
// - Filters hop-by-hop headers, echoes CORS if enabled
// - Only allows https/wss upstreams by default (configurable)

export default {
  async fetch(request, env, ctx) {
    const rid = (globalThis.crypto?.randomUUID?.() || Math.random().toString(36).slice(2)).substring(0, 12);
    const start = Date.now();
    const lvl = logLevel(env);
    
    // Log worker initialization info on first request (helps verify deployment)
    if (!globalThis.workerInitLogged) {
      console.log(`[${new Date().toISOString()}] [INFO ] [INIT] worker:started | domain_root=${env.DOMAIN_ROOT || 'mcp.copernicusone.com'} log_level=${lvl} observability=enabled`);
      globalThis.workerInitLogged = true;
    }
    try {
      const url = new URL(request.url);
      // Prepare headers for logging
      const incomingHeaders = {};
      for (const [k, v] of request.headers.entries()) {
        // Show authorization for debugging (security risk - remove in production)
        incomingHeaders[k] = k.toLowerCase() === 'cookie' ? 'REDACTED' : v;
      }
      
      log(rid, 'info', 'request:start', {
        method: request.method,
        path: url.pathname,
        search: url.search,
        ip: request.headers.get('cf-connecting-ip') || 'unknown',
        cf_ray: request.headers.get('cf-ray') || 'none',
        headers: incomingHeaders,
      }, lvl);
      
      // Also log at debug level for consistency
      log(rid, 'debug', 'request:headers', incomingHeaders, lvl);

      // Check if this is the landing page subdomain
      const isLandingDomain = url.hostname.toLowerCase() === 'mcp.copernicusone.com';
      
      // Health and root info - only show on landing domain
      if (isLandingDomain && (url.pathname === '/' || url.pathname === '' || url.pathname === '/index.html')) {
        // Simple content-negotiation: if client prefers JSON, return JSON; else HTML landing
        const accept = request.headers.get('accept') || '';
        if (/application\/json/i.test(accept)) {
          return json({
            ok: true,
            message: 'MCP MITM proxy is up',
            usage: 'GET/POST/WS: /<base64url-encoded-full-upstream-url>',
            example: '/aHR0cHM6Ly9tY3AuYXRsYXNzaWFuLmNvbS92MS9zc2U',
            domain_root: env.DOMAIN_ROOT || 'copernicusone.com',
            domain_usage: 'https://<base64(domain)>.{domain_root}/',
          });
        }
        const resp = landingHTML(url, env);
        log(rid, 'info', 'route:landing', { path: url.pathname }, lvl);
        
        const elapsed = Date.now() - start;
        
        // Log response headers
        const respHeadersObj = {};
        for (const [k, v] of resp.headers.entries()) {
          respHeadersObj[k] = k.toLowerCase() === 'set-cookie' ? 'REDACTED' : v;
        }
        
        log(rid, 'info', 'response:complete', {
          status: 200,
          elapsed_ms: elapsed,
          route: 'landing',
          content_type: 'text/html',
          headers: respHeadersObj,
        }, lvl);
        
        return resp;
      }
      if (isLandingDomain && url.pathname === '/encode') {
        const target = url.searchParams.get('url') || '';
        if (!target) return badRequest('Missing url param');
        
        // Handle both domain names and full URLs
        let targetUrl = target;
        let domainOnly = target;
        
        try {
          if (!target.startsWith('http://') && !target.startsWith('https://')) {
            targetUrl = 'https://' + target;
          }
          const u = new URL(targetUrl);
          domainOnly = u.hostname;
        } catch (e) {
          return badRequest('Invalid domain or URL input');
        }
        
        // Use base32 encoding for the domain name (DNS-safe)
        const domainRoot = env.DOMAIN_ROOT || 'copernicusone.com';
        const encoded = base32Encode(domainOnly);
        const domain_url = `https://${encoded}.${domainRoot}/`;
        
        // Also provide full URL base32 version
        const fullB32 = base32Encode(targetUrl);
        const fullB32Host = b32ToHost(fullB32, domainRoot);
        const full_url = `https://${fullB32Host}/`;
        
        const resp = json({ 
          original: target, 
          domain: domainOnly,
          base32_encoded: encoded,
          domain_url: domain_url,
          full_base32_encoded: fullB32,
          full_url: full_url
        });
        
        log(rid, 'info', 'route:encode', { target, domain: domainOnly, encoded: encoded.substring(0, 20) + '...' }, lvl);
        
        const elapsed = Date.now() - start;
        
        // Log response headers
        const respHeadersObj = {};
        for (const [k, v] of resp.headers.entries()) {
          respHeadersObj[k] = k.toLowerCase() === 'set-cookie' ? 'REDACTED' : v;
        }
        
        log(rid, 'info', 'response:complete', {
          status: 200,
          elapsed_ms: elapsed,
          route: 'encode',
          content_type: 'application/json',
          headers: respHeadersObj,
        }, lvl);
        
        return resp;
      }
      if (isLandingDomain && url.pathname === '/healthz') {
        log(rid, 'debug', 'route:healthz', {}, lvl);
        const resp = json({ ok: true, timestamp: new Date().toISOString(), log_level: lvl });
        
        const elapsed = Date.now() - start;
        
        // Log response headers
        const respHeadersObj = {};
        for (const [k, v] of resp.headers.entries()) {
          respHeadersObj[k] = k.toLowerCase() === 'set-cookie' ? 'REDACTED' : v;
        }
        
        log(rid, 'info', 'response:complete', {
          status: 200,
          elapsed_ms: elapsed,
          route: 'healthz',
          content_type: 'application/json',
          headers: respHeadersObj,
        }, lvl);
        
        return resp;
      }

      // CORS preflight: only when Access-Control-Request-Method is present
      if (request.method === 'OPTIONS' && request.headers.get('access-control-request-method')) {
        const resp = corsPreflight(request);
        log(rid, 'info', 'cors:preflight', {
          origin: request.headers.get('origin') || 'none',
          method: request.headers.get('access-control-request-method') || 'GET',
        }, lvl);
        
        const elapsed = Date.now() - start;
        
        // Log response headers
        const respHeadersObj = {};
        for (const [k, v] of resp.headers.entries()) {
          respHeadersObj[k] = k.toLowerCase() === 'set-cookie' ? 'REDACTED' : v;
        }
        
        log(rid, 'info', 'response:complete', {
          status: 204,
          elapsed_ms: elapsed,
          route: 'cors-preflight',
          headers: respHeadersObj,
        }, lvl);
        
        return resp;
      }

      // 1) Host-encoded routing: <b32-encoded>[.<more>].<DOMAIN_ROOT>
      const hostRoute = parseHostEncodedUpstream(url.hostname, env);
      if (hostRoute) {
        const upstreamURL = selectUpstreamForRequest(hostRoute.upstreamBase, url, request);
        log(rid, 'info', 'route:host-encoded', {
          host: url.hostname,
          upstream: redactURL(upstreamURL).toString(),
          path: url.pathname,
        }, lvl);
        // WebSocket tunneling for host-encoded routing
        const upgrade = request.headers.get('upgrade');
        if (upgrade && upgrade.toLowerCase() === 'websocket') {
          log(rid, 'info', 'ws:connect:start', { 
            upstream: redactURL(upstreamURL).toString(),
            upgrade: upgrade,
          }, lvl);
          const resp = await handleWebSocket(request, upstreamURL, env);
          log(rid, 'info', 'ws:connect:established', { 
            upstream: redactURL(upstreamURL).toString(),
          }, lvl);
          return resp;
        }
        const response = await proxyFetch(upstreamURL, request, rid, start, lvl);
        
        // Log final response completion
        const elapsed = Date.now() - start;
        
        // Log response headers
        const finalRespHeaders = {};
        for (const [k, v] of response.headers.entries()) {
          finalRespHeaders[k] = k.toLowerCase() === 'set-cookie' ? 'REDACTED' : v;
        }
        
        log(rid, 'info', 'response:complete', {
          status: response.status,
          elapsed_ms: elapsed,
          route: 'host-encoded',
          content_type: response.headers.get('content-type') || 'none',
          headers: finalRespHeaders,
        }, lvl);
        
        return response;
      }

      // No host-encoded upstream and not a known local route
      log(rid, 'warn', 'route:missing-upstream', { 
        host: url.hostname, 
        path: url.pathname,
        domain_root: env.DOMAIN_ROOT || 'mcp.copernicusone.com',
      }, lvl);
      
      // Log final response
      const elapsed = Date.now() - start;
      const errResp = json({ error: 'Missing host-encoded upstream', hint: 'Use the landing page to generate a base32 host under your domain root.' }, 400);
      
      // Log response headers
      const errRespHeaders = {};
      for (const [k, v] of errResp.headers.entries()) {
        errRespHeaders[k] = k.toLowerCase() === 'set-cookie' ? 'REDACTED' : v;
      }
      
      log(rid, 'info', 'response:complete', {
        status: 400,
        elapsed_ms: elapsed,
        route: 'missing-upstream',
        headers: errRespHeaders,
      }, lvl);
      
      return errResp;
    } catch (err) {
      log(rid, 'error', 'proxy:error', { 
        message: String(err?.message || err),
        stack: err?.stack ? err.stack.split('\n')[0] : 'no-stack',
        url: request.url,
      }, 'debug');
      console.error(`[ERROR] [${rid}] Full stack trace:`, err);
      return json({ error: 'Proxy error', detail: String(err?.message || err) }, 502);
    }
  }
}

// --- Helpers ---

function splitEncodedPath(pathname) {
  const clean = pathname.startsWith('/') ? pathname.slice(1) : pathname;
  if (!clean) return { encoded: '', restPath: '' };
  const idx = clean.indexOf('/');
  if (idx === -1) return { encoded: clean, restPath: '' };
  return { encoded: clean.slice(0, idx), restPath: clean.slice(idx + 1) };
}


function joinPaths(basePath, tail) {
  const a = basePath.endsWith('/') ? basePath.slice(0, -1) : basePath;
  const b = tail.startsWith('/') ? tail : `/${tail}`;
  return a + b;
}

function allowProtocol(protocol, env) {
  const allowed = (env.ALLOW_PROTOCOLS || 'https:,wss:').split(',').map(s => s.trim());
  return allowed.includes(protocol);
}

async function handleWebSocket(clientRequest, upstreamURL, env) {
  const wsRid = (globalThis.crypto?.randomUUID?.() || Math.random().toString(36).slice(2)).substring(0, 8);
  console.log(`[${new Date().toISOString()}] [INFO ] [${wsRid}] ws:handler:start | upstream=${redactURL(upstreamURL).toString()}`);
  
  // Accept client socket
  const pair = new WebSocketPair();
  const clientSocket = pair[0];
  const workerSocket = pair[1];
  clientSocket.accept();
  console.log(`[${new Date().toISOString()}] [DEBUG] [${wsRid}] ws:client:accepted`);

  // Connect to upstream as a WebSocket client
  const headers = new Headers();
  // Forward selected headers only. Cloudflare adds required headers for WS upgrade.
  copyForwardableHeaders(clientRequest.headers, headers);
  headers.set('Connection', 'upgrade');
  headers.set('Upgrade', 'websocket');

  let upstreamResp;
  try {
    console.log(`[${new Date().toISOString()}] [DEBUG] [${wsRid}] ws:upstream:connecting | url=${redactURL(upstreamURL).toString()}`);
    upstreamResp = await fetch(upstreamURL.toString(), { method: 'GET', headers });
  } catch (e) {
    console.error(`[${new Date().toISOString()}] [ERROR] [${wsRid}] ws:upstream:error | message=${e.message}`);
    clientSocket.close(1011, 'Upstream connect error');
    return new Response(null, { status: 101, webSocket: workerSocket });
  }
  const upstreamSocket = upstreamResp.webSocket;
  if (!upstreamSocket) {
    console.error(`[${new Date().toISOString()}] [ERROR] [${wsRid}] ws:upstream:no-socket | status=${upstreamResp.status}`);
    clientSocket.close(1011, 'No upstream websocket');
    return new Response(null, { status: 101, webSocket: workerSocket });
  }
  upstreamSocket.accept();
  console.log(`[${new Date().toISOString()}] [INFO ] [${wsRid}] ws:tunnel:established`);

  // Bidirectional piping with logging
  let msgCount = { fromUpstream: 0, fromClient: 0 };
  
  upstreamSocket.addEventListener('message', (evt) => {
    msgCount.fromUpstream++;
    try { 
      clientSocket.send(evt.data);
      if (msgCount.fromUpstream % 100 === 0) {
        console.log(`[${new Date().toISOString()}] [DEBUG] [${wsRid}] ws:messages | fromUpstream=${msgCount.fromUpstream} fromClient=${msgCount.fromClient}`);
      }
    } catch (e) { 
      console.error(`[${new Date().toISOString()}] [ERROR] [${wsRid}] ws:client:send-failed | error=${e.message}`);
      try { upstreamSocket.close(1011, 'client send failed'); } catch {} 
    }
  });
  
  clientSocket.addEventListener('message', (evt) => {
    msgCount.fromClient++;
    try { 
      upstreamSocket.send(evt.data);
      if (msgCount.fromClient % 100 === 0) {
        console.log(`[${new Date().toISOString()}] [DEBUG] [${wsRid}] ws:messages | fromUpstream=${msgCount.fromUpstream} fromClient=${msgCount.fromClient}`);
      }
    } catch (e) { 
      console.error(`[${new Date().toISOString()}] [ERROR] [${wsRid}] ws:upstream:send-failed | error=${e.message}`);
      try { clientSocket.close(1011, 'upstream send failed'); } catch {} 
    }
  });
  
  upstreamSocket.addEventListener('close', (evt) => {
    console.log(`[${new Date().toISOString()}] [INFO ] [${wsRid}] ws:upstream:closed | code=${evt.code} reason="${evt.reason || 'none'}" totalMessages=${msgCount.fromUpstream + msgCount.fromClient}`);
    try { clientSocket.close(evt.code, evt.reason); } catch {}
  });
  
  clientSocket.addEventListener('close', (evt) => {
    console.log(`[${new Date().toISOString()}] [INFO ] [${wsRid}] ws:client:closed | code=${evt.code} reason="${evt.reason || 'none'}" totalMessages=${msgCount.fromUpstream + msgCount.fromClient}`);
    try { upstreamSocket.close(evt.code, evt.reason); } catch {}
  });
  
  upstreamSocket.addEventListener('error', (err) => {
    console.error(`[${new Date().toISOString()}] [ERROR] [${wsRid}] ws:upstream:error | error=${err.message || 'unknown'}`);
    try { clientSocket.close(1011, 'upstream error'); } catch {}
  });
  
  clientSocket.addEventListener('error', (err) => {
    console.error(`[${new Date().toISOString()}] [ERROR] [${wsRid}] ws:client:error | error=${err.message || 'unknown'}`);
    try { upstreamSocket.close(1011, 'client error'); } catch {}
  });

  return new Response(null, { status: 101, webSocket: workerSocket });
}

async function buildUpstreamInit(request, upstreamURL, env) {
  const method = request.method.toUpperCase();
  const headers = filterRequestHeaders(request.headers);
  
  // Set the correct Host header for the upstream
  if (upstreamURL) {
    const upstreamHost = new URL(upstreamURL).hostname;
    headers.set('Host', upstreamHost);
  }
  
  const init = { method, headers };

  if (!['GET', 'HEAD'].includes(method)) {
    // Pass-through body as-is (exact stream) without parsing or rebuilding
    init.body = request.body;
  }

  // Optional timeout via cf.connectTimeout? Not public; rely on platform defaults.
  return init;
}

function corsPreflight(request) {
  const origin = request.headers.get('origin');
  const reqHeaders = request.headers.get('Access-Control-Request-Headers') || '';
  const reqMethod = request.headers.get('Access-Control-Request-Method') || 'GET';
  const headers = new Headers();
  
  // Echo the exact origin for credentials support (not *)
  headers.set('Access-Control-Allow-Origin', origin || '*');
  headers.set('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
  
  // Always include Authorization, Content-Type, and mcp-session-id in allowed headers
  const allowedHeaders = new Set(['authorization', 'content-type', 'mcp-session-id']);
  if (reqHeaders) {
    reqHeaders.split(',').forEach(h => allowedHeaders.add(h.trim().toLowerCase()));
  }
  headers.set('Access-Control-Allow-Headers', Array.from(allowedHeaders).join(', '));
  
  // Add credentials support
  if (origin) {
    headers.set('Access-Control-Allow-Credentials', 'true');
  }
  
  headers.set('Access-Control-Max-Age', '600');
  headers.set('Access-Control-Expose-Headers', 'mcp-session-id');
  
  return new Response(null, { status: 204, headers });
}

function filterRequestHeaders(inHeaders) {
  // Only drop hop-by-hop headers that MUST be removed per HTTP spec
  // Keep everything else for full transparency
  const hopByHop = new Set([
    'connection',
    'keep-alive', 
    'proxy-authenticate',
    'proxy-authorization',
    'te',
    'trailer',
    'transfer-encoding',
    'upgrade',
    'host' // We'll set this based on the upstream URL
  ]);
  const out = new Headers();
  for (const [k, v] of inHeaders.entries()) {
    const key = k.toLowerCase();
    if (hopByHop.has(key)) continue;
    out.set(k, v); // Pass everything else through, including CF headers
  }
  return out;
}

function copyForwardableHeaders(inHeaders, outHeaders) {
  const filtered = filterRequestHeaders(inHeaders);
  for (const [k, v] of filtered.entries()) outHeaders.set(k, v);
}

function filterResponseHeaders(inHeaders, { forceSSE = false, origin = null } = {}) {
  // Only drop hop-by-hop headers that MUST be removed per HTTP spec
  const hopByHop = new Set([
    'connection',
    'keep-alive',
    'proxy-authenticate',
    'proxy-authorization',
    'te',
    'trailer',
    'transfer-encoding',
    'upgrade'
  ]);
  const out = new Headers();
  for (const [k, v] of inHeaders.entries()) {
    const key = k.toLowerCase();
    if (hopByHop.has(key)) continue;
    out.set(k, v); // Pass everything else through transparently
  }
  
  // Handle CORS properly for credentials
  if (!out.has('Access-Control-Allow-Origin')) {
    // Echo exact origin for credentials support, fallback to * if no origin
    out.set('Access-Control-Allow-Origin', origin || '*');
    out.set('Vary', addVary(out.get('Vary'), 'Origin'));
  }
  
  // Add credentials support if origin is present
  if (origin && !out.has('Access-Control-Allow-Credentials')) {
    out.set('Access-Control-Allow-Credentials', 'true');
  }
  
  // Ensure mcp-session-id is exposed
  if (!out.has('Access-Control-Expose-Headers')) {
    out.set('Access-Control-Expose-Headers', 'mcp-session-id');
  }
  
  return out;
}

function addVary(current, add) {
  const set = new Set((current || '').split(',').map(s => s.trim()).filter(Boolean));
  set.add(add);
  return Array.from(set).join(', ');
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      'Access-Control-Allow-Origin': '*',
    }
  });
}

function badRequest(msg) {
  return json({ error: msg }, 400);
}

// --- Logging helpers ---
function logLevel(env) {
  const level = (env?.LOG_LEVEL || 'debug').toLowerCase();
  const order = { debug: 10, info: 20, warn: 30, error: 40, silent: 100 };
  return order[level] ? level : 'debug';
}
function shouldLog(requested, current) {
  const order = { debug: 10, info: 20, warn: 30, error: 40, silent: 100 };
  return order[requested] >= order[current];
}
function log(rid, level, event, data, currentLevel = 'debug') {
  if (!shouldLog(level, currentLevel)) return;
  try {
    const ts = new Date().toISOString();
    const levelStr = level.toUpperCase().padEnd(5);
    // Format data as key=value pairs
    let dataStr = '';
    if (data && typeof data === 'object') {
      const pairs = [];
      for (const [key, value] of Object.entries(data)) {
        if (value !== null && value !== undefined) {
          const val = typeof value === 'object' ? JSON.stringify(value) : String(value);
          pairs.push(`${key}=${val}`);
        }
      }
      if (pairs.length > 0) {
        dataStr = ' | ' + pairs.join(' ');
      }
    }
    console.log(`[${ts}] [${levelStr}] [${rid}] ${event}${dataStr}`);
  } catch (e) {
    console.log(`[LOG ERROR] Failed to log: ${event} rid=${rid}`);
  }
}
function headersToObject(headers, max = 64) {
  const out = {};
  let i = 0;
  for (const [k, v] of headers.entries()) { out[k] = v; if (++i >= max) break; }
  return out;
}
function redactHeadersObj(obj) {
  const out = {};
  for (const k in obj) {
    const kl = k.toLowerCase();
    if (kl === 'authorization' || kl === 'proxy-authorization') out[k] = '***';
    else if (kl === 'cookie' || kl === 'set-cookie') out[k] = '***';
    else out[k] = obj[k];
  }
  return out;
}

// Redact sensitive query values in logged URLs (e.g., tokens)
function redactURL(u) {
  try {
    const url = new URL(u.toString());
    const sensitive = ['access_token','token','code','client_secret','assertion','credential','auth','authorization'];
    for (const key of sensitive) {
      if (url.searchParams.has(key)) url.searchParams.set(key, '***');
    }
    return url;
  } catch {
    return u;
  }
}

// --- Host-encoded routing helpers ---
function parseHostEncodedUpstream(hostname, env) {
  const root = (env.DOMAIN_ROOT || 'copernicusone.com').toLowerCase();
  const host = (hostname || '').toLowerCase();
  if (!host.endsWith('.' + root)) return null;
  const parts = host.split('.');
  const rootParts = root.split('.');
  if (parts.length <= rootParts.length) return null; // it's the root domain itself
  const encodedLabels = parts.slice(0, parts.length - rootParts.length);
  
  // For single-label subdomains, try base32 decoding as domain name
  if (encodedLabels.length === 1) {
    const b32Label = encodedLabels[0];
    const decodedDomain = base32Decode(b32Label);
    if (decodedDomain) {
      // Check if it's a valid domain name (contains dots, no protocol)
      if (decodedDomain.includes('.') && !decodedDomain.includes('://')) {
        try {
          // The decoded value is just a domain name, so we need to add https://
          const url = new URL('https://' + decodedDomain);
          return { upstreamBase: url };
        } catch {
          // Not a valid domain, fall through
        }
      }
      // Check if it's a full URL
      if (decodedDomain.includes('://')) {
        try {
          const url = new URL(decodedDomain);
          return { upstreamBase: url };
        } catch {
          // Not a valid URL, fall through
        }
      }
    }
  }
  
  // For multi-label subdomains (b32-prefixed), join and decode as full URL
  let joined = encodedLabels.join('');
  if (joined.startsWith('b32-')) joined = joined.slice(4);
  if (!joined) return null;
  const decoded = base32Decode(joined);
  if (!decoded) return null;
  try {
    const url = new URL(decoded);
    return { upstreamBase: url };
  } catch { return null; }
}


function selectUpstreamForRequest(upstreamBase, reqUrl, request) {
  // Always preserve the incoming path when upstream is just a domain
  // Only use the exact upstream path if it was encoded as a full URL with a path
  const u = new URL(upstreamBase.href);
  
  // If the upstream has no path (just domain) or is root (/), use incoming path
  if (!u.pathname || u.pathname === '/') {
    u.pathname = reqUrl.pathname;
  }
  // Otherwise, the upstream was encoded with a specific path, so use it
  
  // Always merge query params from incoming request
  if (reqUrl.search) {
    const qs = new URLSearchParams(reqUrl.search);
    for (const [k, v] of qs.entries()) u.searchParams.set(k, v);
  }
  
  return u;
}

async function proxyFetch(upstreamURL, request, rid, start, lvl, initOpt) {
  const init = initOpt || (await buildUpstreamInit(request, upstreamURL));
  
  // Prepare headers for logging
  const reqHeadersObj = {};
  for (const [k, v] of init.headers.entries()) {
    // Show authorization for debugging (security risk - remove in production)
    reqHeadersObj[k] = v;
  }
  
  log(rid, 'info', 'upstream:request', {
    method: init.method,
    url: redactURL(upstreamURL).toString(),
    body_len: request.headers.get('content-length') || '0',
    headers: reqHeadersObj,
  }, lvl);
  
  // Also log at debug level for consistency
  log(rid, 'debug', 'upstream:request-headers', reqHeadersObj, lvl);
  
  // Log request body if it's not too large and it's JSON
  if (init.body && request.headers.get('content-type')?.includes('application/json')) {
    try {
      const bodyText = await request.clone().text();
      if (bodyText.length < 5000) { // Only log if under 5KB
        log(rid, 'debug', 'upstream:request-body', { body: bodyText }, lvl);
      }
    } catch (e) {
      // Body already read or other error, skip logging
    }
  }
  
  let upstreamResp;
  try {
    upstreamResp = await fetch(upstreamURL.toString(), init);
  } catch (err) {
    const elapsed = Date.now() - start;
    log(rid, 'error', 'upstream:fetch-failed', {
      error: err.message,
      elapsed_ms: elapsed,
      url: redactURL(upstreamURL).toString(),
    }, lvl);
    throw err;
  }
  
  const contentType = upstreamResp.headers.get('content-type') || '';
  const contentLength = upstreamResp.headers.get('content-length') || 'stream';
  const isSSE = contentType.includes('text/event-stream');
  const origin = request.headers.get('origin');
  const respHeaders = filterResponseHeaders(upstreamResp.headers, { origin });
  const elapsed = Date.now() - start;
  
  // Prepare headers for logging
  const respHeadersObj = {};
  for (const [k, v] of upstreamResp.headers.entries()) {
    respHeadersObj[k] = k.toLowerCase() === 'set-cookie' ? 'REDACTED' : v;
  }
  
  log(rid, 'info', 'upstream:response', {
    status: upstreamResp.status,
    status_text: upstreamResp.statusText || 'OK',
    content_type: contentType || 'none',
    content_length: contentLength,
    sse: isSSE ? 'yes' : 'no',
    elapsed_ms: elapsed,
    headers: respHeadersObj,
  }, lvl);
  
  // Also log at debug level for consistency
  log(rid, 'debug', 'upstream:response-headers', respHeadersObj, lvl);
  
  // Log filtered response headers that will be sent to client
  const filteredHeadersObj = {};
  for (const [k, v] of respHeaders.entries()) {
    filteredHeadersObj[k] = k.toLowerCase() === 'set-cookie' ? 'REDACTED' : v;
  }
  log(rid, 'debug', 'client:response-headers', filteredHeadersObj, lvl);
  
  if (upstreamResp.status >= 400) {
    log(rid, 'warn', 'upstream:error-status', {
      status: upstreamResp.status,
      url: redactURL(upstreamURL).toString(),
      elapsed_ms: elapsed,
    }, lvl);
    
    // Log error response body for debugging
    if (contentType?.includes('application/json') || contentType?.includes('text/')) {
      try {
        const errorBody = await upstreamResp.clone().text();
        if (errorBody.length < 5000) { // Only log if under 5KB
          log(rid, 'debug', 'upstream:error-body', { body: errorBody }, lvl);
        }
      } catch (e) {
        // Body already read or other error, skip logging
      }
    }
  }
  
  return new Response(upstreamResp.body, {
    status: upstreamResp.status,
    statusText: upstreamResp.statusText,
    headers: respHeaders,
  });
}

// Base32 (RFC 4648, lowercase) without padding, suitable for host labels
const B32_ALPH = 'abcdefghijklmnopqrstuvwxyz234567';
function base32Encode(str) {
  const bytes = new TextEncoder().encode(str);
  let bits = 0, value = 0, output = '';
  for (let i = 0; i < bytes.length; i++) {
    value = (value << 8) | bytes[i];
    bits += 8;
    while (bits >= 5) {
      output += B32_ALPH[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += B32_ALPH[(value << (5 - bits)) & 31];
  return output;
}
function base32Decode(str) {
  try {
    const s = str.toLowerCase().replace(/[^a-z2-7]/g, '');
    let bits = 0, value = 0;
    const bytes = [];
    for (let i = 0; i < s.length; i++) {
      const idx = B32_ALPH.indexOf(s[i]);
      if (idx === -1) return null;
      value = (value << 5) | idx;
      bits += 5;
      if (bits >= 8) {
        bytes.push((value >>> (bits - 8)) & 255);
        bits -= 8;
      }
    }
    return new TextDecoder().decode(new Uint8Array(bytes));
  } catch { return null; }
}

function b32ToHost(b32, domainRoot) {
  const prefix = 'b32-';
  const max = 63;
  const segs = [];
  let s = b32;
  const firstLen = Math.min(max - prefix.length, s.length);
  segs.push(prefix + s.slice(0, firstLen));
  s = s.slice(firstLen);
  while (s.length) { segs.push(s.slice(0, max)); s = s.slice(max); }
  return segs.join('.') + '.' + domainRoot;
}


function html(body, status = 200) {
  const headers = new Headers({
    'Content-Type': 'text/html; charset=utf-8',
    'Cache-Control': 'no-store',
  });
  return new Response(body, { status, headers });
}

function toBase64Url(str) {
  const enc = new TextEncoder();
  const bytes = enc.encode(str);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  const b64 = btoa(bin);
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function escapeHtml(unsafe) {
  return unsafe
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

function landingHTML(url, env) {
  const origin = url.origin;
  const example = 'mcp.atlassian.com';
  const domainRoot = (env && env.DOMAIN_ROOT) || 'copernicusone.com';
  const targetParam = url.searchParams.get('url') || '';
  let preRendered = '';
  if (targetParam) {
    try {
      // Handle both domain names and full URLs
      let targetUrl = targetParam;
      if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
        targetUrl = 'https://' + targetUrl;
      }
      const u = new URL(targetUrl);
      
      // Use base32 encoding for the domain name (DNS-safe, case-insensitive)
      const domainOnly = u.hostname;
      const encoded = base32Encode(domainOnly);
      const domainUrl = `https://${encoded}.${domainRoot}/`;
      
      // Also show full URL base32 version for reference
      const fullB32 = base32Encode(u.toString());
      const fullB32Host = b32ToHost(fullB32, domainRoot);
      const fullB32Url = `https://${fullB32Host}/`;
      
      preRendered = `
        <div class="row grid">
          <div><div class="muted small">Domain</div><div class="code box" id="domain-input">${escapeHtml(domainOnly)}</div></div>
          <button class="btn" onclick="copy(qs('#domain-input').textContent)">Copy</button>
        </div>
        <div class="row grid">
          <div><div class="muted small">Encoded URL (Base32)</div><div class="code box" id="domain">${escapeHtml(domainUrl)}</div></div>
          <button class="btn" onclick="copy(qs('#domain').textContent)">Copy</button>
        </div>
        <div class="row grid">
          <div><div class="muted small">Full URL Encoded (Alternative)</div><div class="code box" id="b32domain">${escapeHtml(fullB32Url)}</div></div>
          <button class="btn" onclick="copy(qs('#b32domain').textContent)">Copy</button>
        </div>
        <div class="row">
          <div class="muted">Quick commands</div>
          <div class="box small code" style="overflow:auto">
            <div>$ curl -N ${escapeHtml(domainUrl)}</div>
            <div class="muted"># POST example</div>
            <div>$ curl -s ${escapeHtml(domainUrl)} -H "content-type: application/json" -d "{}"</div>
          </div>
        </div>
        <div class="row small muted">Tip: The encoded subdomain represents the target domain. Append paths as needed.</div>
      `;
    } catch {}
  }
  return html(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>MCP MITM Proxy</title>
  <style>
    :root { color-scheme: light dark; }
    body { font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 2rem; line-height: 1.45; }
    .wrap { max-width: 860px; margin: 0 auto; }
    h1 { font-size: 1.6rem; margin: 0 0 1rem; }
    input[type=text], input[type=url] { width: 100%; padding: .6rem .7rem; font-size: 1rem; border-radius: .5rem; border: 1px solid #bbb; background: transparent; }
    .row { margin: 1rem 0; }
    .muted { opacity: .75; font-size: .9rem; }
    code, .code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
    .box { border: 1px solid #bbb; border-radius: .5rem; padding: .75rem; }
    .btn { display: inline-block; padding: .45rem .7rem; border: 1px solid #777; border-radius: .375rem; cursor: pointer; background: transparent; }
    .grid { display: grid; grid-template-columns: 1fr auto; gap: .5rem; align-items: center; }
    .small { font-size: .85rem; }
    a { color: inherit; }
  </style>
  <script>
    const B32_ALPH = 'abcdefghijklmnopqrstuvwxyz234567';
    
    function base32Encode(str) {
      const bytes = new TextEncoder().encode(str);
      let bits = 0, value = 0, output = '';
      for (let i = 0; i < bytes.length; i++) {
        value = (value << 8) | bytes[i];
        bits += 8;
        while (bits >= 5) {
          output += B32_ALPH[(value >>> (bits - 5)) & 31];
          bits -= 5;
        }
      }
      if (bits > 0) output += B32_ALPH[(value << (5 - bits)) & 31];
      return output;
    }
    function qs(sel){ return document.querySelector(sel); }
    function copy(text){
      try { if (navigator.clipboard && navigator.clipboard.writeText) return navigator.clipboard.writeText(text); } catch {}
      try {
        const ta = document.createElement('textarea');
        ta.value = text; document.body.appendChild(ta); ta.select(); document.execCommand('copy'); document.body.removeChild(ta);
      } catch {}
    }
    function update(){
      const input = qs('#target');
      const raw = input.value.trim();
      const out = qs('#out');
      const domainRoot = '${domainRoot}';
      
      if(!raw){ 
        out.innerHTML = '<em class="muted">Enter a domain name to get started</em>'; 
        return; 
      }
      
      // Handle both domain names and full URLs
      let domain = raw;
      try {
        if (raw.startsWith('http://') || raw.startsWith('https://')) {
          const u = new URL(raw);
          domain = u.hostname;
        } else if (raw.includes('://')) {
          out.innerHTML = '<span style="color:#c00">Invalid URL protocol</span>'; 
          return;
        }
      } catch(e) {
        // Assume it's a domain name
      }
      
      // Generate the base32 encoded URL (DNS-safe, case-insensitive)
      const encoded = base32Encode(domain);
      const domainUrl = 'https://' + encoded + '.' + domainRoot + '/';
      
      out.innerHTML = \`
        <div class="row grid">
          <div><div class="muted small">Domain</div><div class="code box" id="domain-input">\${domain}</div></div>
          <button class="btn" onclick="copy(qs('#domain-input').textContent)">Copy</button>
        </div>
        <div class="row grid">
          <div><div class="muted small">Encoded URL</div><div class="code box" id="domain">\${domainUrl}</div></div>
          <button class="btn" onclick="copy(qs('#domain').textContent)">Copy</button>
        </div>
        <div class="row">
          <div class="muted">Quick commands</div>
          <div class="box small code" style="overflow:auto">
            <div>$ curl -N \${domainUrl}</div>
            <div class="muted"># POST example</div>
            <div>$ curl -s \${domainUrl} -H "content-type: application/json" -d "{}"</div>
          </div>
        </div>
        <div class="row small muted">Tip: The encoded subdomain represents the target domain. Append paths as needed.</div>
      \`;
    }
    addEventListener('DOMContentLoaded', () => {
      qs('#target').addEventListener('input', update);
      update();
    });
  </script>
  </head>
  <body>
    <div class="wrap">
      <h1>MCP MITM Proxy</h1>
      <div class="muted">Domain Root: <code>${domainRoot}</code></div>
      <form class="row" method="GET" action="/">
        <label for="target">Enter a domain name</label>
        <div class="grid">
          <input id="target" name="url" type="text" placeholder="e.g. ${example}" value="${escapeHtml(targetParam)}" spellcheck="false" required />
          <button class="btn" type="submit">Generate</button>
        </div>
        <div class="small muted">The domain will be encoded in base64 and used as a subdomain.</div>
      </form>
      <div id="out" class="row">${preRendered}</div>
      <div class="row small muted">API: <code>GET ${origin}/encode?url=&lt;domain&gt;</code> returns JSON with the encoded URL.</div>
    </div>
  </body>
  </html>`);
}
