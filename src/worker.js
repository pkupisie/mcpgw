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
      log(rid, 'info', 'request:start', {
        method: request.method,
        path: url.pathname,
        search: url.search,
        ip: request.headers.get('cf-connecting-ip') || 'unknown',
        cf_ray: request.headers.get('cf-ray') || 'none',
      }, lvl);
      
      log(rid, 'debug', 'request:headers', {
        origin: request.headers.get('origin'),
        accept: request.headers.get('accept'),
        content_type: request.headers.get('content-type'),
        ua: request.headers.get('user-agent'),
      }, lvl);

      // Health and root info
      if (url.pathname === '/' || url.pathname === '' || url.pathname === '/index.html') {
        // Simple content-negotiation: if client prefers JSON, return JSON; else HTML landing
        const accept = request.headers.get('accept') || '';
        if (/application\/json/i.test(accept)) {
          return json({
            ok: true,
            message: 'MCP MITM proxy is up',
            usage: 'GET/POST/WS: /<base64url-encoded-full-upstream-url>',
            example: '/aHR0cHM6Ly9tY3AuYXRsYXNzaWFuLmNvbS92MS9zc2U',
            domain_root: env.DOMAIN_ROOT || 'mcp.copernicusone.com',
            domain_usage: 'https://b32-<base32(url)>.{domain_root}/',
          });
        }
        const resp = landingHTML(url, env);
        log(rid, 'info', 'route:landing', { path: url.pathname }, lvl);
        
        const elapsed = Date.now() - start;
        log(rid, 'info', 'response:complete', {
          status: 200,
          elapsed_ms: elapsed,
          route: 'landing',
          content_type: 'text/html',
        }, lvl);
        
        return resp;
      }
      if (url.pathname === '/encode') {
        const target = url.searchParams.get('url') || '';
        if (!target) return badRequest('Missing url param');
        let encoded = '';
        try { encoded = toBase64Url(target); } catch (e) { return badRequest('Invalid URL input'); }
        const worker = `${url.origin}/${encoded}`;
        // Domain-encoded host output
        const domainRoot = env.DOMAIN_ROOT || 'mcp.copernicusone.com';
        const b32 = base32Encode(target);
        const host = b32ToHost(b32, domainRoot);
        const domain_url = `https://${host}/`;
        const resp = json({ original: target, encoded, worker_url: worker, base32: b32, domain_host: host, domain_url });
        log(rid, 'info', 'route:encode', { target, encoded: encoded.substring(0, 20) + '...' }, lvl);
        
        const elapsed = Date.now() - start;
        log(rid, 'info', 'response:complete', {
          status: 200,
          elapsed_ms: elapsed,
          route: 'encode',
          content_type: 'application/json',
        }, lvl);
        
        return resp;
      }
      if (url.pathname === '/healthz') {
        log(rid, 'debug', 'route:healthz', {}, lvl);
        const resp = json({ ok: true, timestamp: new Date().toISOString(), log_level: lvl });
        
        const elapsed = Date.now() - start;
        log(rid, 'info', 'response:complete', {
          status: 200,
          elapsed_ms: elapsed,
          route: 'healthz',
          content_type: 'application/json',
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
        log(rid, 'info', 'response:complete', {
          status: 204,
          elapsed_ms: elapsed,
          route: 'cors-preflight',
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
        log(rid, 'info', 'response:complete', {
          status: response.status,
          elapsed_ms: elapsed,
          route: 'host-encoded',
          content_type: response.headers.get('content-type') || 'none',
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
      log(rid, 'info', 'response:complete', {
        status: 400,
        elapsed_ms: elapsed,
        route: 'missing-upstream',
      }, lvl);
      
      return json({ error: 'Missing host-encoded upstream', hint: 'Use the landing page to generate a base32 host under your domain root.' }, 400);
    } catch (err) {
      log(rid, 'error', 'proxy:error', { 
        message: String(err?.message || err),
        stack: err?.stack ? err.stack.split('\n')[0] : 'no-stack',
        url: url.pathname,
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

function decodeB64UrlToURL(b64u) {
  try {
    // Handle URL-safe base64 without padding
    const normalized = b64u.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(b64u.length / 4) * 4, '=');
    const str = atob(normalized);
    const u = new URL(str);
    return u;
  } catch (e) {
    return null;
  }
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

async function buildUpstreamInit(request, env) {
  const method = request.method.toUpperCase();
  const init = { method, headers: filterRequestHeaders(request.headers) };

  if (!['GET', 'HEAD'].includes(method)) {
    // Pass-through body as-is (exact stream) without parsing or rebuilding
    init.body = request.body;
  }

  // Optional timeout via cf.connectTimeout? Not public; rely on platform defaults.
  return init;
}

function corsPreflight(request) {
  const reqHeaders = request.headers.get('Access-Control-Request-Headers') || '';
  const reqMethod = request.headers.get('Access-Control-Request-Method') || 'GET';
  const headers = new Headers();
  headers.set('Access-Control-Allow-Origin', request.headers.get('origin') || '*');
  headers.set('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
  headers.set('Access-Control-Allow-Headers', reqHeaders || '*');
  headers.set('Access-Control-Max-Age', '600');
  return new Response(null, { status: 204, headers });
}

function filterRequestHeaders(inHeaders) {
  // Forward all headers verbatim except hop-by-hop and restricted ones the platform sets itself
  const drop = new Set([
    'connection','keep-alive','proxy-authenticate','proxy-authorization',
    'te','trailer','transfer-encoding','upgrade','host'
  ]);
  const out = new Headers();
  for (const [k, v] of inHeaders.entries()) {
    const key = k.toLowerCase();
    if (drop.has(key)) continue;
    out.set(k, v);
  }
  return out;
}

function copyForwardableHeaders(inHeaders, outHeaders) {
  const filtered = filterRequestHeaders(inHeaders);
  for (const [k, v] of filtered.entries()) outHeaders.set(k, v);
}

function filterResponseHeaders(inHeaders, { forceSSE = false } = {}) {
  const hopByHop = new Set([
    'connection','keep-alive','proxy-authenticate','proxy-authorization',
    'te','trailer','transfer-encoding','upgrade'
  ]);
  const out = new Headers();
  for (const [k, v] of inHeaders.entries()) {
    const key = k.toLowerCase();
    if (hopByHop.has(key)) continue;
    out.set(k, v);
  }
  // Minimal CORS for browser-based usage; does not modify upstream core headers
  out.set('Access-Control-Allow-Origin', '*');
  out.set('Vary', addVary(out.get('Vary'), 'Origin'));
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
  const root = (env.DOMAIN_ROOT || 'mcp.copernicusone.com').toLowerCase();
  const host = (hostname || '').toLowerCase();
  if (!host.endsWith('.' + root)) return null;
  const parts = host.split('.');
  const rootParts = root.split('.');
  if (parts.length <= rootParts.length) return null; // it's the root domain itself
  const encodedLabels = parts.slice(0, parts.length - rootParts.length);
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
  // Heuristic: if GET + event-stream or requesting /v1/sse, go to exact upstreamBase;
  // otherwise, route to upstream origin + incoming path
  const wantsSSE = request.method.toUpperCase() === 'GET' && (
    (request.headers.get('accept') || '').includes('text/event-stream') ||
    reqUrl.pathname === '/v1/sse' || reqUrl.pathname.endsWith('/sse')
  );
  if (wantsSSE) {
    const u = new URL(upstreamBase.href);
    // Merge query from incoming
    if (reqUrl.search) {
      const qs = new URLSearchParams(reqUrl.search);
      for (const [k, v] of qs.entries()) u.searchParams.set(k, v);
    }
    return u;
  }
  const origin = new URL(upstreamBase.origin);
  origin.pathname = reqUrl.pathname;
  if (reqUrl.search) {
    const qs = new URLSearchParams(reqUrl.search);
    for (const [k, v] of qs.entries()) origin.searchParams.set(k, v);
  }
  return origin;
}

async function proxyFetch(upstreamURL, request, rid, start, lvl, initOpt) {
  const init = initOpt || (await buildUpstreamInit(request));
  
  log(rid, 'info', 'upstream:request', {
    method: init.method,
    url: redactURL(upstreamURL).toString(),
    body_len: request.headers.get('content-length') || '0',
  }, lvl);
  
  log(rid, 'debug', 'upstream:headers', {
    accept: init.headers.get('accept'),
    content_type: init.headers.get('content-type'),
    authorization: init.headers.get('authorization') ? 'present' : 'none',
  }, lvl);
  
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
  const respHeaders = filterResponseHeaders(upstreamResp.headers);
  const elapsed = Date.now() - start;
  
  log(rid, 'info', 'upstream:response', {
    status: upstreamResp.status,
    status_text: upstreamResp.statusText || 'OK',
    content_type: contentType || 'none',
    content_length: contentLength,
    sse: isSSE ? 'yes' : 'no',
    elapsed_ms: elapsed,
  }, lvl);
  
  if (upstreamResp.status >= 400) {
    log(rid, 'warn', 'upstream:error-status', {
      status: upstreamResp.status,
      url: redactURL(upstreamURL).toString(),
      elapsed_ms: elapsed,
    }, lvl);
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
  const example = 'https://mcp.atlassian.com/v1/sse';
  const domainRoot = (env && env.DOMAIN_ROOT) || 'mcp.copernicusone.com';
  const targetParam = url.searchParams.get('url') || '';
  let preRendered = '';
  if (targetParam) {
    try {
      // Validate URL
      const u = new URL(targetParam);
      const encoded = toBase64Url(u.toString());
      const worker = origin + '/' + encoded;
      const curlSse = `curl -N ${worker}`;
      const curlPost = `curl -s ${worker} -H "content-type: application/json" -d "{}"`;
      const b32 = base32Encode(u.toString());
      const host = b32ToHost(b32, domainRoot);
      const domainUrl = `https://${host}/`;
      preRendered = `
        <div class="row grid">
          <div><div class="muted small">Encoded segment</div><div class="code box" id="enc">${escapeHtml(encoded)}</div></div>
          <button class="btn" onclick="copy(qs('#enc').textContent)">Copy</button>
        </div>
        <div class="row grid">
          <div><div class="muted small">Worker URL</div><div class="code box" id="worker">${escapeHtml(worker)}</div></div>
          <button class="btn" onclick="copy(qs('#worker').textContent)">Copy</button>
        </div>
        <div class="row grid">
          <div><div class="muted small">Domain URL</div><div class="code box" id="domain">${escapeHtml(domainUrl)}</div></div>
          <button class="btn" onclick="copy(qs('#domain').textContent)">Copy</button>
        </div>
        <div class="row">
          <div class="muted">Quick commands</div>
          <div class="box small code" style="overflow:auto">
            <div>$ ${escapeHtml(curlSse)}</div>
            <div class="muted"># POST example</div>
            <div>$ ${escapeHtml(curlPost)}</div>
          </div>
        </div>
        <div class="row small muted">Tip: Append extra path or query after the encoded segment, e.g. if you encoded only the origin.</div>
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
    input[type=url] { width: 100%; padding: .6rem .7rem; font-size: 1rem; border-radius: .5rem; border: 1px solid #bbb; background: transparent; }
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
    function toBase64Url(str) {
      const enc = new TextEncoder();
      const bytes = enc.encode(str);
      let bin = '';
      for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
      const b64 = btoa(bin);
      return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
    }
    function fromBase64Url(b64u) {
      const normalized = b64u.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(b64u.length / 4) * 4, '=');
      const bin = atob(normalized);
      const bytes = Uint8Array.from(bin, c => c.charCodeAt(0));
      return new TextDecoder().decode(bytes);
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
      const url = new URL(window.location.href);
      if(!raw){ out.innerHTML = '<em class="muted">Enter a full MCP server URL to get started</em>'; return; }
      let encoded = '';
      try { new URL(raw); encoded = toBase64Url(raw); }
      catch(e){ out.innerHTML = '<span style="color:#c00">Invalid URL</span>'; return; }
      const worker = url.origin + '/' + encoded;
      const curlSse = 'curl -N ' + worker;
      const curlPost = 'curl -s ' + worker + ' -H \"content-type: application/json\" -d \"{}\"';
      out.innerHTML = \`
        <div class="row grid">
          <div><div class="muted small">Encoded segment</div><div class="code box" id="enc">\${encoded}</div></div>
          <button class="btn" onclick="copy(qs('#enc').textContent)">Copy</button>
        </div>
        <div class="row grid">
          <div><div class="muted small">Worker URL</div><div class="code box" id="worker">\${worker}</div></div>
          <button class="btn" onclick="copy(qs('#worker').textContent)">Copy</button>
        </div>
        <div class="row">
          <div class="muted">Quick commands</div>
          <div class="box small code" style="overflow:auto">
            <div>$ \${curlSse}</div>
            <div class="muted"># POST example</div>
            <div>$ \${curlPost}</div>
          </div>
        </div>
        <div class="row small muted">Tip: Append extra path or query after the encoded segment, e.g. if you encoded only the origin.</div>
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
      <div class="muted">Origin: <code>${origin}</code></div>
      <form class="row" method="GET" action="/">
        <label for="target">Enter the full upstream MCP URL</label>
        <div class="grid">
          <input id="target" name="url" type="url" placeholder="e.g. ${example}" value="${escapeHtml(targetParam)}" spellcheck="false" required />
          <button class="btn" type="submit">Generate</button>
        </div>
        <div class="small muted">Only TLS upstreams are allowed by default (https:, wss:).</div>
      </form>
      <div id="out" class="row">${preRendered}</div>
      <div class="row small muted">API: <code>GET ${origin}/encode?url=&lt;full-url&gt;</code> returns JSON (includes a domain URL for <code>${domainRoot}</code>).</div>
    </div>
  </body>
  </html>`);
}
