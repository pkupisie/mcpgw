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
    try {
      const url = new URL(request.url);

      // Health and root info
      if (url.pathname === '/' || url.pathname === '') {
        return json({
          ok: true,
          message: 'MCP MITM proxy is up',
          usage: 'GET/POST/WS: /<base64url-encoded-full-upstream-url>',
          example: '/aHR0cHM6Ly9tY3AuYXRsYXNzaWFuLmNvbS92MS9zc2U',
        });
      }
      if (url.pathname === '/healthz') return json({ ok: true });

      // CORS preflight
      if (request.method === 'OPTIONS') {
        return corsPreflight(request);
      }

      // The first segment is the base64url-encoded full upstream URL.
      // Remaining path segments (if any) are appended to upstream path.
      const { encoded, restPath } = splitEncodedPath(url.pathname);
      if (!encoded) return badRequest('Missing encoded upstream URL in path');

      const upstreamBase = decodeB64UrlToURL(encoded);
      if (!upstreamBase) return badRequest('Invalid base64url for upstream');

      if (!allowProtocol(upstreamBase.protocol, env)) {
        return badRequest('Upstream protocol not allowed');
      }

      // Build final upstream URL
      const upstreamURL = new URL(upstreamBase.href);
      if (restPath) upstreamURL.pathname = joinPaths(upstreamURL.pathname, restPath);
      // Merge query strings: client query overrides upstream duplicates
      if (url.search) {
        const incoming = new URLSearchParams(url.search);
        for (const [k, v] of incoming.entries()) upstreamURL.searchParams.set(k, v);
      }

      // WebSocket tunneling
      const upgrade = request.headers.get('upgrade');
      if (upgrade && upgrade.toLowerCase() === 'websocket') {
        return await handleWebSocket(request, upstreamURL, env);
      }

      // Build upstream request
      const init = await buildUpstreamInit(request, env);
      const upstreamResp = await fetch(upstreamURL.toString(), init);

      // Pass-through SSE streaming (or any streaming body)
      const contentType = upstreamResp.headers.get('content-type') || '';
      const isSSE = contentType.includes('text/event-stream');
      const respHeaders = filterResponseHeaders(upstreamResp.headers, { forceSSE: isSSE });

      return new Response(upstreamResp.body, {
        status: upstreamResp.status,
        statusText: upstreamResp.statusText,
        headers: respHeaders,
      });
    } catch (err) {
      console.error('[proxy] error', err);
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
  // Accept client socket
  const pair = new WebSocketPair();
  const clientSocket = pair[0];
  const workerSocket = pair[1];
  clientSocket.accept();

  // Connect to upstream as a WebSocket client
  const headers = new Headers();
  // Forward selected headers only. Cloudflare adds required headers for WS upgrade.
  copyForwardableHeaders(clientRequest.headers, headers);
  headers.set('Connection', 'upgrade');
  headers.set('Upgrade', 'websocket');

  let upstreamResp;
  try {
    upstreamResp = await fetch(upstreamURL.toString(), { method: 'GET', headers });
  } catch (e) {
    clientSocket.close(1011, 'Upstream connect error');
    return new Response(null, { status: 101, webSocket: workerSocket });
  }
  const upstreamSocket = upstreamResp.webSocket;
  if (!upstreamSocket) {
    clientSocket.close(1011, 'No upstream websocket');
    return new Response(null, { status: 101, webSocket: workerSocket });
  }
  upstreamSocket.accept();

  // Bidirectional piping
  upstreamSocket.addEventListener('message', (evt) => {
    try { clientSocket.send(evt.data); } catch { try { upstreamSocket.close(1011, 'client send failed'); } catch {} }
  });
  clientSocket.addEventListener('message', (evt) => {
    try { upstreamSocket.send(evt.data); } catch { try { clientSocket.close(1011, 'upstream send failed'); } catch {} }
  });
  upstreamSocket.addEventListener('close', (evt) => {
    try { clientSocket.close(evt.code, evt.reason); } catch {}
  });
  clientSocket.addEventListener('close', (evt) => {
    try { upstreamSocket.close(evt.code, evt.reason); } catch {}
  });
  upstreamSocket.addEventListener('error', () => {
    try { clientSocket.close(1011, 'upstream error'); } catch {}
  });
  clientSocket.addEventListener('error', () => {
    try { upstreamSocket.close(1011, 'client error'); } catch {}
  });

  return new Response(null, { status: 101, webSocket: workerSocket });
}

async function buildUpstreamInit(request, env) {
  const method = request.method.toUpperCase();
  const init = { method, headers: filterRequestHeaders(request.headers) };

  if (!['GET', 'HEAD'].includes(method)) {
    // Pass-through body as-is. Clone to avoid stream lock issues.
    init.body = request.body;
  }

  // Enforce no compression to keep SSE clean
  init.headers.delete('accept-encoding');
  // Identify proxy
  init.headers.set('x-mcp-proxy', 'true');

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
  const hopByHop = new Set([
    'connection','keep-alive','proxy-authenticate','proxy-authorization',
    'te','trailer','transfer-encoding','upgrade','accept-encoding'
  ]);
  const allowNames = new Set([
    'authorization','content-type','accept','user-agent','origin','referer','cache-control','pragma'
  ]);
  const out = new Headers();
  for (const [k, v] of inHeaders.entries()) {
    const key = k.toLowerCase();
    if (hopByHop.has(key)) continue;
    if (allowNames.has(key) || key.startsWith('x-')) out.set(k, v);
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
    // Avoid sending explicit content-length on streaming responses
    if (key === 'content-length') continue;
    out.set(k, v);
  }
  // CORS echo for browsers
  out.set('Access-Control-Allow-Origin', '*');
  out.set('Vary', addVary(out.get('Vary'), 'Origin'));
  if (forceSSE) {
    out.set('Content-Type', 'text/event-stream; charset=utf-8');
    out.set('Cache-Control', 'no-cache, no-transform');
    out.set('Connection', 'keep-alive');
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

