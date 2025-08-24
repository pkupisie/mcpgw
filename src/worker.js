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
      if (url.pathname === '/' || url.pathname === '' || url.pathname === '/index.html') {
        // Simple content-negotiation: if client prefers JSON, return JSON; else HTML landing
        const accept = request.headers.get('accept') || '';
        if (/application\/json/i.test(accept)) {
          return json({
            ok: true,
            message: 'MCP MITM proxy is up',
            usage: 'GET/POST/WS: /<base64url-encoded-full-upstream-url>',
            example: '/aHR0cHM6Ly9tY3AuYXRsYXNzaWFuLmNvbS92MS9zc2U',
          });
        }
        return landingHTML(url);
      }
      if (url.pathname === '/encode') {
        const target = url.searchParams.get('url') || '';
        if (!target) return badRequest('Missing url param');
        let encoded = '';
        try { encoded = toBase64Url(target); } catch (e) { return badRequest('Invalid URL input'); }
        const worker = `${url.origin}/${encoded}`;
        return json({ original: target, encoded, worker_url: worker });
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

function landingHTML(url) {
  const origin = url.origin;
  const example = 'https://mcp.atlassian.com/v1/sse';
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
      preRendered = `
        <div class="row grid">
          <div><div class="muted small">Encoded segment</div><div class="code box" id="enc">${escapeHtml(encoded)}</div></div>
          <button class="btn" onclick="copy(qs('#enc').textContent)">Copy</button>
        </div>
        <div class="row grid">
          <div><div class="muted small">Worker URL</div><div class="code box" id="worker">${escapeHtml(worker)}</div></div>
          <button class="btn" onclick="copy(qs('#worker').textContent)">Copy</button>
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
    function copy(text){ navigator.clipboard?.writeText(text); }
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
      <div class="row">
        <label for="target">Enter the full upstream MCP URL</label>
        <input id="target" type="url" placeholder="e.g. ${example}" value="${escapeHtml(targetParam)}" spellcheck="false" />
        <div class="small muted">Only TLS upstreams are allowed by default (https:, wss:).</div>
      </div>
      <div id="out" class="row">${preRendered}</div>
      <div class="row small muted">API: <code>GET ${origin}/encode?url=&lt;full-url&gt;</code> returns JSON.</div>
    </div>
  </body>
  </html>`);
}
