/**
 * MCP request handlers for proxying to upstream servers
 */

import type { Env, MCPRouteInfo } from '../types';
import { accessTokens } from '../stores';
import { getSession } from '../utils/session';
import { isTokenExpired, refreshUpstreamToken } from '../utils/token';
import { tryConnectUpstreamSSE } from './sse';

/**
 * Return 401 with Bearer challenge for SSE endpoints
 */
function sse401(reason: string = "Missing or invalid access token"): Response {
  const headers = {
    "WWW-Authenticate": 'Bearer realm="mcp", scope="mcp read write"',
    "Content-Type": "application/json",
  };
  return new Response(JSON.stringify({
    error: "invalid_token",
    error_description: reason
  }), { status: 401, headers });
}

export async function handleMCPRequest(request: Request, hostRoute: MCPRouteInfo, env: Env): Promise<Response> {
  const url = new URL(request.url);
  
  // Check for WebSocket upgrade
  const upgradeHeader = request.headers.get('Upgrade');
  if (upgradeHeader?.toLowerCase() === 'websocket') {
    return handleWebSocketUpgrade(request, hostRoute, env);
  }
  
  // Check for SSE endpoint - handle both HEAD and GET
  if (url.pathname === '/sse') {
    // Handle HEAD request for /sse
    if (request.method === 'HEAD') {
      const authHeader = request.headers.get('Authorization');
      if (!authHeader?.startsWith('Bearer ')) {
        return sse401("Missing or invalid access token");
      }
      // If token exists, return 200 OK for HEAD request
      return new Response(null, { status: 200 });
    }
    // Handle GET request for /sse
    if (request.headers.get('Accept')?.includes('text/event-stream')) {
      return handleMCPSSE(request, hostRoute, env);
    }
  }
  
  // Get Bearer token from Authorization header
  const authHeader = request.headers.get('Authorization');
  if (!authHeader?.startsWith('Bearer ')) {
    console.log('Missing Bearer token in Authorization header');
    return sse401('Missing or invalid access token');
  }
  
  const token = authHeader.substring(7);
  
  // Check KV first, then memory
  let tokenData: any = null;
  
  if (env.TOKENS) {
    const kvData = await env.TOKENS.get(`access:${token}`);
    if (kvData) {
      tokenData = JSON.parse(kvData);
    }
  }
  
  if (!tokenData) {
    tokenData = accessTokens.get(token);
  }
  
  if (!tokenData) {
    console.log('Invalid or expired access token');
    return sse401('Invalid or expired access token');
  }
  
  // Check if token is expired (1 hour)
  const isExpired = Date.now() - tokenData.created_at > 3600000;
  if (isExpired) {
    console.log('Access token expired');
    if (env.TOKENS) {
      await env.TOKENS.delete(`access:${token}`);
    }
    accessTokens.delete(token);
    return sse401('Access token expired');
  }
  
  // Get session to check for upstream tokens
  const session = await getSession(tokenData.sessionId, env);
  if (!session) {
    console.log('Session not found for token');
    return sse401('Session expired');
  }
  
  // Get upstream OAuth tokens for this server
  const serverOAuth = session.oauth?.[hostRoute.serverDomain];
  if (!serverOAuth?.tokens) {
    console.log(`No upstream OAuth tokens for ${hostRoute.serverDomain}`);
    return sse401('Upstream authentication required');
  }
  
  // Check if upstream token needs refresh
  if (isTokenExpired(serverOAuth)) {
    console.log('Upstream token expired, attempting refresh...');
    const refreshed = await refreshUpstreamToken(hostRoute.serverDomain, session, env, tokenData.sessionId);
    if (!refreshed) {
      console.log('Failed to refresh upstream token');
      return sse401('Failed to refresh upstream authentication');
    }
  }
  
  // Build upstream URL
  const upstreamUrl = `https://${hostRoute.serverDomain}${url.pathname}${url.search}`;
  
  console.log(`\n╔══ MCP REQUEST PROXY ════════════════════════════════`);
  console.log(`║ Method: ${request.method}`);
  console.log(`║ Path: ${url.pathname}`);
  console.log(`║ Upstream: ${upstreamUrl}`);
  console.log(`║ Has Auth: Yes (Bearer ${serverOAuth.tokens.access_token.substring(0, 8)}...)`);
  console.log(`╚══════════════════════════════════════════════════════`);
  
  // Create headers for upstream request
  const upstreamHeaders = new Headers(request.headers);
  upstreamHeaders.set('Authorization', `Bearer ${serverOAuth.tokens.access_token}`);
  upstreamHeaders.delete('Host');
  upstreamHeaders.set('Host', hostRoute.serverDomain);
  
  // Forward request to upstream
  const upstreamResponse = await fetch(upstreamUrl, {
    method: request.method,
    headers: upstreamHeaders,
    body: request.body,
    redirect: 'manual'
  });
  
  // Create response headers
  const responseHeaders = new Headers(upstreamResponse.headers);
  
  // Add CORS headers
  responseHeaders.set('Access-Control-Allow-Origin', '*');
  responseHeaders.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  responseHeaders.set('Access-Control-Allow-Headers', 'Content-Type, Authorization, MCP-Protocol-Version');
  
  console.log(`║ Response Status: ${upstreamResponse.status}`);
  console.log(`╚══════════════════════════════════════════════════════`);
  
  return new Response(upstreamResponse.body, {
    status: upstreamResponse.status,
    statusText: upstreamResponse.statusText,
    headers: responseHeaders
  });
}

async function handleMCPSSE(request: Request, hostRoute: MCPRouteInfo, env: Env): Promise<Response> {
  // Get Bearer token
  const authHeader = request.headers.get('Authorization');
  if (!authHeader?.startsWith('Bearer ')) {
    return sse401("Missing or invalid access token");
  }
  
  const token = authHeader.substring(7);
  
  // Check KV first, then memory
  let tokenData: any = null;
  
  if (env.TOKENS) {
    const kvData = await env.TOKENS.get(`access:${token}`);
    if (kvData) {
      tokenData = JSON.parse(kvData);
    }
  }
  
  if (!tokenData) {
    tokenData = accessTokens.get(token);
  }
  
  if (!tokenData) {
    return sse401("Invalid or expired access token");
  }
  
  // Check if token is expired
  const isExpired = Date.now() - tokenData.created_at > 3600000;
  if (isExpired) {
    if (env.TOKENS) {
      await env.TOKENS.delete(`access:${token}`);
    }
    accessTokens.delete(token);
    return sse401("Access token expired");
  }
  
  // Get session and upstream tokens
  const session = await getSession(tokenData.sessionId, env);
  if (!session) {
    return sse401("Session expired");
  }
  
  const serverOAuth = session.oauth?.[hostRoute.serverDomain];
  if (!serverOAuth?.tokens) {
    return sse401("Upstream authentication required");
  }
  
  console.log(`\n╔══ SSE CONNECTION REQUEST ═══════════════════════════`);
  console.log(`║ Client: ${tokenData.client_id}`);
  console.log(`║ Server: ${hostRoute.serverDomain}`);
  
  // Try to connect to upstream SSE
  const upstreamResponse = await tryConnectUpstreamSSE(hostRoute.serverDomain, serverOAuth.tokens.access_token);
  
  if (!upstreamResponse.ok) {
    console.log(`║ Upstream SSE Failed: ${upstreamResponse.status}`);
    console.log(`╚══════════════════════════════════════════════════════`);
    return upstreamResponse;
  }
  
  console.log(`║ Upstream SSE: Connected`);
  console.log(`╚══════════════════════════════════════════════════════`);
  
  // Create a TransformStream to pass through SSE data
  const { readable, writable } = new TransformStream();
  
  // Pipe upstream SSE to client
  (async () => {
    const reader = upstreamResponse.body!.getReader();
    const writer = writable.getWriter();
    
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        await writer.write(value);
      }
    } catch (error) {
      console.error('SSE streaming error:', error);
    } finally {
      await writer.close();
    }
  })();
  
  return new Response(readable, {
    headers: {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache, no-transform',
      'Connection': 'keep-alive',
      'Access-Control-Allow-Origin': '*'
    }
  });
}

async function handleWebSocketUpgrade(request: Request, hostRoute: MCPRouteInfo, env: Env): Promise<Response> {
  // Get Bearer token
  const authHeader = request.headers.get('Authorization');
  if (!authHeader?.startsWith('Bearer ')) {
    return sse401('Missing or invalid access token');
  }
  
  const token = authHeader.substring(7);
  
  // Check KV first, then memory
  let tokenData: any = null;
  
  if (env.TOKENS) {
    const kvData = await env.TOKENS.get(`access:${token}`);
    if (kvData) {
      tokenData = JSON.parse(kvData);
    }
  }
  
  if (!tokenData) {
    tokenData = accessTokens.get(token);
  }
  
  if (!tokenData) {
    return sse401('Invalid or expired access token');
  }
  
  // Check if token is expired
  const isExpired = Date.now() - tokenData.created_at > 3600000;
  if (isExpired) {
    if (env.TOKENS) {
      await env.TOKENS.delete(`access:${token}`);
    }
    accessTokens.delete(token);
    return sse401('Access token expired');
  }
  
  // Get session and upstream tokens
  const session = await getSession(tokenData.sessionId, env);
  if (!session) {
    return sse401('Session expired');
  }
  
  const serverOAuth = session.oauth?.[hostRoute.serverDomain];
  if (!serverOAuth?.tokens) {
    return sse401('Upstream authentication required');
  }
  
  console.log(`\n╔══ WEBSOCKET UPGRADE REQUEST ════════════════════════`);
  console.log(`║ Client: ${tokenData.client_id}`);
  console.log(`║ Server: ${hostRoute.serverDomain}`);
  console.log(`╚══════════════════════════════════════════════════════`);
  
  // WebSocket upgrade requires special handling in Cloudflare Workers
  // This is a simplified version - full implementation would use Durable Objects
  return new Response('WebSocket upgrade not fully implemented', { status: 501 });
}