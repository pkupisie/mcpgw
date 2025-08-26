/**
 * MCP request handlers for proxying to upstream servers
 */

import type { Env, MCPRouteInfo } from '../types';
import { getAccessToken } from '../utils/kv-storage';
import { getSession } from '../utils/session';
import { isTokenExpired, refreshUpstreamToken } from '../utils/token';
import { tryConnectUpstreamSSE } from './sse';

/**
 * Return 401 with Bearer challenge for SSE endpoints
 */
function sse401(reason: string = "Missing or invalid access token"): Response {
  const headers = {
    "WWW-Authenticate": `Bearer realm="OAuth", error="invalid_token", error_description="${reason}"`,
    "Content-Type": "application/json",
  };
  return new Response(JSON.stringify({
    error: "invalid_token",
    error_description: reason
  }), { status: 401, headers });
}

export async function handleMCPRequest(request: Request, hostRoute: MCPRouteInfo, env: Env): Promise<Response> {
  const url = new URL(request.url);
  
  console.log(`\n╔══ MCP REQUEST ENTRY ════════════════════════════════`);
  console.log(`║ URL: ${url.toString()}`);
  console.log(`║ Method: ${request.method}`);
  console.log(`║ Path: ${url.pathname}`);
  console.log(`║ Accept: ${request.headers.get('Accept')}`);
  console.log(`║ Server Domain: ${hostRoute.serverDomain}`);
  console.log(`╚══════════════════════════════════════════════════════`);
  
  // Check for WebSocket upgrade
  const upgradeHeader = request.headers.get('Upgrade');
  if (upgradeHeader?.toLowerCase() === 'websocket') {
    return handleWebSocketUpgrade(request, hostRoute, env);
  }
  
  // Check for SSE endpoint - handle both HEAD and GET
  if (url.pathname === '/sse') {
    // Add detailed logging for SSE authentication
    console.log(`\n╔══ SSE AUTHENTICATION CHECK ════════════════════════`);
    console.log(`║ Method: ${request.method}`);
    const authHeaderForSSE = request.headers.get('Authorization');
    console.log(`║ Authorization Header: ${authHeaderForSSE || '*** MISSING ***'}`);
    if (authHeaderForSSE?.startsWith('Bearer ')) {
      console.log(`║ Token: ${authHeaderForSSE.substring(7, 15)}...`);
    }
    console.log(`║ User-Agent: ${request.headers.get('User-Agent')}`);
    console.log(`╚══════════════════════════════════════════════════════`);
    
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
  
  // Get access token from KV
  const tokenData = await getAccessToken(env, token);
  
  if (!tokenData) {
    console.log('Invalid or expired access token');
    return sse401('Invalid or expired access token');
  }
  
  // Check if token is expired (1 hour)
  const isExpired = Date.now() - tokenData.created_at > 3600000;
  if (isExpired) {
    console.log('Access token expired');
    // Note: Token will be auto-deleted by KV TTL
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
  console.log(`\n╔══ SSE ENDPOINT HIT ══════════════════════════════════`);
  console.log(`║ Path: ${new URL(request.url).pathname}`);
  console.log(`║ Method: ${request.method}`);
  console.log(`║ Headers: ${JSON.stringify(Object.fromEntries(request.headers.entries()))}`);
  
  // Get Bearer token
  const authHeader = request.headers.get('Authorization');
  console.log(`║ Auth Header: ${authHeader ? authHeader.substring(0, 20) + '...' : 'MISSING'}`);
  
  if (!authHeader?.startsWith('Bearer ')) {
    console.log(`║ Result: 401 - Missing Bearer token`);
    console.log(`╚══════════════════════════════════════════════════════`);
    return sse401("Missing or invalid access token");
  }
  
  const token = authHeader.substring(7);
  console.log(`║ Token: ${token.substring(0, 8)}...`);
  console.log(`║ KV Available: ${env.MCPGW ? 'YES' : 'NO'}`);
  
  // Get access token from KV
  const tokenData = await getAccessToken(env, token);
  console.log(`║ Token Result: ${tokenData ? 'FOUND' : 'NOT FOUND'}`);
  if (tokenData) {
    console.log(`║ Token Client: ${tokenData.client_id}`);
  }
  
  console.log(`║ Token lookup from KV`);
  
  if (!tokenData) {
    console.log(`║ Result: 401 - Token not found in KV or memory`);
    console.log(`╚══════════════════════════════════════════════════════`);
    return sse401("Invalid or expired access token");
  }
  
  // Check if token is expired
  const isExpired = Date.now() - tokenData.created_at > 3600000;
  if (isExpired) {
    // Note: Token will be auto-deleted by KV TTL
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
  
  // Get access token from KV
  const tokenData = await getAccessToken(env, token);
  
  if (!tokenData) {
    return sse401('Invalid or expired access token');
  }
  
  // Check if token is expired
  const isExpired = Date.now() - tokenData.created_at > 3600000;
  if (isExpired) {
    // Note: Token will be auto-deleted by KV TTL
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