/**
 * Upstream OAuth handlers for MCP OAuth Gateway
 */

import type { Env, MCPServerConfig, SessionData } from '../types';
import { sessions } from '../stores';
import { getSessionId, getSession } from '../utils/session';
import { generateRandomString, sha256Base64Url } from '../utils/crypto';
import { getCurrentDomain } from '../utils/url';
import { isTokenExpired } from '../utils/token';

export async function handleOAuthStart(request: Request, env: Env): Promise<Response> {
  const sessionId = getSessionId(request);
  const session = sessionId ? await getSession(sessionId, env) : null;
  
  if (!session || !session.localAuth) {
    return Response.redirect(`https://${getCurrentDomain(request)}/login?return_to=/oauth/start`, 302);
  }
  
  const url = new URL(request.url);
  const serverDomain = url.searchParams.get('server');
  
  if (!serverDomain) {
    return new Response('Missing server parameter', { status: 400 });
  }
  
  // Parse MCP servers config
  let mcpServers: MCPServerConfig[] = [];
  try {
    mcpServers = JSON.parse(env.MCP_SERVERS || '[]');
  } catch (e) {
    return new Response('Invalid MCP_SERVERS configuration', { status: 500 });
  }
  
  const serverConfig = mcpServers.find(s => s.domain === serverDomain);
  
  if (!serverConfig) {
    return new Response('Unknown server', { status: 404 });
  }
  
  // Generate OAuth state and PKCE
  const state = generateRandomString(32);
  const pkceVerifier = generateRandomString(64);
  const pkceChallenge = await sha256Base64Url(pkceVerifier);
  
  // Store OAuth state in session
  if (!session.oauth) session.oauth = {};
  session.oauth[serverDomain] = {
    state,
    pkceVerifier
  };
  
  // Build authorization URL
  const authUrl = new URL(serverConfig.authzEndpoint);
  authUrl.searchParams.set('client_id', serverConfig.clientId);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('redirect_uri', `https://${getCurrentDomain(request)}/oauth/callback`);
  authUrl.searchParams.set('state', state);
  authUrl.searchParams.set('scope', serverConfig.scopes);
  authUrl.searchParams.set('code_challenge', pkceChallenge);
  authUrl.searchParams.set('code_challenge_method', 'S256');
  
  console.log(`Starting OAuth flow for ${serverDomain}`);
  console.log(`Redirect URL: ${authUrl.toString()}`);
  
  return Response.redirect(authUrl.toString(), 302);
}

export async function handleOAuthCallback(request: Request, env: Env): Promise<Response> {
  const sessionId = getSessionId(request);
  const session = sessionId ? await getSession(sessionId, env) : null;
  
  if (!session || !session.localAuth) {
    return new Response('Unauthorized', { status: 401 });
  }
  
  const url = new URL(request.url);
  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state');
  const error = url.searchParams.get('error');
  
  if (error) {
    return new Response(`OAuth error: ${error}`, { status: 400 });
  }
  
  if (!code || !state) {
    return new Response('Missing code or state', { status: 400 });
  }
  
  // Find which server this callback is for
  let serverDomain: string | null = null;
  for (const [domain, data] of Object.entries(session.oauth || {})) {
    if (data.state === state) {
      serverDomain = domain;
      break;
    }
  }
  
  if (!serverDomain) {
    return new Response('Invalid state', { status: 400 });
  }
  
  // Parse MCP servers config
  let mcpServers: MCPServerConfig[] = [];
  try {
    mcpServers = JSON.parse(env.MCP_SERVERS || '[]');
  } catch (e) {
    return new Response('Invalid MCP_SERVERS configuration', { status: 500 });
  }
  
  const serverConfig = mcpServers.find(s => s.domain === serverDomain);
  
  if (!serverConfig) {
    return new Response('Unknown server', { status: 404 });
  }
  
  const serverData = session.oauth![serverDomain];
  
  // Exchange code for tokens
  const tokenUrl = new URL(serverConfig.tokenEndpoint);
  const tokenBody = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: `https://${getCurrentDomain(request)}/oauth/callback`,
    client_id: serverConfig.clientId,
    code_verifier: serverData.pkceVerifier!
  });
  
  if (serverConfig.clientSecret) {
    tokenBody.set('client_secret', serverConfig.clientSecret);
  }
  
  console.log(`Exchanging code for tokens with ${serverDomain}`);
  
  const tokenResponse = await fetch(tokenUrl.toString(), {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Accept': 'application/json'
    },
    body: tokenBody.toString()
  });
  
  if (!tokenResponse.ok) {
    const errorText = await tokenResponse.text();
    console.error(`Token exchange failed: ${errorText}`);
    return new Response(`Token exchange failed: ${errorText}`, { status: 500 });
  }
  
  const tokens = await tokenResponse.json() as any;
  
  // Store tokens in session
  serverData.tokens = {
    access_token: tokens.access_token,
    refresh_token: tokens.refresh_token,
    expires_in: tokens.expires_in
  };
  
  if (tokens.expires_in) {
    serverData.expiresAt = Date.now() + (tokens.expires_in * 1000);
  }
  
  // Clean up PKCE data
  delete serverData.state;
  delete serverData.pkceVerifier;
  
  console.log(`Successfully authenticated with ${serverDomain}`);
  
  // Redirect to dashboard or pending resource
  const redirectTo = session.pendingResource || '/';
  delete session.pendingResource;
  
  return Response.redirect(`https://${getCurrentDomain(request)}${redirectTo}`, 302);
}

export async function refreshUpstreamToken(serverDomain: string, serverData: any, env: Env): Promise<boolean> {
  if (!serverData.tokens?.refresh_token) {
    console.error('No refresh token available');
    return false;
  }
  
  // Parse MCP servers config
  let mcpServers: MCPServerConfig[] = [];
  try {
    mcpServers = JSON.parse(env.MCP_SERVERS || '[]');
  } catch (e) {
    console.error('Failed to parse MCP_SERVERS:', e);
    return false;
  }
  
  const serverConfig = mcpServers.find(s => s.domain === serverDomain);
  
  if (!serverConfig) {
    console.error(`No config found for server: ${serverDomain}`);
    return false;
  }
  
  const tokenUrl = new URL(serverConfig.tokenEndpoint);
  const tokenBody = new URLSearchParams({
    grant_type: 'refresh_token',
    refresh_token: serverData.tokens.refresh_token,
    client_id: serverConfig.clientId
  });
  
  if (serverConfig.clientSecret) {
    tokenBody.set('client_secret', serverConfig.clientSecret);
  }
  
  try {
    const tokenResponse = await fetch(tokenUrl.toString(), {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json'
      },
      body: tokenBody.toString()
    });
    
    if (!tokenResponse.ok) {
      const errorText = await tokenResponse.text();
      console.error(`Token refresh failed: ${errorText}`);
      return false;
    }
    
    const tokens = await tokenResponse.json() as any;
    
    // Update tokens
    serverData.tokens.access_token = tokens.access_token;
    if (tokens.refresh_token) {
      serverData.tokens.refresh_token = tokens.refresh_token;
    }
    if (tokens.expires_in) {
      serverData.tokens.expires_in = tokens.expires_in;
      serverData.expiresAt = Date.now() + (tokens.expires_in * 1000);
    }
    
    console.log(`Successfully refreshed token for ${serverDomain}`);
    return true;
  } catch (error) {
    console.error(`Failed to refresh token: ${error}`);
    return false;
  }
}