/**
 * Upstream OAuth handlers for MCP OAuth Gateway
 */

import type { Env, MCPRouteInfo, SessionData } from '../types';
import { sessions } from '../stores';
import { getSessionId, getSession, saveSession } from '../utils/session';
import { generateRandomString, sha256Base64Url } from '../utils/crypto';
import { getCurrentDomain } from '../utils/url';
import { isTokenExpired } from '../utils/token';
import { discoverOAuthConfig, registerDynamicClient } from '../utils/oauth-discovery';

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
  
  // Create a mock hostRoute for initiateUpstreamOAuth
  const hostRoute: MCPRouteInfo = {
    serverDomain,
    encodedDomain: '', // Not needed for OAuth start
    isEncoded: false
  };
  
  // Use the same OAuth discovery flow
  return initiateUpstreamOAuth(request, hostRoute, session, env);
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
  
  const serverData = session.oauth![serverDomain];
  
  // Get the stored OAuth config from session
  const storedConfig = serverData.config;
  if (!storedConfig) {
    console.error(`No stored OAuth config for ${serverDomain}`);
    return new Response('OAuth configuration not found', { status: 500 });
  }
  
  // Exchange code for tokens
  const tokenUrl = new URL(storedConfig.token_endpoint);
  const tokenBody = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: `https://${getCurrentDomain(request)}/oauth/callback`,
    client_id: storedConfig.client_id,
    code_verifier: serverData.pkceVerifier!
  });
  
  if (storedConfig.client_secret) {
    tokenBody.set('client_secret', storedConfig.client_secret);
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
  
  // Save updated session to KV
  await saveSession(sessionId!, session, env);
  
  console.log(`Successfully authenticated with ${serverDomain}`);
  
  // Redirect to dashboard or pending resource
  const redirectTo = session.pendingResource || '/';
  delete session.pendingResource;
  
  return Response.redirect(`https://${getCurrentDomain(request)}${redirectTo}`, 302);
}

export async function initiateUpstreamOAuth(request: Request, hostRoute: MCPRouteInfo, session: SessionData, env: Env): Promise<Response> {
  const redirectUri = `https://${getCurrentDomain(request)}/oauth/callback`;
  
  // Try to discover OAuth configuration from upstream server
  console.log(`\n╔══ DISCOVERING OAUTH CONFIG ═════════════════════════`);
  console.log(`║ Server: ${hostRoute.serverDomain}`);
  
  const oauthConfig = await discoverOAuthConfig(hostRoute.serverDomain);
  
  if (!oauthConfig) {
    console.log(`║ Discovery failed - server may not support OAuth`);
    console.log(`╚══════════════════════════════════════════════════════`);
    return new Response('OAuth discovery failed. Server may not support OAuth.', { status: 502 });
  }
  
  console.log(`║ Authorization: ${oauthConfig.authorization_endpoint}`);
  console.log(`║ Token: ${oauthConfig.token_endpoint}`);
  
  // Check if we need to register a dynamic client
  let clientId: string;
  let clientSecret: string | undefined;
  
  // Check if we have a stored client for this server
  const storedClient = session.oauth?.[hostRoute.serverDomain]?.client;
  if (storedClient) {
    clientId = storedClient.client_id;
    clientSecret = storedClient.client_secret;
    console.log(`║ Using stored client: ${clientId}`);
  } else if (oauthConfig.registration_endpoint) {
    // Try dynamic client registration
    console.log(`║ Attempting dynamic client registration...`);
    const registration = await registerDynamicClient(
      hostRoute.serverDomain,
      oauthConfig.registration_endpoint,
      redirectUri
    );
    
    if (!registration) {
      console.log(`║ Registration failed - trying with default client`);
      // Fallback to a default client ID
      clientId = 'mcp-oauth-gateway';
    } else {
      clientId = registration.client_id;
      clientSecret = registration.client_secret;
      console.log(`║ Registered client: ${clientId}`);
      
      // Store the client registration in session
      if (!session.oauth) session.oauth = {};
      if (!session.oauth[hostRoute.serverDomain]) {
        session.oauth[hostRoute.serverDomain] = {};
      }
      session.oauth[hostRoute.serverDomain].client = {
        client_id: clientId,
        client_secret: clientSecret
      };
    }
  } else {
    // Use a default client ID if no registration endpoint
    clientId = 'mcp-oauth-gateway';
    console.log(`║ Using default client ID: ${clientId}`);
  }
  
  // Generate OAuth state and PKCE
  const state = generateRandomString(32);
  const pkceVerifier = generateRandomString(64);
  const pkceChallenge = await sha256Base64Url(pkceVerifier);
  
  // Store OAuth state in session
  if (!session.oauth) session.oauth = {};
  if (!session.oauth[hostRoute.serverDomain]) {
    session.oauth[hostRoute.serverDomain] = {};
  }
  
  session.oauth[hostRoute.serverDomain] = {
    ...session.oauth[hostRoute.serverDomain],
    state,
    pkceVerifier,
    config: {
      authorization_endpoint: oauthConfig.authorization_endpoint,
      token_endpoint: oauthConfig.token_endpoint,
      client_id: clientId,
      client_secret: clientSecret
    }
  };
  
  // Get session ID from request to save
  const sessionId = getSessionId(request);
  if (sessionId) {
    await saveSession(sessionId, session, env);
  }
  
  // Determine scopes to request
  const scopes = oauthConfig.scopes_supported?.includes('mcp') 
    ? 'mcp read write'
    : oauthConfig.scopes_supported?.join(' ') || 'read write';
  
  // Build authorization URL
  const authUrl = new URL(oauthConfig.authorization_endpoint);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('client_id', clientId);
  authUrl.searchParams.set('redirect_uri', redirectUri);
  authUrl.searchParams.set('state', state);
  authUrl.searchParams.set('scope', scopes);
  authUrl.searchParams.set('code_challenge', pkceChallenge);
  authUrl.searchParams.set('code_challenge_method', 'S256');
  
  console.log(`║ Scopes: ${scopes}`);
  console.log(`║ Redirect URI: ${redirectUri}`);
  console.log(`╚══════════════════════════════════════════════════════`);
  
  return Response.redirect(authUrl.toString(), 302);
}

