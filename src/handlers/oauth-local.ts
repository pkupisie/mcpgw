/**
 * Local OAuth handlers for downstream clients (Claude/ChatGPT)
 */

import type { Env, MCPRouteInfo, SessionData } from '../types';
import { sessions, authorizationCodes, accessTokens, deviceCodes, userCodeMap } from '../stores';
import { getSessionId, getSession, generateSessionId, createDeviceSession, generateUserCode, saveSession } from '../utils/session';
import { generateRandomString, sha256Base64Url } from '../utils/crypto';
import { getCurrentDomain } from '../utils/url';
import { initiateUpstreamOAuth } from './oauth-upstream';

export async function handleLocalOAuth(request: Request, hostRoute: MCPRouteInfo, env: Env): Promise<Response> {
  const url = new URL(request.url);
  
  if (url.pathname === '/oauth/authorize') {
    if (request.method === 'GET') return handleLocalOAuthAuthorize(request, hostRoute, env);
    if (request.method === 'POST') return handleLocalOAuthAuthorizePost(request, hostRoute, env);
  }
  
  if (url.pathname === '/oauth/token') {
    if (request.method === 'POST') return handleLocalOAuthToken(request, hostRoute, env);
  }
  
  if (url.pathname === '/oauth/device') {
    if (request.method === 'POST') return handleLocalOAuthDevice(request, hostRoute, env);
  }
  
  if (url.pathname === '/oauth/revoke') {
    if (request.method === 'POST') return handleLocalOAuthRevoke(request, hostRoute, env);
  }
  
  if (url.pathname === '/oauth/introspect') {
    if (request.method === 'POST') return handleLocalOAuthIntrospect(request, hostRoute, env);
  }
  
  if (url.pathname === '/oauth/device/verify') {
    if (request.method === 'GET') return handleDeviceVerify(request, hostRoute, env);
    if (request.method === 'POST') return handleDeviceVerifyPost(request, hostRoute, env);
  }
  
  if (url.pathname === '/oauth/register') {
    if (request.method === 'POST') return handleClientRegistration(request, hostRoute, env);
  }
  
  if (url.pathname === '/oauth/callback') {
    return handleOAuthCallback(request, env);
  }
  
  return new Response('OAuth endpoint not found', { status: 404 });
}

async function handleLocalOAuthAuthorize(request: Request, hostRoute: MCPRouteInfo, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const params = url.searchParams;
  
  const response_type = params.get('response_type');
  const client_id = params.get('client_id');
  const redirect_uri = params.get('redirect_uri');
  const scope = params.get('scope');
  const state = params.get('state');
  const code_challenge = params.get('code_challenge');
  const code_challenge_method = params.get('code_challenge_method');
  const resource = params.get('resource');
  
  console.log(`\n╔══ OAUTH AUTHORIZE REQUEST ══════════════════════════`);
  console.log(`║ Client ID: ${client_id}`);
  console.log(`║ Requested Scope: ${scope}`);
  console.log(`║ Resource: ${resource || 'none'}`);
  console.log(`║ Redirect URI: ${redirect_uri}`);
  console.log(`╚══════════════════════════════════════════════════════`)
  
  if (response_type !== 'code') {
    return new Response('Only authorization code flow is supported', { status: 400 });
  }
  
  if (!client_id || !redirect_uri) {
    return new Response('Missing required parameters: client_id, redirect_uri', { status: 400 });
  }
  
  // Check if user is authenticated with gateway
  const sessionId = getSessionId(request);
  const session = sessionId ? await getSession(sessionId, env) : null;
  
  // Log current sessions for debugging
  console.log(`║ Total Sessions in Memory: ${sessions.size}`);
  console.log(`║ Session Check: ${sessionId ? `Found (${sessionId.substring(0, 8)}...)` : 'Not found'}`);
  console.log(`║ Session Valid: ${session ? 'Yes' : 'No'}`);
  console.log(`║ Local Auth: ${session?.localAuth ? 'Yes' : 'No'}`);
  
  // Debug: Log all session IDs
  if (sessions.size > 0) {
    const sessionIds = Array.from(sessions.keys()).map(id => id.substring(0, 8) + '...');
    console.log(`║ Active Sessions: [${sessionIds.join(', ')}]`);
  }
  
  if (!session || !session.localAuth) {
    // Redirect to login with return URL
    const loginUrl = new URL(`https://${getCurrentDomain(request)}/login`);
    loginUrl.searchParams.set('return_to', request.url);
    console.log(`║ Redirecting to login: ${loginUrl.toString()}`);
    console.log(`╚══════════════════════════════════════════════════════`);
    return Response.redirect(loginUrl.toString(), 302);
  }
  
  // Show authorization consent page
  const hostname = new URL(request.url).hostname;
  const html = `<!doctype html><html><head><title>Authorize Application</title></head><body>
    <h1>Authorize MCP Access</h1>
    <p><strong>Application:</strong> ${client_id}</p>
    <p><strong>Server:</strong> ${hostRoute.serverDomain}</p>
    <p><strong>Scopes:</strong> ${scope || 'default'}</p>
    ${resource ? `<p><strong>Resource:</strong> ${resource}</p>` : ''}
    <form method="POST" action="/oauth/authorize">
      <input type="hidden" name="response_type" value="${response_type}">
      <input type="hidden" name="client_id" value="${client_id}">
      <input type="hidden" name="redirect_uri" value="${redirect_uri}">
      <input type="hidden" name="scope" value="${scope || ''}">
      <input type="hidden" name="state" value="${state || ''}">
      <input type="hidden" name="code_challenge" value="${code_challenge || ''}">
      <input type="hidden" name="code_challenge_method" value="${code_challenge_method || ''}">
      <input type="hidden" name="resource" value="${resource || ''}">
      <button type="submit" name="action" value="authorize">Authorize</button>
      <button type="submit" name="action" value="deny">Deny</button>
    </form>
  </body></html>`;
  
  return new Response(html, {
    headers: { 'Content-Type': 'text/html' }
  });
}

async function handleLocalOAuthAuthorizePost(request: Request, hostRoute: MCPRouteInfo, env: Env): Promise<Response> {
  const formData = await request.formData();
  const action = formData.get('action');
  
  if (action !== 'authorize') {
    const redirect_uri = formData.get('redirect_uri') as string;
    const state = formData.get('state') as string;
    const errorUrl = new URL(redirect_uri);
    errorUrl.searchParams.set('error', 'access_denied');
    if (state) errorUrl.searchParams.set('state', state);
    return Response.redirect(errorUrl.toString(), 302);
  }
  
  // Generate authorization code
  const code = generateRandomString(32);
  const sessionId = getSessionId(request);
  const session = await getSession(sessionId!, env);
  
  if (!session) {
    return new Response('Session expired', { status: 401 });
  }
  
  // Check if we have upstream tokens for this server
  const upstreamTokens = session.oauth?.[hostRoute.serverDomain]?.tokens;
  
  if (!upstreamTokens) {
    // Save pending client authorization
    session.pendingClientAuth = {
      client_id: formData.get('client_id') as string,
      redirect_uri: formData.get('redirect_uri') as string,
      scope: formData.get('scope') as string,
      state: formData.get('state') as string,
      code_challenge: formData.get('code_challenge') as string,
      code_challenge_method: formData.get('code_challenge_method') as string,
      resource: formData.get('resource') as string,
      serverDomain: hostRoute.serverDomain
    };
    
    // Save session before redirecting
    await saveSession(sessionId!, session, env);
    
    // Redirect to upstream OAuth
    return initiateUpstreamOAuth(request, hostRoute, session, env);
  }
  
  // Store authorization code data globally
  const hostname = new URL(request.url).hostname;
  
  const codeData = {
    client_id: formData.get('client_id') as string,
    redirect_uri: formData.get('redirect_uri') as string,
    scope: formData.get('scope') as string,
    code_challenge: formData.get('code_challenge') as string,
    code_challenge_method: formData.get('code_challenge_method') as string,
    resource: formData.get('resource') as string,
    serverDomain: hostRoute.serverDomain,
    hostname,
    sessionId,
    created_at: Date.now()
  };
  
  // Store in KV if available, otherwise in memory
  if (env.OAUTH_CODES) {
    await env.OAUTH_CODES.put(code, JSON.stringify(codeData), { expirationTtl: 600 });
  } else {
    authorizationCodes.set(code, codeData);
  }
  
  // Redirect back to client with code
  const redirect_uri = formData.get('redirect_uri') as string;
  const state = formData.get('state') as string;
  const redirectUrl = new URL(redirect_uri);
  redirectUrl.searchParams.set('code', code);
  if (state) redirectUrl.searchParams.set('state', state);
  redirectUrl.searchParams.set('iss', `https://${hostname}`);
  
  console.log(`\n╔══ AUTHORIZATION CODE ISSUED ════════════════════════`);
  console.log(`║ Code: ${code.substring(0, 8)}...`);
  console.log(`║ Client: ${codeData.client_id}`);
  console.log(`║ Redirect: ${redirectUrl.toString()}`);
  console.log(`╚══════════════════════════════════════════════════════`);
  
  return Response.redirect(redirectUrl.toString(), 302);
}

async function handleLocalOAuthToken(request: Request, hostRoute: MCPRouteInfo, env: Env): Promise<Response> {
  const formData = await request.formData();
  const grant_type = formData.get('grant_type');
  
  console.log(`\n╔══ DOWNSTREAM OAUTH TOKEN EXCHANGE (Claude → Gateway) ══`);
  console.log(`║ Grant Type: ${grant_type}`);
  
  if (grant_type === 'authorization_code') {
    const code = formData.get('code') as string;
    const client_id = formData.get('client_id') as string;
    const redirect_uri = formData.get('redirect_uri') as string;
    const code_verifier = formData.get('code_verifier') as string;
    
    console.log(`║ Code: ${code?.substring(0, 8)}...`);
    console.log(`║ Client ID: ${client_id}`);
    console.log(`║ Redirect URI: ${redirect_uri}`);
    
    // Look up code in KV store or memory
    let codeData: any;
    if (env.OAUTH_CODES) {
      const codeDataStr = await env.OAUTH_CODES.get(code);
      if (!codeDataStr) {
        console.log(`║ Result: FAILED - Code not found in KV`);
        console.log(`╚══════════════════════════════════════════════════════`);
        return new Response(JSON.stringify({ error: 'invalid_grant', error_description: 'Authorization code expired or not found' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        });
      }
      codeData = JSON.parse(codeDataStr);
      await env.OAUTH_CODES.delete(code);
    } else {
      codeData = authorizationCodes.get(code);
      if (!codeData) {
        console.log(`║ Result: FAILED - Code not found in memory`);
        console.log(`╚══════════════════════════════════════════════════════`);
        return new Response(JSON.stringify({ error: 'invalid_grant', error_description: 'Authorization code expired or not found' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        });
      }
      authorizationCodes.delete(code);
    }
    
    // Validate code parameters
    if (codeData.client_id !== client_id || codeData.redirect_uri !== redirect_uri) {
      console.log(`║ Result: FAILED - Parameter mismatch`);
      console.log(`╚══════════════════════════════════════════════════════`);
      return new Response(JSON.stringify({ error: 'invalid_grant', error_description: 'Invalid authorization code parameters' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    // Validate PKCE if used
    if (codeData.code_challenge) {
      if (!code_verifier) {
        console.log(`║ Result: FAILED - Missing code verifier`);
        console.log(`╚══════════════════════════════════════════════════════`);
        return new Response(JSON.stringify({ error: 'invalid_grant', error_description: 'PKCE verification failed' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        });
      }
      
      const expectedChallenge = await sha256Base64Url(code_verifier);
      if (expectedChallenge !== codeData.code_challenge) {
        console.log(`║ Result: FAILED - PKCE challenge mismatch`);
        console.log(`╚══════════════════════════════════════════════════════`);
        return new Response(JSON.stringify({ error: 'invalid_grant', error_description: 'PKCE verification failed' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        });
      }
    }
    
    // Generate access token
    const access_token = generateRandomString(40);
    const refresh_token = generateRandomString(40);
    
    // Store token globally
    accessTokens.set(access_token, {
      client_id,
      sessionId: codeData.sessionId,
      serverDomain: codeData.serverDomain,
      hostname: codeData.hostname,
      scope: codeData.scope,
      created_at: Date.now()
    });
    
    const tokenResponse = {
      access_token,
      token_type: 'Bearer',
      expires_in: 3600,
      refresh_token,
      scope: codeData.scope || 'mcp'
    };
    
    console.log(`║ Result: SUCCESS`);
    console.log(`║ Access Token: ${access_token.substring(0, 8)}...`);
    console.log(`║ Scope: ${tokenResponse.scope}`);
    console.log(`╚══════════════════════════════════════════════════════`);
    
    return new Response(JSON.stringify(tokenResponse), {
      headers: { 'Content-Type': 'application/json' }
    });
  }
  
  if (grant_type === 'urn:ietf:params:oauth:grant-type:device_code') {
    const device_code = formData.get('device_code') as string;
    const client_id = formData.get('client_id') as string;
    
    const deviceData = deviceCodes.get(device_code);
    if (!deviceData) {
      return new Response(JSON.stringify({ error: 'expired_token' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    if (!deviceData.authorized) {
      return new Response(JSON.stringify({ error: 'authorization_pending' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    // Generate tokens
    const access_token = generateRandomString(40);
    const refresh_token = generateRandomString(40);
    
    deviceCodes.delete(device_code);
    
    return new Response(JSON.stringify({
      access_token,
      token_type: 'Bearer',
      expires_in: 3600,
      refresh_token,
      scope: 'mcp'
    }), {
      headers: { 'Content-Type': 'application/json' }
    });
  }
  
  return new Response(JSON.stringify({ error: 'unsupported_grant_type' }), {
    status: 400,
    headers: { 'Content-Type': 'application/json' }
  });
}

async function handleLocalOAuthDevice(request: Request, hostRoute: MCPRouteInfo, env: Env): Promise<Response> {
  const formData = await request.formData();
  const client_id = formData.get('client_id') as string;
  const scope = formData.get('scope') as string;
  
  const device_code = generateRandomString(32);
  const user_code = generateUserCode();
  const verification_uri = `https://${getCurrentDomain(request)}/oauth/device/verify`;
  const verification_uri_complete = `${verification_uri}?user_code=${user_code}`;
  
  // Store device code
  deviceCodes.set(device_code, {
    client_id,
    user_code,
    scope,
    authorized: false,
    created_at: Date.now()
  });
  
  // Map user code to device code for easy lookup
  userCodeMap.set(user_code, device_code);
  
  // Clean up old codes after 15 minutes
  setTimeout(() => {
    deviceCodes.delete(device_code);
    userCodeMap.delete(user_code);
  }, 900000);
  
  return new Response(JSON.stringify({
    device_code,
    user_code,
    verification_uri,
    verification_uri_complete,
    expires_in: 900,
    interval: 5
  }), {
    headers: { 'Content-Type': 'application/json' }
  });
}

async function handleLocalOAuthRevoke(request: Request, hostRoute: MCPRouteInfo, env: Env): Promise<Response> {
  const formData = await request.formData();
  const token = formData.get('token') as string;
  
  if (token) {
    accessTokens.delete(token);
  }
  
  return new Response(null, { status: 200 });
}

async function handleLocalOAuthIntrospect(request: Request, hostRoute: MCPRouteInfo, env: Env): Promise<Response> {
  const formData = await request.formData();
  const token = formData.get('token') as string;
  
  const tokenData = accessTokens.get(token);
  
  if (!tokenData) {
    return new Response(JSON.stringify({ active: false }), {
      headers: { 'Content-Type': 'application/json' }
    });
  }
  
  // Check if token is expired (1 hour)
  const isExpired = Date.now() - tokenData.created_at > 3600000;
  
  if (isExpired) {
    accessTokens.delete(token);
    return new Response(JSON.stringify({ active: false }), {
      headers: { 'Content-Type': 'application/json' }
    });
  }
  
  return new Response(JSON.stringify({
    active: true,
    scope: tokenData.scope || 'mcp',
    client_id: tokenData.client_id,
    token_type: 'Bearer',
    exp: Math.floor((tokenData.created_at + 3600000) / 1000)
  }), {
    headers: { 'Content-Type': 'application/json' }
  });
}

async function handleDeviceVerify(request: Request, hostRoute: MCPRouteInfo, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const user_code = url.searchParams.get('user_code') || '';
  
  const html = `<!doctype html><html><body>
    <h1>Device Authorization</h1>
    <form method="POST" action="/oauth/device/verify">
      <label>Enter code: <input name="user_code" value="${user_code}" required></label>
      <button type="submit">Authorize</button>
    </form>
  </body></html>`;
  
  return new Response(html, {
    headers: { 'Content-Type': 'text/html' }
  });
}

async function handleDeviceVerifyPost(request: Request, hostRoute: MCPRouteInfo, env: Env): Promise<Response> {
  const formData = await request.formData();
  const user_code = formData.get('user_code') as string;
  
  const device_code = userCodeMap.get(user_code);
  if (!device_code) {
    return new Response('Invalid code', { status: 400 });
  }
  
  const deviceData = deviceCodes.get(device_code);
  if (!deviceData) {
    return new Response('Code expired', { status: 400 });
  }
  
  // Mark as authorized
  deviceData.authorized = true;
  
  return new Response('Device authorized! You can close this window.', {
    headers: { 'Content-Type': 'text/plain' }
  });
}

async function handleClientRegistration(request: Request, hostRoute: MCPRouteInfo, env: Env): Promise<Response> {
  const body = await request.json() as any;
  
  // Simple static registration - return same client_id
  const response = {
    client_id: body.client_name || 'mcp-client',
    client_name: body.client_name,
    redirect_uris: body.redirect_uris,
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    token_endpoint_auth_method: 'none',
    scope: 'mcp read write'
  };
  
  return new Response(JSON.stringify(response), {
    headers: { 'Content-Type': 'application/json' },
    status: 201
  });
}

async function handleOAuthCallback(request: Request, env: Env): Promise<Response> {
  // This is handled by oauth-upstream.ts
  const { handleOAuthCallback: upstreamHandler } = await import('./oauth-upstream');
  return upstreamHandler(request, env);
}