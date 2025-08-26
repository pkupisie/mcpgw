/**
 * Local OAuth handlers for downstream clients (Claude/ChatGPT)
 */

import type { Env, MCPRouteInfo, SessionData } from '../types';
import { getSessionId, getSession, generateSessionId, createDeviceSession, generateUserCode, saveSession } from '../utils/session';
import { generateRandomString, sha256Base64Url } from '../utils/crypto';
import { getCurrentDomain } from '../utils/url';
import { corsFor } from '../utils/cors';
import { initiateUpstreamOAuth } from './oauth-upstream';
import {
  getAuthCode,
  saveAuthCode,
  deleteAuthCode,
  getAccessToken,
  saveAccessToken,
  deleteAccessToken,
  getRefreshToken,
  saveRefreshToken,
  deleteRefreshToken,
  getRegisteredClient,
  saveRegisteredClient,
  getDeviceCode,
  saveDeviceCode,
  deleteDeviceCode,
  getUserCodeMapping,
  saveUserCodeMapping,
  deleteUserCodeMapping
} from '../utils/kv-storage';

export async function handleLocalOAuth(request: Request, hostRoute: MCPRouteInfo, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const origin = request.headers.get('Origin');
  
  // Handle OPTIONS preflight for all OAuth endpoints
  if (request.method === 'OPTIONS') {
    // For /oauth/register and /oauth/token, use specific CORS
    if (url.pathname === '/oauth/register' || url.pathname === '/oauth/token') {
      return new Response(null, {
        status: 204,
        headers: corsFor(origin)
      });
    }
    // For other OAuth endpoints, use standard CORS
    return new Response(null, {
      status: 204,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        'Vary': 'Origin'
      }
    });
  }
  
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
  let sessionId = getSessionId(request);
  let session = sessionId ? await getSession(sessionId, env) : null;
  
  // If no session exists, create one to store the pending auth request
  if (!session) {
    sessionId = generateSessionId();
    session = { csrf: generateRandomString(16), localAuth: false, oauth: {} };
    
    // Store the pending client auth request
    session.pendingClientAuth = {
      client_id: params.get('client_id') as string,
      redirect_uri: params.get('redirect_uri') as string,
      scope: params.get('scope') as string,
      state: params.get('state') as string,
      code_challenge: params.get('code_challenge') as string,
      code_challenge_method: params.get('code_challenge_method') as string,
      resource: params.get('resource') as string,
      serverDomain: hostRoute.serverDomain
    };
    
    await saveSession(sessionId, session, env);
  }
  
  // Log session status for debugging
  console.log(`║ Session Check: ${sessionId ? `Found (${sessionId.substring(0, 8)}...)` : 'Not found'}`);
  console.log(`║ Session Valid: ${session ? 'Yes' : 'No'}`);
  console.log(`║ Local Auth: ${session?.localAuth ? 'Yes' : 'No'}`)
  
  if (!session.localAuth) {
    // Redirect to login with return URL and session to merge
    const loginUrl = new URL(`https://${getCurrentDomain(request)}/login`);
    loginUrl.searchParams.set('return_to', request.url);
    // Pass the existing session ID to the login handler so we can merge it later
    loginUrl.searchParams.set('merge_session', sessionId!);
    console.log(`║ Redirecting to login: ${loginUrl.toString()}`);
    console.log(`╚══════════════════════════════════════════════════════`);
    
    const response = Response.redirect(loginUrl.toString(), 302);
    // If we created a new session, we need to set the cookie for the redirect
    if (!getSessionId(request)) {
      response.headers.set('Set-Cookie', `session=${sessionId}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=28800`);
    }
    return response;
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
  console.log(`║ Checking upstream tokens for: ${hostRoute.serverDomain}`);
  console.log(`║ Session OAuth data:`, JSON.stringify(session.oauth || {}));
  const upstreamTokens = session.oauth?.[hostRoute.serverDomain]?.tokens;
  console.log(`║ Upstream tokens exist: ${upstreamTokens ? 'Yes' : 'No'}`);
  if (upstreamTokens) {
    console.log(`║ Token details: access_token=${upstreamTokens.access_token?.substring(0, 8)}...`);
  }
  
  if (!upstreamTokens) {
    console.log(`║ No upstream tokens found - initiating upstream OAuth`);
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
  
  // If we reach here, we have upstream tokens - issue authorization code
  console.log(`║ Have upstream tokens - issuing authorization code`);
  console.log(`║ Upstream server: ${hostRoute.serverDomain}`);
  
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
  
  // Store authorization code with 10 minute TTL
  await saveAuthCode(env, code, codeData);
  
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
  const origin = request.headers.get('Origin');
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
    
    // Get authorization code from KV
    const codeData = await getAuthCode(env, code);
    if (!codeData) {
      console.log(`║ Result: FAILED - Code not found`);
      console.log(`╚══════════════════════════════════════════════════════`);
      return new Response(JSON.stringify({ error: 'invalid_grant', error_description: 'Authorization code expired or not found' }), {
        status: 400,
        headers: { 
          'Content-Type': 'application/json',
          'Cache-Control': 'no-store',
          ...corsFor(origin)
        }
      });
    }
    
    // Delete code after use
    await deleteAuthCode(env, code);
    
    // Validate code parameters
    if (codeData.client_id !== client_id || codeData.redirect_uri !== redirect_uri) {
      console.log(`║ Result: FAILED - Parameter mismatch`);
      console.log(`╚══════════════════════════════════════════════════════`);
      return new Response(JSON.stringify({ error: 'invalid_grant', error_description: 'Invalid authorization code parameters' }), {
        status: 400,
        headers: { 
          'Content-Type': 'application/json',
          'Cache-Control': 'no-store',
          ...corsFor(origin)
        }
      });
    }
    
    // Validate PKCE if used
    if (codeData.code_challenge) {
      if (!code_verifier) {
        console.log(`║ Result: FAILED - Missing code verifier`);
        console.log(`╚══════════════════════════════════════════════════════`);
        return new Response(JSON.stringify({ error: 'invalid_grant', error_description: 'PKCE verification failed' }), {
          status: 400,
          headers: { 
            'Content-Type': 'application/json',
            'Cache-Control': 'no-store',
            ...corsFor(origin)
          }
        });
      }
      
      const expectedChallenge = await sha256Base64Url(code_verifier);
      if (expectedChallenge !== codeData.code_challenge) {
        console.log(`║ Result: FAILED - PKCE challenge mismatch`);
        console.log(`╚══════════════════════════════════════════════════════`);
        return new Response(JSON.stringify({ error: 'invalid_grant', error_description: 'PKCE verification failed' }), {
          status: 400,
          headers: { 
            'Content-Type': 'application/json',
            'Cache-Control': 'no-store',
            ...corsFor(origin)
          }
        });
      }
    }
    
    // Generate access token
    const access_token = generateRandomString(40);
    const refresh_token = generateRandomString(40);
    const now = Date.now();
    
    // Store access token in KV and memory
    const accessTokenData = {
      client_id,
      sessionId: codeData.sessionId,
      serverDomain: codeData.serverDomain,
      hostname: codeData.hostname,
      scope: codeData.scope,
      created_at: now
    };
    
    // Store access token with 1 hour TTL
    await saveAccessToken(env, access_token, accessTokenData);
    
    // Store refresh token in KV and memory
    const refreshTokenData = {
      client_id,
      sessionId: codeData.sessionId,
      serverDomain: codeData.serverDomain,
      hostname: codeData.hostname,
      scope: codeData.scope,
      created_at: now,
      access_token
    };
    
    // Store refresh token with 30 day TTL
    await saveRefreshToken(env, refresh_token, refreshTokenData);
    
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
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store',
        ...corsFor(origin)
      }
    });
  }
  
  if (grant_type === 'refresh_token') {
    const refresh_token = formData.get('refresh_token') as string;
    const client_id = formData.get('client_id') as string;
    const scope = formData.get('scope') as string;  // Optional - if omitted, use original scope
    
    console.log(`║ Refresh Token: ${refresh_token?.substring(0, 8)}...`);
    console.log(`║ Client ID: ${client_id}`);
    
    if (!refresh_token) {
      console.log(`║ Result: FAILED - Missing refresh_token`);
      console.log(`╚══════════════════════════════════════════════════════`);
      return new Response(JSON.stringify({ 
        error: 'invalid_request', 
        error_description: 'missing refresh_token' 
      }), {
        status: 400,
        headers: {
          'Content-Type': 'application/json',
          'Cache-Control': 'no-store',
          ...corsFor(origin)
        }
      });
    }
    
    // Get refresh token from KV
    const refreshTokenData = await getRefreshToken(env, refresh_token);
    if (!refreshTokenData) {
      console.log(`║ Result: FAILED - Invalid refresh token`);
      console.log(`╚══════════════════════════════════════════════════════`);
      return new Response(JSON.stringify({ 
        error: 'invalid_grant', 
        error_description: 'Invalid or expired refresh token' 
      }), {
        status: 400,
        headers: {
          'Content-Type': 'application/json',
          'Cache-Control': 'no-store',
          ...corsFor(origin)
        }
      });
    }
    
    // Validate client_id if provided
    if (client_id && refreshTokenData.client_id !== client_id) {
      console.log(`║ Result: FAILED - Client ID mismatch`);
      console.log(`╚══════════════════════════════════════════════════════`);
      return new Response(JSON.stringify({ 
        error: 'invalid_grant', 
        error_description: 'Client ID mismatch' 
      }), {
        status: 400,
        headers: {
          'Content-Type': 'application/json',
          'Cache-Control': 'no-store',
          ...corsFor(origin)
        }
      });
    }
    
    // Check if refresh token is expired (30 days)
    const refreshTokenAge = Date.now() - refreshTokenData.created_at;
    if (refreshTokenAge > 30 * 24 * 60 * 60 * 1000) {
      // Delete from KV and memory
      await deleteRefreshToken(env, refresh_token);
      console.log(`║ Result: FAILED - Refresh token expired`);
      console.log(`╚══════════════════════════════════════════════════════`);
      return new Response(JSON.stringify({ 
        error: 'invalid_grant', 
        error_description: 'Refresh token expired' 
      }), {
        status: 400,
        headers: {
          'Content-Type': 'application/json',
          'Cache-Control': 'no-store',
          ...corsFor(origin)
        }
      });
    }
    
    // Delete old access token if it exists
    if (refreshTokenData.access_token) {
      await deleteAccessToken(env, refreshTokenData.access_token);
    }
    
    // Generate new tokens
    const new_access_token = generateRandomString(40);
    const new_refresh_token = generateRandomString(40);
    const now = Date.now();
    
    // Store new access token in KV and memory
    const newAccessTokenData = {
      client_id: refreshTokenData.client_id,
      sessionId: refreshTokenData.sessionId,
      serverDomain: refreshTokenData.serverDomain,
      hostname: refreshTokenData.hostname,
      scope: scope || refreshTokenData.scope,
      created_at: now
    };
    
    await saveAccessToken(env, new_access_token, newAccessTokenData);
    
    // Delete old refresh token
    await deleteRefreshToken(env, refresh_token);
    
    // Store new refresh token in KV and memory
    const newRefreshTokenData = {
      client_id: refreshTokenData.client_id,
      sessionId: refreshTokenData.sessionId,
      serverDomain: refreshTokenData.serverDomain,
      hostname: refreshTokenData.hostname,
      scope: scope || refreshTokenData.scope,
      created_at: now,
      access_token: new_access_token
    };
    
    await saveRefreshToken(env, new_refresh_token, newRefreshTokenData);
    
    const tokenResponse = {
      access_token: new_access_token,
      token_type: 'Bearer',
      expires_in: 3600,
      refresh_token: new_refresh_token,
      scope: scope || refreshTokenData.scope || 'mcp read write'
    };
    
    console.log(`║ Result: SUCCESS`);
    console.log(`║ New Access Token: ${new_access_token.substring(0, 8)}...`);
    console.log(`║ New Refresh Token: ${new_refresh_token.substring(0, 8)}...`);
    console.log(`║ Scope: ${tokenResponse.scope}`);
    console.log(`╚══════════════════════════════════════════════════════`);
    
    return new Response(JSON.stringify(tokenResponse), {
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store',
        ...corsFor(origin)
      }
    });
  }
  
  if (grant_type === 'urn:ietf:params:oauth:grant-type:device_code') {
    const device_code = formData.get('device_code') as string;
    const client_id = formData.get('client_id') as string;
    
    // Get device code from KV
    const deviceData = await getDeviceCode(env, device_code);
    if (!deviceData) {
      return new Response(JSON.stringify({ error: 'expired_token' }), {
        status: 400,
        headers: { 
          'Content-Type': 'application/json',
          'Cache-Control': 'no-store',
          ...corsFor(origin)
        }
      });
    }
    
    if (!deviceData.authorized) {
      return new Response(JSON.stringify({ error: 'authorization_pending' }), {
        status: 400,
        headers: { 
          'Content-Type': 'application/json',
          'Cache-Control': 'no-store',
          ...corsFor(origin)
        }
      });
    }
    
    // Generate tokens
    const access_token = generateRandomString(40);
    const refresh_token = generateRandomString(40);
    const now = Date.now();
    const hostname = new URL(request.url).hostname;
    
    // Store access token in KV and memory
    const accessTokenData = {
      client_id: deviceData.client_id,
      sessionId: '', // Device flow doesn't use sessionId
      serverDomain: hostRoute.serverDomain,
      hostname: hostname,
      scope: deviceData.scope || 'mcp',
      created_at: now
    };
    
    await saveAccessToken(env, access_token, accessTokenData);
    
    // Store refresh token in KV and memory
    const refreshTokenData = {
      client_id: deviceData.client_id,
      sessionId: '', // Device flow doesn't use sessionId
      serverDomain: hostRoute.serverDomain,
      hostname: hostname,
      scope: deviceData.scope || 'mcp',
      created_at: now,
      access_token
    };
    
    await saveRefreshToken(env, refresh_token, refreshTokenData);
    
    // Delete device code
    await deleteDeviceCode(env, device_code);
    
    return new Response(JSON.stringify({
      access_token,
      token_type: 'Bearer',
      expires_in: 3600,
      refresh_token,
      scope: deviceData.scope || 'mcp'
    }), {
      headers: { 
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store',
        ...corsFor(origin)
      }
    });
  }
  
  console.log(`║ Result: FAILED - Unsupported grant type: ${grant_type}`);
  console.log(`╚══════════════════════════════════════════════════════`);
  
  return new Response(JSON.stringify({ 
    error: 'unsupported_grant_type',
    error_description: 'Only authorization_code and refresh_token grants are supported'
  }), {
    status: 400,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store',
      ...corsFor(origin)
    }
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
  
  // Store device code in KV and memory
  const deviceData = {
    client_id,
    user_code,
    scope,
    authorized: false,
    created_at: Date.now()
  };
  
  // Store device code and user code mapping with 15 minute TTL
  await saveDeviceCode(env, device_code, deviceData);
  await saveUserCodeMapping(env, user_code, device_code);
  
  return new Response(JSON.stringify({
    device_code,
    user_code,
    verification_uri,
    verification_uri_complete,
    expires_in: 900,
    interval: 5
  }), {
    headers: { 
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store'
    }
  });
}

async function handleLocalOAuthRevoke(request: Request, hostRoute: MCPRouteInfo, env: Env): Promise<Response> {
  const formData = await request.formData();
  const token = formData.get('token') as string;
  const token_type_hint = formData.get('token_type_hint') as string;
  
  if (token) {
    // Try to determine token type and delete from appropriate stores
    if (token_type_hint === 'refresh_token' || !token_type_hint) {
      // Delete as refresh token
      await deleteRefreshToken(env, token);
    }
    
    if (token_type_hint === 'access_token' || !token_type_hint) {
      // Delete as access token
      await deleteAccessToken(env, token);
    }
  }
  
  return new Response(null, { status: 200 });
}

async function handleLocalOAuthIntrospect(request: Request, hostRoute: MCPRouteInfo, env: Env): Promise<Response> {
  const formData = await request.formData();
  const token = formData.get('token') as string;
  const token_type_hint = formData.get('token_type_hint') as string;
  
  // Try to find token in KV first, then memory
  let tokenData: any = null;
  let tokenType: string = '';
  
  // Check as access token first (most common)
  if (!token_type_hint || token_type_hint === 'access_token') {
    tokenData = await getAccessToken(env, token);
    if (tokenData) tokenType = 'access_token';
  }
  
  // Check as refresh token if not found
  if (!tokenData && (!token_type_hint || token_type_hint === 'refresh_token')) {
    tokenData = await getRefreshToken(env, token);
    if (tokenData) tokenType = 'refresh_token';
  }
  
  if (!tokenData) {
    return new Response(JSON.stringify({ active: false }), {
      headers: { 
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store'
      }
    });
  }
  
  // Check expiration based on token type
  const expirationMs = tokenType === 'refresh_token' ? 30 * 24 * 60 * 60 * 1000 : 3600000;
  const isExpired = Date.now() - tokenData.created_at > expirationMs;
  
  if (isExpired) {
    // Clean up expired token
    if (tokenType === 'refresh_token') {
      await deleteRefreshToken(env, token);
    } else {
      await deleteAccessToken(env, token);
    }
    
    return new Response(JSON.stringify({ active: false }), {
      headers: { 
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store'
      }
    });
  }
  
  return new Response(JSON.stringify({
    active: true,
    scope: tokenData.scope || 'mcp',
    client_id: tokenData.client_id,
    token_type: 'Bearer',
    exp: Math.floor((tokenData.created_at + expirationMs) / 1000)
  }), {
    headers: { 
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store'
    }
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
  
  // Look up device code from user code mapping
  // Get device code from user code mapping
  const device_code = await getUserCodeMapping(env, user_code);
  
  if (!device_code) {
    return new Response('Invalid code', { status: 400 });
  }
  
  // Get device data from KV
  const deviceData = await getDeviceCode(env, device_code);
  
  if (!deviceData) {
    return new Response('Code expired', { status: 400 });
  }
  
  // Mark as authorized and update in KV
  deviceData.authorized = true;
  
  // Update device code with authorization
  await saveDeviceCode(env, device_code, deviceData);
  
  return new Response('Device authorized! You can close this window.', {
    headers: { 'Content-Type': 'text/plain' }
  });
}

async function handleClientRegistration(request: Request, hostRoute: MCPRouteInfo, env: Env): Promise<Response> {
  const origin = request.headers.get('Origin');
  
  try {
    const body = await request.json() as any;
    const currentDomain = getCurrentDomain(request);
    
    // Generate a unique client_id
    const client_id = `mcp_${generateRandomString(12)}`;
    
    // RFC 7591 compliant response
    const response = {
      client_id,
      client_id_issued_at: Math.floor(Date.now() / 1000),
      client_name: body.client_name || 'MCP Client',
      redirect_uris: body.redirect_uris || [`https://${currentDomain}/oauth/callback`],
      grant_types: body.grant_types || ['authorization_code', 'refresh_token'],
      response_types: body.response_types || ['code'],
      token_endpoint_auth_method: body.token_endpoint_auth_method || 'none',
      scope: body.scope || 'mcp read write',
      // Optional fields for completeness
      client_secret_expires_at: 0,  // Never expires
      registration_access_token: `reg_${generateRandomString(32)}`,
      registration_client_uri: `https://${currentDomain}/oauth/register/${client_id}`
    };
    
    // Store client registration if needed (for now, we're stateless)
    console.log(`Client registered: ${client_id} from origin: ${origin}`);
    
    return new Response(JSON.stringify(response), {
      status: 201,
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store',
        ...corsFor(origin)
      }
    });
  } catch (error) {
    console.error('Client registration error:', error);
    return new Response(JSON.stringify({ 
      error: 'invalid_client_metadata',
      error_description: 'Failed to process client registration'
    }), {
      status: 400,
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store',
        ...corsFor(origin)
      }
    });
  }
}

async function handleOAuthCallback(request: Request, env: Env): Promise<Response> {
  // This is handled by oauth-upstream.ts
  const { handleOAuthCallback: upstreamHandler } = await import('./oauth-upstream');
  return upstreamHandler(request, env);
}