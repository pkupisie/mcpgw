/**
 * Authentication handlers for MCP OAuth Gateway
 */

import type { Env, SessionData } from '../types';
import { generateSessionId, saveSession, getSession } from '../utils/session';
import { generateRandomString } from '../utils/crypto';
import { getCurrentDomain } from '../utils/url';

export function handleLoginPage(request: Request): Response {
  const returnTo = new URL(request.url).searchParams.get('return_to') || '';
  
  console.log(`\n╔══ LOGIN PAGE RENDERED ══════════════════════════════`);
  console.log(`║ Return To: ${returnTo || '(none)'}`)
  console.log(`╚══════════════════════════════════════════════════════`);
  
  const html = `<!doctype html><html><body>
    <h1>MCP Gateway Login</h1>
    <form method="POST" action="/login">
      <label>User: <input name="user" required></label><br><br>
      <label>Pass: <input name="pass" type="password" required></label><br><br>
      <input type="hidden" name="return_to" value="${returnTo}">
      <button type="submit">Sign in</button>
    </form>
  </body></html>`;
  
  return new Response(html, {
    headers: { 'Content-Type': 'text/html' }
  });
}

export async function handleLogin(request: Request, env: Env): Promise<Response> {
  const formData = await request.formData();
  const user = formData.get('user') as string;
  const pass = formData.get('pass') as string;
  const url = new URL(request.url);
  
  console.log(`\n╔══ LOGIN ATTEMPT ════════════════════════════════════`);
  console.log(`║ User: ${user}`);
  
  if (user !== env.LOCAL_USER || pass !== env.LOCAL_PASSWORD) {
    console.log(`║ Result: FAILED - Invalid credentials`);
    console.log(`╚══════════════════════════════════════════════════════`);
    return new Response('Invalid credentials', { status: 401 });
  }
  
  // Check if we need to merge an old session
  const mergeSessionId = url.searchParams.get('merge_session');
  let oldSessionData: SessionData | null = null;
  if (mergeSessionId) {
    oldSessionData = await getSession(mergeSessionId, env);
    console.log(`║ Merging session: ${mergeSessionId.substring(0, 8)}...`);
    if (oldSessionData?.pendingClientAuth) {
      console.log(`║ Found pending auth for: ${oldSessionData.pendingClientAuth.client_id}`);
    }
  }
  
  // Create a new session to prevent session fixation
  const newSessionId = generateSessionId();
  const newSession: SessionData = {
    csrf: generateRandomString(32),
    localAuth: true,
    oauth: {},
    // If we have old session data, merge its pending auth
    ...(oldSessionData?.pendingClientAuth && { pendingClientAuth: oldSessionData.pendingClientAuth })
  };
  
  // Save the new session to KV
  await saveSession(newSessionId, newSession, env);
  
  console.log(`║ Session Created: ${newSessionId.substring(0, 8)}...`);
  
  // Check for return_to parameter - it could be a full URL with query params
  const returnTo = formData.get('return_to') as string || 
                   `https://${getCurrentDomain(request)}/`;
  
  console.log(`║ Result: SUCCESS`);
  console.log(`║ Session ID: ${newSessionId.substring(0, 8)}...`);
  console.log(`║ Return To: ${returnTo}`);
  console.log(`╚══════════════════════════════════════════════════════`);
  
  return new Response(null, {
    status: 302,
    headers: {
      'Location': returnTo,
      'Set-Cookie': `session=${newSessionId}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=28800`
    }
  });
}