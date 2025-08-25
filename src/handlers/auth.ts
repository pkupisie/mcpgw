/**
 * Authentication handlers for MCP OAuth Gateway
 */

import type { Env, SessionData } from '../types';
import { sessions } from '../stores';
import { generateSessionId } from '../utils/session';
import { generateRandomString } from '../utils/crypto';
import { getCurrentDomain } from '../utils/url';

export function handleLoginPage(request: Request): Response {
  const returnTo = new URL(request.url).searchParams.get('return_to') || '';
  
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
  
  if (user !== env.LOCAL_USER || pass !== env.LOCAL_PASSWORD) {
    return new Response('Invalid credentials', { status: 401 });
  }
  
  // Create session
  const sessionId = generateSessionId();
  const session: SessionData = {
    csrf: generateRandomString(32),
    localAuth: true,
    oauth: {}
  };
  
  sessions.set(sessionId, session);
  
  // Clean up old sessions periodically (simple memory management)
  if (sessions.size > 1000) {
    // Remove oldest sessions when we hit 1000
    const entries = Array.from(sessions.entries());
    for (let i = 0; i < 100; i++) {
      sessions.delete(entries[i][0]);
    }
  }
  
  const returnTo = formData.get('return_to') as string || '/';
  const redirectUrl = returnTo.startsWith('/') 
    ? `https://${getCurrentDomain(request)}${returnTo}`
    : '/';
  
  return new Response(null, {
    status: 302,
    headers: {
      'Location': redirectUrl,
      'Set-Cookie': `session=${sessionId}; HttpOnly; Secure; SameSite=Lax; Path=/`
    }
  });
}