/**
 * Utility handlers for MCP OAuth Gateway
 */

import type { Env } from '../types';
import { getSessionId, getSession } from '../utils/session';
import { getCurrentDomain, generateEncodedHostname } from '../utils/url';

export async function handleEncode(request: Request, env: Env): Promise<Response> {
  const sessionId = getSessionId(request);
  const session = sessionId ? await getSession(sessionId, env) : null;
  
  if (!session || !session.localAuth) {
    return Response.redirect(`https://${getCurrentDomain(request)}/login?return_to=/encode`, 302);
  }
  
  const url = new URL(request.url);
  const domain = url.searchParams.get('domain');
  
  if (!domain) {
    return new Response('Missing domain parameter', { status: 400 });
  }
  
  const encodedHostname = generateEncodedHostname(domain, env.DOMAIN_ROOT);
  const encodedUrl = `https://${encodedHostname}/`;
  
  const html = `<!doctype html><html><body>
    <h1>Encoded URL Generated</h1>
    <p>Original domain: <code>${domain}</code></p>
    <p>Encoded URL: <code>${encodedUrl}</code></p>
    <p>Use this URL as your MCP server endpoint.</p>
    <a href="/">Back to dashboard</a>
  </body></html>`;
  
  return new Response(html, {
    headers: { 'Content-Type': 'text/html' }
  });
}