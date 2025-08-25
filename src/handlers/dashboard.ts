/**
 * Dashboard handler for MCP OAuth Gateway
 */

import type { Env } from '../types';
import { getSessionId, getSession } from '../utils/session';
import { getCurrentDomain } from '../utils/url';
import { generateEncodedHostname } from '../utils/url';

export async function handleDashboard(request: Request, env: Env): Promise<Response> {
  const sessionId = getSessionId(request);
  const session = sessionId ? await getSession(sessionId, env) : null;
  
  if (!session || !session.localAuth) {
    return Response.redirect(`https://${getCurrentDomain(request)}/login`, 302);
  }
  
  // Show connected servers from session
  let serversHtml = '<h2>Connected MCP Servers</h2>';
  const connectedServers = Object.entries(session.oauth || {});
  
  if (connectedServers.length === 0) {
    serversHtml += '<p>No MCP servers connected yet. Use the form below to connect to a server.</p>';
  } else {
    serversHtml += '<ul>';
    for (const [domain, data] of connectedServers) {
      const isConnected = !!(data.tokens);
      const encodedHostname = generateEncodedHostname(domain, env.DOMAIN_ROOT);
      const encodedUrl = `https://${encodedHostname}/`;
      serversHtml += `
        <li>
          <strong>${domain}</strong> 
          ${isConnected ? '✅ Connected' : '⏳ Auth in progress'}
          <br><small>MCP URL for Claude: <code>${encodedUrl}</code></small>
          ${!isConnected ? `<br><a href="/oauth/start?server=${encodeURIComponent(domain)}">Reconnect</a>` : ''}
        </li>`;
    }
    serversHtml += '</ul>';
  }
  
  const html = `<!doctype html><html><head><title>MCP Gateway</title></head><body>
    <h1>MCP OAuth Gateway</h1>
    <p>Domain root: <code>${env.DOMAIN_ROOT}</code></p>
    ${serversHtml}
    <h3>Connect to New MCP Server</h3>
    <p>Enter the domain of an MCP server that supports OAuth:</p>
    <form method="GET" action="/encode">
      <label>Server Domain: <input name="domain" placeholder="mcp.example.com" required></label>
      <button type="submit">Generate Encoded URL</button>
    </form>
    <p><small>The gateway will automatically discover OAuth endpoints from the server.</small></p>
  </body></html>`;
  
  return new Response(html, {
    headers: { 'Content-Type': 'text/html' }
  });
}