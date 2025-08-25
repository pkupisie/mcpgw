/**
 * Dashboard handler for MCP OAuth Gateway
 */

import type { Env, MCPServerConfig } from '../types';
import { getSessionId, getSession } from '../utils/session';
import { getCurrentDomain } from '../utils/url';
import { generateEncodedHostname } from '../utils/url';

export async function handleDashboard(request: Request, env: Env): Promise<Response> {
  const sessionId = getSessionId(request);
  const session = sessionId ? await getSession(sessionId, env) : null;
  
  if (!session || !session.localAuth) {
    return Response.redirect(`https://${getCurrentDomain(request)}/login`, 302);
  }
  
  // Parse MCP servers
  let mcpServers: MCPServerConfig[] = [];
  try {
    mcpServers = JSON.parse(env.MCP_SERVERS || '[]');
  } catch (e) {
    console.error('Failed to parse MCP_SERVERS:', e);
  }
  
  let serversHtml = '<h2>MCP Servers</h2>';
  if (mcpServers.length === 0) {
    serversHtml += '<p>No MCP servers configured.</p>';
  } else {
    serversHtml += '<ul>';
    for (const server of mcpServers) {
      const isConnected = !!(session.oauth?.[server.domain]?.tokens);
      const encodedHostname = generateEncodedHostname(server.domain, env.DOMAIN_ROOT);
      const encodedUrl = `https://${encodedHostname}/`;
      serversHtml += `
        <li>
          <strong>${server.name}</strong> (${server.domain}) 
          ${isConnected ? '✅ Connected' : '❌ Not connected'}
          <br><small>URL: <code>${encodedUrl}</code></small>
          ${!isConnected ? `<br><a href="/oauth/start?server=${encodeURIComponent(server.domain)}">Connect</a>` : ''}
        </li>`;
    }
    serversHtml += '</ul>';
  }
  
  const html = `<!doctype html><html><head><title>MCP Gateway</title></head><body>
    <h1>MCP OAuth Gateway</h1>
    <p>Domain root: <code>${env.DOMAIN_ROOT}</code></p>
    ${serversHtml}
    <h3>Add New Server</h3>
    <form method="GET" action="/encode">
      <label>Domain: <input name="domain" placeholder="mcp.example.com" required></label>
      <button type="submit">Generate URL</button>
    </form>
  </body></html>`;
  
  return new Response(html, {
    headers: { 'Content-Type': 'text/html' }
  });
}