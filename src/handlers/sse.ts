/**
 * Server-Sent Events (SSE) handler for MCP connections
 */

export async function tryConnectUpstreamSSE(serverDomain: string, accessToken: string): Promise<Response> {
  const upstreamUrl = `https://${serverDomain}/sse`;
  
  console.log(`Connecting to upstream SSE: ${upstreamUrl}`);
  
  try {
    const response = await fetch(upstreamUrl, {
      headers: {
        'Accept': 'text/event-stream',
        'Authorization': `Bearer ${accessToken}`,
        'Cache-Control': 'no-cache'
      }
    });
    
    return response;
  } catch (error) {
    console.error(`Failed to connect to upstream SSE:`, error);
    return new Response('Failed to connect to upstream SSE', { status: 502 });
  }
}