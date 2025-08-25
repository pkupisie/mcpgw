/**
 * Token management utilities for MCP OAuth Gateway
 */

import type { SessionData, MCPServerConfig, Env } from '../types';

// Check if token is expired with optional buffer
export function isTokenExpired(serverOAuth: any, bufferSeconds: number = 300): boolean {
  if (!serverOAuth?.expiresAt) return true; // If no expiration time, consider it expired
  return Date.now() > (serverOAuth.expiresAt - bufferSeconds * 1000); // Check if expired or expires within buffer
}

// Refresh upstream OAuth token
export async function refreshUpstreamToken(serverDomain: string, session: SessionData, env: Env): Promise<boolean> {
  const serverData = session.oauth?.[serverDomain];
  
  if (!serverData?.tokens?.refresh_token) {
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