/**
 * Token management utilities for MCP OAuth Gateway
 */

import type { SessionData, Env } from '../types';
import { saveSession } from './session';

// Check if token is expired with optional buffer
export function isTokenExpired(serverOAuth: any, bufferSeconds: number = 300): boolean {
  if (!serverOAuth?.expiresAt) return true; // If no expiration time, consider it expired
  return Date.now() > (serverOAuth.expiresAt - bufferSeconds * 1000); // Check if expired or expires within buffer
}

// Refresh upstream OAuth token
export async function refreshUpstreamToken(serverDomain: string, session: SessionData, env: Env, sessionId?: string): Promise<boolean> {
  const serverData = session.oauth?.[serverDomain];
  
  if (!serverData?.tokens?.refresh_token) {
    console.error('No refresh token available');
    return false;
  }
  
  // Get stored OAuth config from session
  const storedConfig = serverData.config;
  if (!storedConfig) {
    console.error(`No stored OAuth config for ${serverDomain}`);
    return false;
  }
  
  const tokenUrl = new URL(storedConfig.token_endpoint);
  const tokenBody = new URLSearchParams({
    grant_type: 'refresh_token',
    refresh_token: serverData.tokens.refresh_token,
    client_id: storedConfig.client_id
  });
  
  if (storedConfig.client_secret) {
    tokenBody.set('client_secret', storedConfig.client_secret);
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
    
    // Save updated session if sessionId provided
    if (sessionId) {
      await saveSession(sessionId, session, env);
    }
    
    return true;
  } catch (error) {
    console.error(`Failed to refresh token: ${error}`);
    return false;
  }
}