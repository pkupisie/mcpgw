/**
 * Session management utilities for MCP OAuth Gateway
 */

import type { SessionData, Env } from '../types';
import { sessions } from '../stores';
import { generateRandomString } from './crypto';

// Extract session ID from request cookies
export function getSessionId(request: Request): string | null {
  const cookieHeader = request.headers.get('Cookie');
  if (!cookieHeader) return null;
  
  const cookies: Record<string, string> = {};
  cookieHeader.split(';').forEach(c => {
    const [key, ...value] = c.trim().split('=');
    if (key && value.length > 0) {
      cookies[key] = value.join('=');
    }
  });
  
  return cookies.session || null;
}

// Get session data from store
export async function getSession(sessionId: string, env: Env): Promise<SessionData | null> {
  return sessions.get(sessionId) || null;
}

// Generate new session ID
export function generateSessionId(): string {
  return generateRandomString(32);
}

// Create a new device session
export function createDeviceSession(): SessionData {
  return {
    csrf: generateRandomString(16),
    localAuth: false,
    deviceCodes: {}
  };
}

// Generate user code for device flow
export function generateUserCode(): string {
  return generateRandomString(8).toUpperCase();
}