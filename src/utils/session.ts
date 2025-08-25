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

// Get session data from KV store or memory fallback
export async function getSession(sessionId: string, env: Env): Promise<SessionData | null> {
  // Try KV first if available
  if (env.SESSIONS) {
    try {
      const sessionStr = await env.SESSIONS.get(sessionId);
      if (sessionStr) {
        const session = JSON.parse(sessionStr) as SessionData;
        // Also cache in memory for this request
        sessions.set(sessionId, session);
        return session;
      }
    } catch (error) {
      console.error('Failed to get session from KV:', error);
    }
  }
  
  // Fallback to in-memory store
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

// Save session to KV store and memory
export async function saveSession(sessionId: string, session: SessionData, env: Env): Promise<void> {
  // Save to memory first
  sessions.set(sessionId, session);
  
  // Save to KV if available
  if (env.SESSIONS) {
    try {
      // Store with 8 hour TTL (28800 seconds)
      await env.SESSIONS.put(sessionId, JSON.stringify(session), {
        expirationTtl: 28800
      });
    } catch (error) {
      console.error('Failed to save session to KV:', error);
    }
  }
}