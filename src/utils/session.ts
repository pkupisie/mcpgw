/**
 * Session management utilities for MCP OAuth Gateway
 */

import type { SessionData, Env } from '../types';
import { generateRandomString } from './crypto';
import { getSession as kvGetSession, saveSession as kvSaveSession } from './kv-storage';

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

// Get session data from KV store
export async function getSession(sessionId: string, env: Env): Promise<SessionData | null> {
  return await kvGetSession(env, sessionId);
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

// Save session to KV store
export async function saveSession(sessionId: string, session: SessionData, env: Env): Promise<void> {
  await kvSaveSession(env, sessionId, session);
}