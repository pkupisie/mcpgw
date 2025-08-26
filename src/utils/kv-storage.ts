/**
 * Unified KV storage utilities for MCP OAuth Gateway
 * All data is stored in a single KV namespace with prefixed keys
 */

import type { 
  SessionData, 
  RegisteredClient, 
  AuthorizationCode, 
  AccessToken, 
  RefreshToken,
  Env 
} from '../types';

// TTL configurations (in seconds)
const TTL_CONFIG = {
  session: 28800,        // 8 hours
  auth_code: 600,        // 10 minutes
  access_token: 3600,    // 1 hour
  refresh_token: 2592000, // 30 days
  device_code: 900,      // 15 minutes
  user_code: 900,        // 15 minutes
  correlation: 300,      // 5 minutes
  client: null           // Never expires
} as const;

// Key prefixes for different data types
const KEY_PREFIX = {
  session: 'session:',
  auth_code: 'auth_code:',
  access_token: 'access_token:',
  refresh_token: 'refresh_token:',
  client: 'client:',
  device_code: 'device_code:',
  user_code: 'user_code:',
  correlation: 'correlation:'
} as const;

// Generic KV operations
async function kvGet(env: Env, key: string): Promise<string | null> {
  if (!env.MCPGW) {
    console.error('KV namespace MCPGW not configured');
    return null;
  }
  
  try {
    return await env.MCPGW.get(key);
  } catch (error) {
    console.error(`Failed to get KV key ${key}:`, error);
    return null;
  }
}

async function kvPut(env: Env, key: string, value: string, ttl: number | null): Promise<void> {
  if (!env.MCPGW) {
    console.error('KV namespace MCPGW not configured');
    return;
  }
  
  try {
    const options = ttl ? { expirationTtl: ttl } : undefined;
    await env.MCPGW.put(key, value, options);
  } catch (error) {
    console.error(`Failed to put KV key ${key}:`, error);
    throw error;
  }
}

async function kvDelete(env: Env, key: string): Promise<void> {
  if (!env.MCPGW) {
    console.error('KV namespace MCPGW not configured');
    return;
  }
  
  try {
    await env.MCPGW.delete(key);
  } catch (error) {
    console.error(`Failed to delete KV key ${key}:`, error);
  }
}

// Session storage
export async function getSession(env: Env, sessionId: string): Promise<SessionData | null> {
  const key = `${KEY_PREFIX.session}${sessionId}`;
  const data = await kvGet(env, key);
  return data ? JSON.parse(data) : null;
}

export async function saveSession(env: Env, sessionId: string, session: SessionData): Promise<void> {
  const key = `${KEY_PREFIX.session}${sessionId}`;
  await kvPut(env, key, JSON.stringify(session), TTL_CONFIG.session);
}

export async function deleteSession(env: Env, sessionId: string): Promise<void> {
  const key = `${KEY_PREFIX.session}${sessionId}`;
  await kvDelete(env, key);
}

// Authorization code storage
export async function getAuthCode(env: Env, code: string): Promise<AuthorizationCode | null> {
  const key = `${KEY_PREFIX.auth_code}${code}`;
  const data = await kvGet(env, key);
  return data ? JSON.parse(data) : null;
}

export async function saveAuthCode(env: Env, code: string, codeData: AuthorizationCode): Promise<void> {
  const key = `${KEY_PREFIX.auth_code}${code}`;
  await kvPut(env, key, JSON.stringify(codeData), TTL_CONFIG.auth_code);
}

export async function deleteAuthCode(env: Env, code: string): Promise<void> {
  const key = `${KEY_PREFIX.auth_code}${code}`;
  await kvDelete(env, key);
}

// Access token storage
export async function getAccessToken(env: Env, token: string): Promise<AccessToken | null> {
  const key = `${KEY_PREFIX.access_token}${token}`;
  const data = await kvGet(env, key);
  return data ? JSON.parse(data) : null;
}

export async function saveAccessToken(env: Env, token: string, tokenData: AccessToken): Promise<void> {
  const key = `${KEY_PREFIX.access_token}${token}`;
  await kvPut(env, key, JSON.stringify(tokenData), TTL_CONFIG.access_token);
}

export async function deleteAccessToken(env: Env, token: string): Promise<void> {
  const key = `${KEY_PREFIX.access_token}${token}`;
  await kvDelete(env, key);
}

// Refresh token storage
export async function getRefreshToken(env: Env, token: string): Promise<RefreshToken | null> {
  const key = `${KEY_PREFIX.refresh_token}${token}`;
  const data = await kvGet(env, key);
  return data ? JSON.parse(data) : null;
}

export async function saveRefreshToken(env: Env, token: string, tokenData: RefreshToken): Promise<void> {
  const key = `${KEY_PREFIX.refresh_token}${token}`;
  await kvPut(env, key, JSON.stringify(tokenData), TTL_CONFIG.refresh_token);
}

export async function deleteRefreshToken(env: Env, token: string): Promise<void> {
  const key = `${KEY_PREFIX.refresh_token}${token}`;
  await kvDelete(env, key);
}

// Client registration storage
export async function getRegisteredClient(env: Env, clientId: string): Promise<RegisteredClient | null> {
  const key = `${KEY_PREFIX.client}${clientId}`;
  const data = await kvGet(env, key);
  return data ? JSON.parse(data) : null;
}

export async function saveRegisteredClient(env: Env, clientId: string, client: RegisteredClient): Promise<void> {
  const key = `${KEY_PREFIX.client}${clientId}`;
  await kvPut(env, key, JSON.stringify(client), TTL_CONFIG.client);
}

// Device code storage
export async function getDeviceCode(env: Env, deviceCode: string): Promise<any | null> {
  const key = `${KEY_PREFIX.device_code}${deviceCode}`;
  const data = await kvGet(env, key);
  return data ? JSON.parse(data) : null;
}

export async function saveDeviceCode(env: Env, deviceCode: string, deviceData: any): Promise<void> {
  const key = `${KEY_PREFIX.device_code}${deviceCode}`;
  await kvPut(env, key, JSON.stringify(deviceData), TTL_CONFIG.device_code);
}

export async function deleteDeviceCode(env: Env, deviceCode: string): Promise<void> {
  const key = `${KEY_PREFIX.device_code}${deviceCode}`;
  await kvDelete(env, key);
}

// User code to device code mapping
export async function getUserCodeMapping(env: Env, userCode: string): Promise<string | null> {
  const key = `${KEY_PREFIX.user_code}${userCode}`;
  return await kvGet(env, key);
}

export async function saveUserCodeMapping(env: Env, userCode: string, deviceCode: string): Promise<void> {
  const key = `${KEY_PREFIX.user_code}${userCode}`;
  await kvPut(env, key, deviceCode, TTL_CONFIG.user_code);
}

export async function deleteUserCodeMapping(env: Env, userCode: string): Promise<void> {
  const key = `${KEY_PREFIX.user_code}${userCode}`;
  await kvDelete(env, key);
}

// Request correlation storage
export async function getCorrelation(env: Env, correlationId: string): Promise<string | null> {
  const key = `${KEY_PREFIX.correlation}${correlationId}`;
  return await kvGet(env, key);
}

export async function saveCorrelation(env: Env, correlationId: string, value: string): Promise<void> {
  const key = `${KEY_PREFIX.correlation}${correlationId}`;
  await kvPut(env, key, value, TTL_CONFIG.correlation);
}

export async function deleteCorrelation(env: Env, correlationId: string): Promise<void> {
  const key = `${KEY_PREFIX.correlation}${correlationId}`;
  await kvDelete(env, key);
}