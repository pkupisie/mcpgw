/**
 * Global state stores for MCP OAuth Gateway
 * These are in-memory stores that reset on worker restart
 */

import type { SessionData, RegisteredClient, AuthorizationCode, AccessToken, RefreshToken } from './types';

// In-memory session storage (resets on worker restart)
export const sessions = new Map<string, SessionData>();

// Global registered clients store (resets on worker restart)
export const registeredClients = new Map<string, RegisteredClient>();

// Global authorization code store
export const authorizationCodes = new Map<string, AuthorizationCode>();

// Global access token store
export const accessTokens = new Map<string, AccessToken>();

// Global refresh token store
export const refreshTokens = new Map<string, RefreshToken>();

// Device flow stores
export const deviceCodes = new Map<string, any>();
export const userCodeMap = new Map<string, string>();

// Request correlation tracking
export const requestCorrelation = new Map<string, string>();