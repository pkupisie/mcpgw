/**
 * Type definitions for MCP OAuth Gateway
 */

export interface SessionData {
  csrf: string;
  localAuth: boolean;
  pendingResource?: string;
  oauth?: {
    [serverDomain: string]: {
      state?: string;
      pkceVerifier?: string;
      tokens?: {
        access_token: string;
        refresh_token?: string;
        expires_in?: number;
      };
      expiresAt?: number;
      client?: {
        client_id: string;
        client_secret?: string;
      };
      config?: {
        authorization_endpoint: string;
        token_endpoint: string;
        client_id: string;
        client_secret?: string;
      };
    };
  };
  localOAuthTokens?: {
    [domain: string]: {
      access_token: string;
      refresh_token?: string;
      expires_at: number;
      client_id: string;
    };
  };
  deviceCodes?: {
    [domain: string]: {
      [device_code: string]: {
        user_code: string;
        verification_uri: string;
        expires_at: number;
        client_id: string;
        scope: string;
        interval: number;
      };
    };
  };
  pendingClientAuth?: {
    client_id: string;
    redirect_uri: string;
    scope: string;
    state: string;
    code_challenge: string;
    code_challenge_method: string;
    resource: string;
    serverDomain: string;
  };
}

export interface MCPRouteInfo {
  serverDomain: string;
  encodedDomain?: string;
  isEncoded: boolean;
  upstreamBase?: URL;
}

export interface RegisteredClient {
  client_id: string;
  client_secret?: string;
  registered_at: number;
}

export interface AuthorizationCode {
  client_id: string;
  redirect_uri: string;
  scope: string;
  code_challenge?: string;
  code_challenge_method?: string;
  resource?: string;
  serverDomain: string;
  hostname: string;
  sessionId: string;
  created_at: number;
}

export interface AccessToken {
  client_id: string;
  sessionId: string;
  serverDomain: string;
  hostname: string;
  scope?: string;
  created_at: number;
}

export interface RefreshToken {
  client_id: string;
  sessionId: string;
  serverDomain: string;
  hostname: string;
  scope?: string;
  created_at: number;
  access_token?: string;  // Track associated access token for rotation
}

export interface Env {
  DOMAIN_ROOT: string;
  LOCAL_USER: string;
  LOCAL_PASSWORD: string;
  OAUTH_CODES: KVNamespace;
  SESSIONS: KVNamespace;
}