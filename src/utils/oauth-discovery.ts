/**
 * OAuth discovery utilities for dynamic configuration
 */

export interface OAuthDiscoveryConfig {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  scopes_supported?: string[];
  response_types_supported?: string[];
  grant_types_supported?: string[];
  code_challenge_methods_supported?: string[];
  registration_endpoint?: string;
}

/**
 * Discover OAuth configuration from upstream MCP server
 */
export async function discoverOAuthConfig(serverDomain: string): Promise<OAuthDiscoveryConfig | null> {
  try {
    // Try OAuth 2.0 Authorization Server Metadata (RFC 8414)
    const metadataUrl = `https://${serverDomain}/.well-known/oauth-authorization-server`;
    console.log(`Discovering OAuth config from: ${metadataUrl}`);
    
    const response = await fetch(metadataUrl, {
      headers: {
        'Accept': 'application/json'
      }
    });
    
    if (!response.ok) {
      console.error(`OAuth discovery failed for ${serverDomain}: ${response.status}`);
      return null;
    }
    
    const config = await response.json() as OAuthDiscoveryConfig;
    console.log(`OAuth config discovered for ${serverDomain}:`, {
      issuer: config.issuer,
      authz: config.authorization_endpoint,
      token: config.token_endpoint,
      scopes: config.scopes_supported
    });
    
    return config;
  } catch (error) {
    console.error(`Failed to discover OAuth config for ${serverDomain}:`, error);
    return null;
  }
}

/**
 * Register dynamic client with upstream OAuth server
 */
export async function registerDynamicClient(
  serverDomain: string,
  registrationEndpoint: string,
  redirectUri: string
): Promise<{ client_id: string; client_secret?: string } | null> {
  try {
    const clientMetadata = {
      client_name: 'MCP OAuth Gateway',
      client_uri: redirectUri.split('/oauth')[0],
      redirect_uris: [redirectUri],
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      token_endpoint_auth_method: 'none',
      scope: 'mcp read write'
    };
    
    console.log(`Registering dynamic client with ${serverDomain}`);
    
    const response = await fetch(registrationEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      body: JSON.stringify(clientMetadata)
    });
    
    if (!response.ok) {
      console.error(`Client registration failed: ${response.status}`);
      return null;
    }
    
    const registration = await response.json() as any;
    console.log(`Client registered: ${registration.client_id}`);
    
    return {
      client_id: registration.client_id,
      client_secret: registration.client_secret
    };
  } catch (error) {
    console.error(`Failed to register client:`, error);
    return null;
  }
}