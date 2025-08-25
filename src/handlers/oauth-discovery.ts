/**
 * OAuth discovery and metadata handlers for MCP OAuth Gateway
 */

import type { Env, MCPRouteInfo } from '../types';
import { getCurrentDomain } from '../utils/url';

export async function handleOAuthDiscovery(request: Request, hostRoute: MCPRouteInfo, env: Env): Promise<Response> {
  const currentDomain = getCurrentDomain(request);
  const issuer = `https://${currentDomain}`;
  
  const metadata = {
    issuer,
    authorization_endpoint: `${issuer}/oauth/authorize`,
    token_endpoint: `${issuer}/oauth/token`,
    device_authorization_endpoint: `${issuer}/oauth/device`,
    introspection_endpoint: `${issuer}/oauth/introspect`,
    revocation_endpoint: `${issuer}/oauth/revoke`,
    registration_endpoint: `${issuer}/oauth/register`,
    response_types_supported: ['code'],
    response_modes_supported: ['query'],
    grant_types_supported: [
      'authorization_code',
      'refresh_token',
      'urn:ietf:params:oauth:grant-type:device_code'
    ],
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: ['none'],
    revocation_endpoint_auth_methods_supported: ['none'],
    introspection_endpoint_auth_methods_supported: ['none'],
    request_parameter_supported: false,
    authorization_response_iss_parameter_supported: true,
    backchannel_logout_supported: false,
    frontchannel_logout_supported: false,
    scopes_supported: ['read', 'write', 'admin']
  };
  
  console.log(`\n╔══ OAUTH DISCOVERY RESPONSE ═════════════════════════`);
  console.log(`║ Issuer: ${issuer}`);
  console.log(`║ Authorization: ${metadata.authorization_endpoint}`);
  console.log(`║ Token: ${metadata.token_endpoint}`);
  console.log(`║ Device: ${metadata.device_authorization_endpoint}`);
  console.log(`╚══════════════════════════════════════════════════════`);
  
  return new Response(JSON.stringify(metadata), {
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'public, max-age=3600'
    }
  });
}

export async function handleProtectedResourceMetadata(request: Request, hostRoute: MCPRouteInfo, env: Env): Promise<Response> {
  const currentDomain = getCurrentDomain(request);
  const resource = `https://${currentDomain}`;
  
  const metadata = {
    resource,
    authorization_servers: [`https://${currentDomain}`],
    bearer_methods_supported: ['header'],
    resource_signing_alg_values_supported: ['RS256'],
    resource_documentation: 'https://modelcontextprotocol.io/docs',
    resource_policy_uri: 'https://modelcontextprotocol.io/privacy',
    resource_tos_uri: 'https://modelcontextprotocol.io/terms'
  };
  
  console.log(`\n╔══ PROTECTED RESOURCE METADATA ══════════════════════`);
  console.log(`║ Resource: ${resource}`);
  console.log(`║ Auth Server: ${metadata.authorization_servers[0]}`);
  console.log(`║ Bearer Methods: ${metadata.bearer_methods_supported.join(', ')}`);
  console.log(`╚══════════════════════════════════════════════════════`);
  
  return new Response(JSON.stringify(metadata), {
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'public, max-age=3600'
    }
  });
}