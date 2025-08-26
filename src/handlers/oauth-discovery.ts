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
    scopes_supported: ['mcp', 'read', 'write']
  };
  
  console.log(`\n╔══ OAUTH DISCOVERY RESPONSE ═════════════════════════`);
  console.log(`║ Issuer: ${issuer}`);
  console.log(`║ Authorization: ${metadata.authorization_endpoint}`);
  console.log(`║ Token: ${metadata.token_endpoint}`);
  console.log(`║ Device: ${metadata.device_authorization_endpoint}`);
  console.log(`╚══════════════════════════════════════════════════════`);
  
  return new Response(JSON.stringify(metadata), {
    status: 200,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Vary': 'Origin',
      'Cache-Control': 'public, max-age=300'
    }
  });
}

export async function handleProtectedResourceMetadata(request: Request, hostRoute: MCPRouteInfo, env: Env): Promise<Response> {
  const currentDomain = getCurrentDomain(request);
  const resource = `https://${currentDomain}`;
  
  const metadata = {
    resource,
    authorization_servers: [`https://${currentDomain}`],
    bearer_methods_supported: ['authorization_header'],
    scopes_supported: ['mcp', 'read', 'write'],
    sse_endpoint: `${resource}/sse`,
    resource_documentation: `https://${currentDomain}`,
    
    // Explicitly indicate that authentication is required
    authentication_required: true,
    
    // MCP-specific metadata
    mcp_version: '1.0',
    upstream_server: hostRoute.serverDomain,
    capabilities: ['tools', 'resources', 'prompts'],
    
    // Server identification for Claude
    server_name: `${hostRoute.serverDomain} (via MCP Gateway)`,
    server_description: 'MCP OAuth Gateway proxying to upstream server'
  };
  
  console.log(`\n╔══ PROTECTED RESOURCE METADATA ══════════════════════`);
  console.log(`║ Resource: ${resource}`);
  console.log(`║ Auth Server: ${metadata.authorization_servers[0]}`);
  console.log(`║ Bearer Methods: ${metadata.bearer_methods_supported.join(', ')}`);
  console.log(`║ SSE Endpoint: ${metadata.sse_endpoint}`);
  console.log(`╚══════════════════════════════════════════════════════`);
  
  return new Response(JSON.stringify(metadata), {
    status: 200,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Vary': 'Origin',
      'Cache-Control': 'public, max-age=300'
    }
  });
}