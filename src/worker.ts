/**
 * MCP OAuth Gateway - Cloudflare Worker (Modularized Version)
 * 
 * Simplified OAuth gateway implementing hostname-based routing with authentication
 * for MCP (Model Context Protocol) servers.
 * 
 * Architecture: Claude.ai/ChatGPT → Cloudflare Worker → MCP Server (with OAuth)
 */

/// <reference types="@cloudflare/workers-types" />

import type { Env, MCPRouteInfo } from './types';
import { parseHostEncodedUpstream } from './routing/parser';
import { handleDashboard } from './handlers/dashboard';
import { handleLoginPage, handleLogin } from './handlers/auth';
import { handleOAuthDiscovery, handleProtectedResourceMetadata } from './handlers/oauth-discovery';
import { handleOAuthStart, handleOAuthCallback } from './handlers/oauth-upstream';
import { handleEncode } from './handlers/utility';
import { handleLocalOAuth } from './handlers/oauth-local';
import { handleMCPRequest } from './handlers/mcp';

// Export the worker
export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    
    try {
      // Parse hostname to determine if this is an MCP route
      const hostRoute = parseHostEncodedUpstream(url.hostname, env.DOMAIN_ROOT);
      
      if (hostRoute) {
        // Handle CORS preflight requests for all paths
        if (request.method === 'OPTIONS') {
          return new Response(null, {
            status: 204,
            headers: {
              'Access-Control-Allow-Origin': '*',
              'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
              'Access-Control-Allow-Headers': 'Content-Type, Authorization, MCP-Protocol-Version',
              'Access-Control-Max-Age': '86400',
              'Vary': 'Origin'
            }
          });
        }
        
        // Handle all .well-known paths - these MUST be public (no auth)
        if (url.pathname === '/.well-known/openid-configuration' || 
            url.pathname.startsWith('/.well-known/openid-configuration/')) {
          // OIDC discovery - same as OAuth but with OIDC naming
          return handleOAuthDiscovery(request, hostRoute, env);
        }
        
        if (url.pathname.startsWith('/.well-known/oauth-authorization-server')) {
          // OAuth 2.0 Authorization Server Metadata (RFC 8414)
          return handleOAuthDiscovery(request, hostRoute, env);
        }
        
        if (url.pathname.startsWith('/.well-known/oauth-protected-resource')) {
          // OAuth 2.0 Protected Resource Metadata
          return handleProtectedResourceMetadata(request, hostRoute, env);
        }
        
        // Add login handler for encoded domains
        if (url.pathname === '/login') {
          if (request.method === 'GET') return handleLoginPage(request);
          if (request.method === 'POST') return handleLogin(request, env);
        }
        
        if (url.pathname.startsWith('/oauth/')) {
          return handleLocalOAuth(request, hostRoute, env);
        }
        
        // This is an MCP server request
        return handleMCPRequest(request, hostRoute, env);
      }
      
      // Landing domain routes (handle custom domain, mcp.domain, and workers.dev)
      const hostname = url.hostname.toLowerCase();
      const domainRoot = env.DOMAIN_ROOT.toLowerCase();
      const isLandingDomain = hostname === domainRoot ||
                             hostname === `mcp.${domainRoot}` ||
                             (hostname.startsWith('mcp.') && hostname.includes('.workers.dev'));
      
      if (isLandingDomain) {
        if (url.pathname === '/' || url.pathname === '') {
          return handleDashboard(request, env);
        }
        
        if (url.pathname === '/login') {
          if (request.method === 'GET') return handleLoginPage(request);
          if (request.method === 'POST') return handleLogin(request, env);
        }
        
        if (url.pathname === '/encode') {
          return handleEncode(request, env);
        }
        
        if (url.pathname === '/oauth/start') {
          return handleOAuthStart(request, env);
        }
        
        if (url.pathname === '/oauth/callback') {
          return handleOAuthCallback(request, env);
        }
      }
      
      return new Response('Not found', { status: 404 });
    } catch (error) {
      console.error('Worker error:', error);
      return new Response('Internal server error', { status: 500 });
    }
  }
};