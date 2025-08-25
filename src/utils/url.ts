/**
 * URL and domain utilities for MCP OAuth Gateway
 */

import { base32Encode } from '../encoding';

// Generate encoded hostname for MCP server
export function generateEncodedHostname(domain: string, domainRoot: string): string {
  const encoded = base32Encode(domain);
  return `${encoded}-enc.${domainRoot}`;
}

// Get current domain from request
export function getCurrentDomain(request: Request): string {
  return new URL(request.url).hostname;
}