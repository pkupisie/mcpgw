/**
 * Hostname parsing utilities for MCP OAuth Gateway
 */

import { base32Decode } from '../encoding';
import type { MCPRouteInfo } from '../types';

// Parse hostname to determine if this is an MCP route
export function parseHostEncodedUpstream(hostname: string, domainRoot: string): MCPRouteInfo | null {
  const root = domainRoot.toLowerCase();
  const host = hostname.toLowerCase();
  
  if (!host.endsWith('.' + root)) return null;
  
  const parts = host.split('.');
  const rootParts = root.split('.');
  if (parts.length <= rootParts.length) return null;
  
  const encodedLabels = parts.slice(0, parts.length - rootParts.length);
  
  // Check for {base32}-enc format
  if (encodedLabels.length === 1) {
    const label = encodedLabels[0];
    if (label.endsWith('-enc')) {
      const base32Part = label.slice(0, -4);
      const decodedDomain = base32Decode(base32Part);
      
      if (decodedDomain) {
        try {
          let targetUrl: URL;
          if (decodedDomain.includes('://')) {
            targetUrl = new URL(decodedDomain);
          } else {
            targetUrl = new URL('https://' + decodedDomain);
          }
          
          return {
            upstreamBase: targetUrl,
            serverDomain: targetUrl.hostname
          };
        } catch {
          return null;
        }
      }
    }
  }
  
  return null;
}