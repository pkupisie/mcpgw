// Shared encoding utilities derived from src/worker.js
// Base32 (RFC 4648, lowercase) without padding, suitable for host labels
const B32_ALPH = 'abcdefghijklmnopqrstuvwxyz234567';

export function base32Encode(input: string): string {
  const bytes = new TextEncoder().encode(input);
  let bits = 0;
  let value = 0;
  let output = '';
  for (let i = 0; i < bytes.length; i++) {
    value = (value << 8) | bytes[i]!;
    bits += 8;
    while (bits >= 5) {
      output += B32_ALPH[(value >>> (bits - 5)) & 31] as string;
      bits -= 5;
    }
  }
  if (bits > 0) output += B32_ALPH[(value << (5 - bits)) & 31] as string;
  return output;
}

export function base32Decode(input: string): string | null {
  try {
    const s = input.toLowerCase().replace(/[^a-z2-7]/g, '');
    let bits = 0;
    let value = 0;
    const bytes: number[] = [];
    for (let i = 0; i < s.length; i++) {
      const idx = B32_ALPH.indexOf(s[i] as string);
      if (idx === -1) return null;
      value = (value << 5) | idx;
      bits += 5;
      if (bits >= 8) {
        bytes.push((value >>> (bits - 8)) & 255);
        bits -= 8;
      }
    }
    return new TextDecoder().decode(new Uint8Array(bytes));
  } catch {
    return null;
  }
}

export function toBase64Url(input: string | ArrayBuffer | Uint8Array): string {
  let bytes: Uint8Array;
  if (typeof input === 'string') {
    bytes = new TextEncoder().encode(input);
  } else if (input instanceof Uint8Array) {
    bytes = input;
  } else {
    bytes = new Uint8Array(input);
  }
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!);
  const b64 = typeof btoa === 'function' ? btoa(bin) : Buffer.from(bin, 'binary').toString('base64');
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

export async function sha256Base64Url(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  if (typeof crypto !== 'undefined' && 'subtle' in crypto) {
    const digest = await crypto.subtle.digest('SHA-256', data);
    return toBase64Url(new Uint8Array(digest));
  }
  // Node.js fallback
  const { createHash } = await import('crypto');
  const hash = createHash('sha256').update(Buffer.from(data)).digest('base64');
  return hash.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

export function b32ToHost(b32: string, domainRoot: string): string {
  const prefix = 'b32-';
  const max = 63;
  const segs: string[] = [];
  let s = b32;
  const firstLen = Math.min(max - prefix.length, s.length);
  segs.push(prefix + s.slice(0, firstLen));
  s = s.slice(firstLen);
  while (s.length) {
    segs.push(s.slice(0, max));
    s = s.slice(max);
  }
  return segs.join('.') + '.' + domainRoot;
}

// Hostname parsing for MCP server routing
export interface MCPRouteInfo {
  upstreamBase: URL;
  serverDomain: string; // normalized domain for OAuth config lookup
}

export function parseHostEncodedUpstream(hostname: string, domainRoot: string): MCPRouteInfo | null {
  const root = domainRoot.toLowerCase();
  const host = hostname.toLowerCase();
  if (!host.endsWith('.' + root)) return null;
  
  const parts = host.split('.');
  const rootParts = root.split('.');
  if (parts.length <= rootParts.length) return null; // it's the root domain itself
  
  const encodedLabels = parts.slice(0, parts.length - rootParts.length);
  
  // Check for {base32}-enc format (e.g., "abc123-enc")
  if (encodedLabels.length === 1) {
    const label = encodedLabels[0]!;
    if (label.endsWith('-enc')) {
      const base32Part = label.slice(0, -4); // Remove "-enc" suffix
      const decodedDomain = base32Decode(base32Part);
      if (decodedDomain) {
        try {
          // The decoded value should be just a domain name
          let targetUrl;
          if (decodedDomain.includes('://')) {
            targetUrl = new URL(decodedDomain);
          } else {
            // Assume it's a domain name and add https://
            targetUrl = new URL('https://' + decodedDomain);
          }
          return { 
            upstreamBase: targetUrl,
            serverDomain: targetUrl.hostname
          };
        } catch {
          // Not a valid domain/URL, fall through
        }
      }
    }
  }
  
  // Legacy support: For single-label subdomains without "-enc", try base32 decoding as domain name
  if (encodedLabels.length === 1) {
    const b32Label = encodedLabels[0]!;
    const decodedDomain = base32Decode(b32Label);
    if (decodedDomain) {
      // Check if it's a valid domain name (contains dots, no protocol)
      if (decodedDomain.includes('.') && !decodedDomain.includes('://')) {
        try {
          // The decoded value is just a domain name, so we need to add https://
          const url = new URL('https://' + decodedDomain);
          return { 
            upstreamBase: url,
            serverDomain: url.hostname
          };
        } catch {
          // Not a valid domain, fall through
        }
      }
      // Check if it's a full URL
      if (decodedDomain.includes('://')) {
        try {
          const url = new URL(decodedDomain);
          return { 
            upstreamBase: url,
            serverDomain: url.hostname
          };
        } catch {
          // Not a valid URL, fall through
        }
      }
    }
  }
  
  // For multi-label subdomains (b32-prefixed), join and decode as full URL
  let joined = encodedLabels.join('');
  if (joined.startsWith('b32-')) joined = joined.slice(4);
  if (!joined) return null;
  const decoded = base32Decode(joined);
  if (!decoded) return null;
  try {
    const url = new URL(decoded);
    return { 
      upstreamBase: url,
      serverDomain: url.hostname
    };
  } catch { return null; }
}

export function selectUpstreamForRequest(upstreamBase: URL, reqUrl: URL, request?: any): URL {
  // Always preserve the incoming path when upstream is just a domain
  // Only use the exact upstream path if it was encoded as a full URL with a path
  const u = new URL(upstreamBase.href);
  
  // If the upstream has no path (just domain) or is root (/), use incoming path
  if (!u.pathname || u.pathname === '/') {
    u.pathname = reqUrl.pathname;
  }
  // Otherwise, the upstream was encoded with a specific path, so use it
  
  // Always merge query params from incoming request
  if (reqUrl.search) {
    const qs = new URLSearchParams(reqUrl.search);
    for (const [k, v] of qs.entries()) u.searchParams.set(k, v);
  }
  
  return u;
}

export function generateEncodedHostname(domain: string, domainRoot: string): string {
  const encoded = base32Encode(domain);
  return `${encoded}-enc.${domainRoot}`;
}