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

