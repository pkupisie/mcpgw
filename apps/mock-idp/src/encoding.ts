// Shared encoding utilities derived from src/worker.js
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