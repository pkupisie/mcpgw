// Base32 encoding utilities for Cloudflare Worker
// Compatible with the existing gateway implementation

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
  
  if (bits > 0) {
    output += B32_ALPH[(value << (5 - bits)) & 31] as string;
  }
  
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