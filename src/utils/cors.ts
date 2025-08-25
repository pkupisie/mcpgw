/**
 * CORS utilities for handling cross-origin requests
 */

/**
 * Generate CORS headers for specific allowed origins
 * @param origin The origin header from the request
 * @returns CORS headers object
 */
export function corsFor(origin: string | null): Record<string, string> {
  // Allow MCP Inspector in dev and other specific origins
  const allowed = new Set([
    'http://localhost:6274',  // MCP Inspector dev
    'http://localhost:3000',  // Common dev ports
    'http://localhost:5173',  // Vite dev server
    'http://localhost:8080',  // Common dev port
    // Add production origins here if needed
  ]);
  
  // If origin is in allowed list, echo it back; otherwise empty string
  const allowOrigin = origin && allowed.has(origin) ? origin : '';
  
  return {
    'Access-Control-Allow-Origin': allowOrigin,
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Credentials': 'false',
    'Vary': 'Origin',
  };
}

/**
 * Generate CORS headers for public endpoints (no credentials)
 * @returns CORS headers object
 */
export function publicCors(): Record<string, string> {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Vary': 'Origin',
  };
}