/**
 * Token management utilities for MCP OAuth Gateway
 */

// Check if token is expired with optional buffer
export function isTokenExpired(expiresAt: number | undefined, bufferSeconds: number = 300): boolean {
  if (!expiresAt) return true; // If no expiration time, consider it expired
  return Date.now() > (expiresAt - bufferSeconds * 1000); // Check if expired or expires within buffer
}