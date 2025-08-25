/**
 * Logging utilities for MCP OAuth Gateway
 */

// Generate unique request ID for tracing
export function generateRequestId(): string {
  return crypto.randomUUID();
}

// Structured logging helper
export function log(data: any) {
  console.log(JSON.stringify(data));
}

// Summary line logging
export function logSummary(endpoint: string, method: string, status: number, details: string) {
  console.log(`SUM ${endpoint} ${method} ${status} ${details}`);
}