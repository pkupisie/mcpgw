/**
 * Handler exports for MCP OAuth Gateway
 * These functions will be gradually moved to individual modules
 */

// Re-export all handlers from worker.ts for now
// This allows us to fix the build issue while gradually refactoring
export * from '../worker-handlers';