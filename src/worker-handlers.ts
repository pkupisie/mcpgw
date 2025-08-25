/**
 * Temporary export file for handlers still in monolithic file
 * These will be gradually moved to individual handler modules
 */

// Re-export all handlers from the backup monolithic file
// This is a temporary measure to allow gradual migration
export {
  handleOAuthDiscovery,
  handleProtectedResourceMetadata,
  handleLocalOAuth,
  handleMCPRequest,
  handleEncode,
  handleOAuthStart,
  handleOAuthCallback,
  handleMCPSSE,
  handleWebSocketUpgrade,
  handleLocalOAuthAuthorize,
  handleLocalOAuthAuthorizePost,
  handleLocalOAuthToken,
  handleLocalOAuthRevoke,
  handleLocalOAuthDevice,
  handleLocalOAuthIntrospect,
  handleDeviceVerify,
  handleClientRegistration,
  handleDeviceVerifyPost,
  initiateUpstreamOAuth,
  registerUpstreamClient,
  discoverUpstreamOAuth,
  refreshUpstreamToken,
  tryConnectUpstreamSSE,
  isTokenExpired,
  getCurrentDomain,
  generateEncodedHostname,
  getSessionId,
  getSession,
  generateSessionId,
  generateRandomString,
  sha256Base64Url,
  generateUserCode,
  createDeviceSession
} from './worker-monolith.backup';