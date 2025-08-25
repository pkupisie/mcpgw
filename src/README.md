# MCP OAuth Gateway - Source Code Structure

## Overview
The MCP OAuth Gateway has been refactored into a modular architecture for better maintainability, testing, and scalability.

## Directory Structure

```
src/
├── worker.ts                 # Original monolithic worker (for backward compatibility)
├── worker-new.ts            # New modular entry point
├── worker-handlers.ts       # Temporary exports from worker.ts (migration in progress)
├── types.ts                 # TypeScript interfaces and type definitions
├── stores.ts                # Global state management (sessions, tokens, etc.)
├── encoding.ts              # Base32 encoding/decoding utilities
├── utils/                   # Utility modules
│   ├── logging.ts          # Logging and request tracing
│   ├── crypto.ts           # Cryptographic functions (PKCE, random strings)
│   ├── session.ts          # Session management
│   ├── token.ts            # Token validation utilities
│   └── url.ts              # URL and domain utilities
├── routing/                 # Routing logic
│   └── parser.ts           # Hostname parsing and route detection
└── handlers/                # Request handlers
    ├── dashboard.ts        # Dashboard UI handler
    ├── auth.ts             # Login/logout handlers
    ├── oauth-discovery.ts  # OAuth metadata endpoints
    ├── oauth-upstream.ts   # Upstream OAuth flow handlers
    └── utility.ts          # Utility handlers (encode, etc.)
```

## Module Descriptions

### Core Modules

- **types.ts**: All TypeScript interfaces and type definitions used across the application
- **stores.ts**: In-memory stores for sessions, tokens, and authorization codes
- **encoding.ts**: Base32 encoding/decoding for domain name transformation

### Utility Modules

- **utils/logging.ts**: Request ID generation, structured logging, and summary logging
- **utils/crypto.ts**: Random string generation, SHA256 hashing for PKCE challenges
- **utils/session.ts**: Session ID management, cookie parsing, device session creation
- **utils/token.ts**: Token expiration checking with configurable buffer time
- **utils/url.ts**: Domain encoding, current domain extraction

### Handler Modules

- **handlers/dashboard.ts**: Main dashboard UI showing connected MCP servers
- **handlers/auth.ts**: Local authentication (username/password login)
- **handlers/oauth-discovery.ts**: OAuth 2.1 discovery and metadata endpoints
- **handlers/oauth-upstream.ts**: Upstream OAuth flow (start, callback, token refresh)
- **handlers/utility.ts**: Utility endpoints like domain encoding

### Routing

- **routing/parser.ts**: Parses hostnames to detect encoded MCP server routes

## Migration Path

The codebase supports both the original monolithic `worker.ts` and the new modular `worker-new.ts`:

1. **Current State**: Both versions work side-by-side
2. **Gradual Migration**: Functions are being moved from `worker.ts` to individual modules
3. **Temporary Bridge**: `worker-handlers.ts` exports functions still in `worker.ts`
4. **Future State**: `worker-new.ts` will become the main entry point

## Build Commands

```bash
# Build original worker
npm run build:worker

# Build modular version
npm run build:modular

# Build everything
npm run build
```

## Benefits of Modularization

1. **Better Organization**: Related functionality grouped together
2. **Easier Testing**: Individual modules can be unit tested
3. **Improved Maintainability**: Smaller files are easier to understand and modify
4. **Type Safety**: Centralized types prevent inconsistencies
5. **Reusability**: Utilities can be used across different handlers
6. **Scalability**: New features can be added as new modules

## Next Steps

1. Complete migration of remaining handlers from `worker.ts`
2. Add unit tests for individual modules
3. Remove `worker-handlers.ts` bridge file
4. Rename `worker-new.ts` to `worker.ts`
5. Archive original monolithic version