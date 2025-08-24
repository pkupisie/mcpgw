import Fastify from 'fastify';
import fastifyStatic from '@fastify/static';
import fastifyFormbody from '@fastify/formbody';
import fastifyCors from '@fastify/cors';
import fastifyWebsocket from '@fastify/websocket';
import rateLimit from '@fastify/rate-limit';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { z } from 'zod';
import dotenv from 'dotenv';
import { createGw } from './server.js';

dotenv.config();

const __dirname = dirname(fileURLToPath(import.meta.url));

const app = Fastify({
  trustProxy: true,
  logger: {
    level: process.env.LOG_LEVEL || 'info',
    redact: ['req.headers.authorization', 'res.headers.authorization'],
    transport: undefined,
  },
});

await app.register(fastifyFormbody);
await app.register(fastifyWebsocket);
await app.register(rateLimit, {
  max: 100,
  timeWindow: '1 minute',
});

// Static assets (client pages)
await app.register(fastifyStatic, {
  root: join(__dirname, 'public'),
  prefix: '/',
  index: false,
  decorateReply: false,
});

// CORS (same-origin by default)
await app.register(fastifyCors, {
  origin: (origin, cb) => {
    const allowed = process.env.ALLOWED_ORIGINS?.split(',').map(s => s.trim()).filter(Boolean) || [];
    if (!origin || allowed.length === 0) return cb(null, true);
    if (allowed.includes(origin)) return cb(null, true);
    cb(new Error('Not allowed'), false);
  },
  credentials: true,
  allowedHeaders: ['authorization', 'content-type', 'x-csrf-token', 'mcp-session-id'],
  exposedHeaders: ['mcp-session-id'],
});

// Health endpoints
app.get('/healthz', async () => ({ ok: true }));
app.get('/readyz', async () => ({ ok: true }));

// Mount core GW routes
await createGw(app);

const port = Number(process.env.PORT || 3000);
const host = process.env.HOST || '0.0.0.0';
app.listen({ port, host })
  .then(address => {
    app.log.info({ address }, 'GW listening');
  })
  .catch(err => {
    app.log.error(err, 'Failed to start');
    process.exit(1);
  });

