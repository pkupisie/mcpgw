import Fastify from 'fastify';
import formbody from '@fastify/formbody';
import { randomBytes } from 'crypto';
import { sha256Base64Url } from './encoding.js';

type CodeRecord = {
  code_challenge: string;
  code_challenge_method: string;
  client_id: string;
  redirect_uri: string;
  scope: string;
  state: string;
  user: string;
  issuedAt: number;
};

const app = Fastify({ logger: { level: process.env.LOG_LEVEL || 'info' } });
await app.register(formbody);

const codes = new Map<string, CodeRecord>();
const accessTokens = new Map<string, { user: string; exp: number; refresh?: string }>();
const refreshTokens = new Map<string, { user: string; exp: number }>();

app.get('/healthz', async () => ({ ok: true }));

app.get('/authorize', async (req, reply) => {
  const q = Object.fromEntries(new URL('http://x' + (req as any).raw.url).searchParams.entries());
  const { client_id, redirect_uri, response_type, scope, state, code_challenge, code_challenge_method } = q as any;
  if (response_type !== 'code') return reply.status(400).send('response_type must be code');
  const html = `<!doctype html><html><body>
    <h1>Mock IdP Login</h1>
    <form method="POST" action="/authorize?${new URLSearchParams(q as any)}">
      <label>User: <input name="user" value="operator"></label><br>
      <label>Password: <input name="pass" type="password" value="pass"></label><br>
      <button type="submit">Login</button>
    </form>
  </body></html>`;
  reply.type('text/html').send(html);
});

app.post('/authorize', async (req, reply) => {
  const url = new URL('http://x' + (req as any).raw.url);
  const q = Object.fromEntries(url.searchParams.entries());
  const body = (req as any).body || {};
  const user = String(body.user || '');
  const pass = String(body.pass || '');
  if (pass !== 'pass') return reply.status(401).send('Invalid');
  const code = randomBytes(16).toString('base64url');
  codes.set(code, {
    code_challenge: String(q.code_challenge || ''),
    code_challenge_method: String(q.code_challenge_method || 'S256'),
    client_id: String(q.client_id || ''),
    redirect_uri: String(q.redirect_uri || ''),
    scope: String(q.scope || ''),
    state: String(q.state || ''),
    user,
    issuedAt: Date.now(),
  });
  const redir = new URL(String(q.redirect_uri));
  redir.searchParams.set('code', code);
  redir.searchParams.set('state', String(q.state || ''));
  reply.redirect(302, redir.toString());
});

app.post('/token', async (req, reply) => {
  const body = (req as any).body || {};
  const grant = String(body.grant_type || '');
  if (grant === 'authorization_code') {
    const code = String(body.code || '');
    const verifier = String(body.code_verifier || '');
    const rec = codes.get(code);
    if (!rec) return reply.status(400).send({ error: 'invalid_grant' });
    codes.delete(code); // one-time use
    const challenge = await sha256Base64Url(verifier);
    if (challenge !== rec.code_challenge) {
      return reply.status(400).send({ error: 'invalid_grant', error_description: 'PKCE mismatch' });
    }
    const access = 'token-' + randomBytes(24).toString('base64url');
    const refresh = 'refresh-' + randomBytes(24).toString('base64url');
    const exp = Math.floor(Date.now() / 1000) + 60; // short expiry for tests
    accessTokens.set(access, { user: rec.user, exp, refresh });
    refreshTokens.set(refresh, { user: rec.user, exp: Math.floor(Date.now() / 1000) + 3600 });
    return reply.send({ access_token: access, refresh_token: refresh, token_type: 'Bearer', expires_in: 60, scope: rec.scope });
  }
  if (grant === 'refresh_token') {
    const rt = String(body.refresh_token || '');
    const r = refreshTokens.get(rt);
    if (!r) return reply.status(400).send({ error: 'invalid_grant' });
    const access = 'token-' + randomBytes(24).toString('base64url');
    const exp = Math.floor(Date.now() / 1000) + 60;
    accessTokens.set(access, { user: r.user, exp, refresh: rt });
    return reply.send({ access_token: access, refresh_token: rt, token_type: 'Bearer', expires_in: 60 });
  }
  return reply.status(400).send({ error: 'unsupported_grant_type' });
});

app.get('/api/profile', async (req, reply) => {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  const rec = accessTokens.get(token);
  if (!rec) return reply.status(401).send({ error: 'unauthorized' });
  if (rec.exp < Math.floor(Date.now() / 1000)) return reply.status(401).send({ error: 'expired' });
  return reply.send({ user: rec.user, token });
});

app.get('/sse/stream', async (req, reply) => {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  const rec = accessTokens.get(token);
  if (!rec) return reply.status(401).send();
  reply
    .header('Content-Type', 'text/event-stream')
    .header('Cache-Control', 'no-cache')
    .header('Connection', 'keep-alive')
    .status(200);
  let i = 0;
  const timer = setInterval(() => {
    reply.raw.write(`data: tick ${++i}\n\n`);
    if (i >= 5) clearInterval(timer);
  }, 1000);
  req.raw.on('close', () => clearInterval(timer));
});

const port = Number(process.env.MOCK_PORT || 4000);
app.listen({ port, host: '0.0.0.0' }).then(addr => {
  app.log.info({ addr }, 'Mock IdP/Server listening');
});
