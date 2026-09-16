const encoder = new TextEncoder();
const sessionCookie = 'coconut_session';
const preauthCookie = 'coconut_preauth';
const sessionDuration = 60 * 60 * 8;
const preauthDuration = 60 * 5;

const base64Url = value => btoa(String.fromCharCode(...new Uint8Array(value))).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');

const fromBase64Url = value => {
  const padded = value.replaceAll('-', '+').replaceAll('_', '/') + '='.repeat((4 - value.length % 4) % 4);
  return Uint8Array.from(atob(padded), character => character.charCodeAt(0));
};

const digest = async value => crypto.subtle.digest('SHA-256', encoder.encode(value));

const equal = async (left, right) => {
  const [leftHash, rightHash] = await Promise.all([digest(left), digest(right)]);
  const leftBytes = new Uint8Array(leftHash);
  const rightBytes = new Uint8Array(rightHash);
  let difference = 0;
  for (let index = 0; index < leftBytes.length; index += 1) difference |= leftBytes[index] ^ rightBytes[index];
  return difference === 0;
};

const sign = async (value, secret) => {
  const key = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return base64Url(await crypto.subtle.sign('HMAC', key, encoder.encode(value)));
};

const createToken = async (type, secret, duration) => {
  const payload = base64Url(encoder.encode(JSON.stringify({ type, expires: Date.now() + duration * 1000 })));
  return `${payload}.${await sign(payload, secret)}`;
};

const verifyToken = async (token, type, secret) => {
  if (!token || !secret) return false;
  const [payload, signature] = token.split('.');
  if (!payload || !signature || !(await equal(await sign(payload, secret), signature))) return false;
  try {
    const decoded = JSON.parse(new TextDecoder().decode(fromBase64Url(payload)));
    return decoded.type === type && Number.isFinite(decoded.expires) && decoded.expires > Date.now();
  } catch {
    return false;
  }
};

const cookies = request => Object.fromEntries((request.headers.get('Cookie') || '').split(';').map(value => value.trim().split(/=(.*)/s)).filter(([name]) => name));

const safeNext = value => value && value.startsWith('/') && !value.startsWith('//') ? value : '/';

const cookie = (name, value, duration) => `${name}=${value}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${duration}`;

const clearCookie = name => `${name}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;

const page = ({ step, next, error }) => {
  const isCodeStep = step === 'code';
  const title = isCodeStep ? 'Verify access code' : 'Sign in';
  const body = isCodeStep
    ? '<label for="access-code">Access code</label><input id="access-code" name="accessCode" type="password" inputmode="numeric" autocomplete="one-time-code" required autofocus><button type="submit">Unlock COCONUT</button>'
    : '<label for="username">Username</label><input id="username" name="username" autocomplete="username" required autofocus><label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" required><button type="submit">Continue</button>';
  const message = error ? '<p class="error" role="alert">Unable to verify those details. Try again.</p>' : '<p>Protected access requires two verification steps.</p>';
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title} | COCONUT</title><style>:root{color-scheme:dark}*{box-sizing:border-box}body{min-height:100vh;margin:0;display:grid;place-items:center;padding:24px;background:radial-gradient(circle at top,#174a37,#06100c 62%);color:#ecfff6;font:16px Arial,sans-serif}.card{width:min(420px,100%);padding:32px;border:1px solid #65e9ad66;border-radius:20px;background:#0b1d16e8;box-shadow:0 20px 60px #0008}h1{margin:0 0 8px;font-size:28px;letter-spacing:.08em}p{margin:0 0 24px;color:#b3d9c4;line-height:1.5}form{display:grid;gap:12px}label{font-size:14px;font-weight:700}input,button{min-height:48px;border-radius:10px;font:inherit}input{width:100%;border:1px solid #5ba783;background:#06110c;color:#fff;padding:0 12px}input:focus{outline:2px solid #5effaf;outline-offset:2px}button{margin-top:12px;border:0;background:#5effaf;color:#062014;font-weight:700;cursor:pointer}.error{margin:-4px 0 8px;color:#ffb4b4}</style></head><body><main class="card"><h1>COCONUT</h1><p>${title}</p>${message}<form method="post" action="/auth?next=${encodeURIComponent(next)}">${body}</form></main></body></html>`;
};

const authResponse = (body, status = 200, headers = {}) => new Response(body, { status, headers: { 'Content-Type': 'text/html; charset=UTF-8', 'Cache-Control': 'no-store', ...headers } });

const redirect = (location, cookiesToSet = []) => {
  const headers = new Headers({ Location: location });
  cookiesToSet.forEach(value => headers.append('Set-Cookie', value));
  return new Response(null, { status: 303, headers });
};

export const onRequest = async context => {
  const { request, env } = context;
  const url = new URL(request.url);
  const configured = env.AUTH_USERNAME && env.AUTH_PASSWORD && env.AUTH_ACCESS_CODE && env.AUTH_SESSION_SECRET;
  if (!configured) return new Response('Authentication is not configured.', { status: 503, headers: { 'Cache-Control': 'no-store' } });

  const requestCookies = cookies(request);
  const next = safeNext(url.searchParams.get('next'));
  const preauthorized = await verifyToken(requestCookies[preauthCookie], 'preauth', env.AUTH_SESSION_SECRET);
  const authorized = await verifyToken(requestCookies[sessionCookie], 'session', env.AUTH_SESSION_SECRET);

  if (url.pathname === '/auth/logout') return redirect('/auth', [clearCookie(sessionCookie), clearCookie(preauthCookie)]);
  if (url.pathname === '/auth') {
    if (authorized) return Response.redirect(new URL(next, url), 303);
    if (request.method === 'GET') return authResponse(page({ step: preauthorized ? 'code' : 'password', next, error: url.searchParams.has('error') }));
    if (request.method !== 'POST') return new Response('Method not allowed', { status: 405, headers: { Allow: 'GET, POST' } });
    const form = await request.formData();
    if (!preauthorized) {
      const valid = await equal(String(form.get('username') || ''), env.AUTH_USERNAME) && await equal(String(form.get('password') || ''), env.AUTH_PASSWORD);
      if (!valid) return redirect(`/auth?next=${encodeURIComponent(next)}&error=1`);
      const token = await createToken('preauth', env.AUTH_SESSION_SECRET, preauthDuration);
      return redirect(`/auth?next=${encodeURIComponent(next)}`, [cookie(preauthCookie, token, preauthDuration)]);
    }
    if (!(await equal(String(form.get('accessCode') || ''), env.AUTH_ACCESS_CODE))) return redirect(`/auth?next=${encodeURIComponent(next)}&error=1`);
    const token = await createToken('session', env.AUTH_SESSION_SECRET, sessionDuration);
    return redirect(next, [cookie(sessionCookie, token, sessionDuration), clearCookie(preauthCookie)]);
  }

  if (authorized) return context.next();
  return Response.redirect(new URL(`/auth?next=${encodeURIComponent(url.pathname + url.search)}`, url), 303);
};
