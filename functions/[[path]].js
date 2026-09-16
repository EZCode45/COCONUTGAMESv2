const encoder = new TextEncoder();
const decoder = new TextDecoder();
const sessionCookie = 'coconut_session';
const sessionDuration = 60 * 60 * 8;
const passwordIterations = 210000;

const base64Url = value => btoa(String.fromCharCode(...new Uint8Array(value))).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');

const fromBase64Url = value => {
  const padded = value.replaceAll('-', '+').replaceAll('_', '/') + '='.repeat((4 - value.length % 4) % 4);
  return Uint8Array.from(atob(padded), character => character.charCodeAt(0));
};

const randomValue = length => {
  const value = new Uint8Array(length);
  crypto.getRandomValues(value);
  return value;
};

const equal = async (left, right) => {
  const [leftHash, rightHash] = await Promise.all([
    crypto.subtle.digest('SHA-256', encoder.encode(left)),
    crypto.subtle.digest('SHA-256', encoder.encode(right))
  ]);
  const leftBytes = new Uint8Array(leftHash);
  const rightBytes = new Uint8Array(rightHash);
  let difference = 0;
  for (let index = 0; index < leftBytes.length; index += 1) difference |= leftBytes[index] ^ rightBytes[index];
  return difference === 0;
};

const passwordHash = async (password, salt) => {
  const material = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']);
  const derived = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: passwordIterations, hash: 'SHA-256' }, material, 256);
  return base64Url(derived);
};

const sign = async (value, secret) => {
  const key = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return base64Url(await crypto.subtle.sign('HMAC', key, encoder.encode(value)));
};

const createSession = async (account, secret) => {
  const payload = base64Url(encoder.encode(JSON.stringify({ accountId: account.id, username: account.username, expires: Date.now() + sessionDuration * 1000 })));
  return `${payload}.${await sign(payload, secret)}`;
};

const verifySession = async (token, secret) => {
  if (!token || !secret) return null;
  const [payload, signature] = token.split('.');
  if (!payload || !signature || !(await equal(await sign(payload, secret), signature))) return null;
  try {
    const decoded = JSON.parse(decoder.decode(fromBase64Url(payload)));
    if (!Number.isInteger(decoded.accountId) || typeof decoded.username !== 'string' || !Number.isFinite(decoded.expires) || decoded.expires <= Date.now()) return null;
    return decoded;
  } catch {
    return null;
  }
};

const cookies = request => Object.fromEntries((request.headers.get('Cookie') || '').split(';').map(value => value.trim().split(/=(.*)/s)).filter(([name]) => name));

const safeNext = value => value && value.startsWith('/') && !value.startsWith('//') ? value : '/';

const cookie = (name, value, duration) => `${name}=${value}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${duration}`;

const clearCookie = name => `${name}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;

const normalizeUsername = value => String(value || '').trim().toLowerCase();

const validUsername = value => /^[a-z0-9][a-z0-9_-]{2,31}$/.test(value);

const validPassword = value => typeof value === 'string' && value.length >= 12 && value.length <= 128;

const escapeHtml = value => String(value).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;').replaceAll("'", '&#039;');

const authPage = ({ mode, next, error }) => {
  const registering = mode === 'register';
  const title = registering ? 'Create your account' : 'Welcome back';
  const message = registering ? 'Choose a username and a password with at least 12 characters.' : 'Sign in to continue to COCONUT.';
  const fields = registering
    ? '<label for="username">Username</label><input id="username" name="username" autocomplete="username" pattern="[A-Za-z0-9_-]{3,32}" minlength="3" maxlength="32" required autofocus><label for="password">Password</label><input id="password" name="password" type="password" autocomplete="new-password" minlength="12" maxlength="128" required><label for="confirmation">Confirm password</label><input id="confirmation" name="confirmation" type="password" autocomplete="new-password" minlength="12" maxlength="128" required><button type="submit">Create account</button>'
    : '<label for="username">Username</label><input id="username" name="username" autocomplete="username" required autofocus><label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" required><button type="submit">Sign in</button>';
  const alternateHref = registering ? `/auth?next=${encodeURIComponent(next)}` : `/auth?mode=register&next=${encodeURIComponent(next)}`;
  const alternateText = registering ? 'Already have an account? Sign in' : 'Need an account? Create one';
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title} | COCONUT</title><style>:root{color-scheme:dark}*{box-sizing:border-box}body{min-height:100vh;margin:0;display:grid;place-items:center;padding:24px;background:radial-gradient(circle at top,#174a37,#06100c 62%);color:#ecfff6;font:16px Arial,sans-serif}.card{width:min(420px,100%);padding:32px;border:1px solid #65e9ad66;border-radius:20px;background:#0b1d16e8;box-shadow:0 20px 60px #0008}h1{margin:0 0 8px;font-size:28px;letter-spacing:.08em}.brand{color:#62efae;font-size:13px;font-weight:700;letter-spacing:.16em}p{margin:0 0 24px;color:#b3d9c4;line-height:1.5}form{display:grid;gap:12px}label{font-size:14px;font-weight:700}input,button{min-height:48px;border-radius:10px;font:inherit}input{width:100%;border:1px solid #5ba783;background:#06110c;color:#fff;padding:0 12px}input:focus{outline:2px solid #5effaf;outline-offset:2px}button{margin-top:12px;border:0;background:#5effaf;color:#062014;font-weight:700;cursor:pointer}.error{margin:-4px 0 16px;color:#ffb4b4}.alternate{display:block;margin-top:20px;color:#8bf1bc;text-align:center}</style></head><body><main class="card"><div class="brand">COCONUT</div><h1>${title}</h1><p>${message}</p>${error ? `<p class="error" role="alert">${escapeHtml(error)}</p>` : ''}<form method="post" action="/auth?mode=${registering ? 'register' : 'login'}&next=${encodeURIComponent(next)}">${fields}</form><a class="alternate" href="${alternateHref}">${alternateText}</a></main></body></html>`;
};

const authResponse = body => new Response(body, { headers: { 'Content-Type': 'text/html; charset=UTF-8', 'Cache-Control': 'no-store' } });

const redirect = (location, cookiesToSet = []) => {
  const headers = new Headers({ Location: location });
  cookiesToSet.forEach(value => headers.append('Set-Cookie', value));
  return new Response(null, { status: 303, headers });
};

export const onRequest = async context => {
  const { request, env } = context;
  const url = new URL(request.url);
  if (!env.ACCOUNTS || !env.AUTH_SESSION_SECRET) return new Response('Account authentication is not configured.', { status: 503, headers: { 'Cache-Control': 'no-store' } });

  const next = safeNext(url.searchParams.get('next'));
  const session = await verifySession(cookies(request)[sessionCookie], env.AUTH_SESSION_SECRET);

  if (url.pathname === '/auth/logout') return redirect('/auth', [clearCookie(sessionCookie)]);
  if (url.pathname === '/auth') {
    if (session) return redirect(next);
    const mode = url.searchParams.get('mode') === 'register' ? 'register' : 'login';
    if (request.method === 'GET') return authResponse(authPage({ mode, next, error: url.searchParams.get('error') || '' }));
    if (request.method !== 'POST') return new Response('Method not allowed', { status: 405, headers: { Allow: 'GET, POST' } });
    const form = await request.formData();
    const username = normalizeUsername(form.get('username'));
    const password = String(form.get('password') || '');
    if (!validUsername(username) || !validPassword(password)) return redirect(`/auth?mode=${mode}&next=${encodeURIComponent(next)}&error=${encodeURIComponent('Use a 3–32 character username and a password with at least 12 characters.')}`);

    if (mode === 'register') {
      if (password !== String(form.get('confirmation') || '')) return redirect(`/auth?mode=register&next=${encodeURIComponent(next)}&error=${encodeURIComponent('Passwords do not match.')}`);
      const salt = randomValue(16);
      const hash = await passwordHash(password, salt);
      try {
        const account = await env.ACCOUNTS.prepare('INSERT INTO accounts (username, password_hash, password_salt) VALUES (?, ?, ?) RETURNING id, username').bind(username, hash, base64Url(salt)).first();
        const token = await createSession(account, env.AUTH_SESSION_SECRET);
        return redirect(next, [cookie(sessionCookie, token, sessionDuration)]);
      } catch {
        return redirect(`/auth?mode=register&next=${encodeURIComponent(next)}&error=${encodeURIComponent('That username is already in use.')}`);
      }
    }

    const account = await env.ACCOUNTS.prepare('SELECT id, username, password_hash, password_salt FROM accounts WHERE username = ?').bind(username).first();
    if (!account || !(await equal(await passwordHash(password, fromBase64Url(account.password_salt)), account.password_hash))) return redirect(`/auth?next=${encodeURIComponent(next)}&error=${encodeURIComponent('Incorrect username or password.')}`);
    const token = await createSession(account, env.AUTH_SESSION_SECRET);
    return redirect(next, [cookie(sessionCookie, token, sessionDuration)]);
  }

  if (session) return context.next();
  return redirect(`/auth?next=${encodeURIComponent(url.pathname + url.search)}`);
};
