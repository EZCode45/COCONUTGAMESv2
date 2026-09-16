import { createServer } from 'node:http';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { randomBytes, randomUUID, scrypt as scryptCallback, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';
import { extname, join, normalize } from 'node:path';

const scrypt = promisify(scryptCallback);
const port = Number(process.env.PORT || 8787);
const dataDirectory = join(process.cwd(), 'data');
const dataFile = join(dataDirectory, 'accounts.json');
const root = process.cwd();
const contentTypes = { '.css': 'text/css; charset=UTF-8', '.html': 'text/html; charset=UTF-8', '.js': 'text/javascript; charset=UTF-8', '.json': 'application/json; charset=UTF-8', '.png': 'image/png', '.svg': 'image/svg+xml', '.woff2': 'font/woff2', '.ttf': 'font/ttf' };

const readState = async () => {
  await mkdir(dataDirectory, { recursive: true });
  try {
    const value = JSON.parse(await readFile(dataFile, 'utf8'));
    return { accounts: value.accounts || [], notifications: value.notifications || [], sessions: value.sessions || [] };
  } catch {
    const value = { accounts: [], notifications: [], sessions: [] };
    await writeState(value);
    return value;
  }
};

const writeState = value => writeFile(dataFile, JSON.stringify(value, null, 2));
const hashPassword = async (password, salt = randomBytes(16).toString('hex')) => ({ salt, hash: (await scrypt(password, salt, 64)).toString('hex') });
const passwordMatches = async (password, account) => timingSafeEqual(Buffer.from((await hashPassword(password, account.salt)).hash, 'hex'), Buffer.from(account.passwordHash, 'hex'));
const json = (response, status, body) => response.writeHead(status, { 'Content-Type': 'application/json; charset=UTF-8', 'Cache-Control': 'no-store' }).end(JSON.stringify(body));
const failure = (response, status, error) => json(response, status, { error });
const parseBody = request => new Promise((resolve, reject) => { let value = ''; request.on('data', chunk => { value += chunk; if (value.length > 100000) reject(new Error('Request too large')); }); request.on('end', () => { try { resolve(value ? JSON.parse(value) : {}); } catch { reject(new Error('Invalid request body')); } }); request.on('error', reject); });
const username = value => String(value || '').trim().toLowerCase();
const validUsername = value => /^[a-z0-9][a-z0-9_-]{2,31}$/.test(value);
const validPassword = value => typeof value === 'string' && value.length >= 8 && value.length <= 128;
const publicAccount = account => ({ id: account.id, username: account.username, role: account.role, playerData: account.playerData, devices: account.devices.map(device => ({ id: device.id, name: device.name, createdAt: device.createdAt })) });
const sessionAccount = (request, state) => { const token = request.headers.authorization?.replace(/^Bearer\s+/i, ''); const session = state.sessions.find(value => value.token === token && value.expiresAt > Date.now()); return session ? state.accounts.find(account => account.id === session.accountId) : null; };
const newSession = (state, account, deviceId) => { const token = randomBytes(32).toString('hex'); state.sessions = state.sessions.filter(value => value.expiresAt > Date.now()); state.sessions.push({ token, accountId: account.id, deviceId, expiresAt: Date.now() + 1000 * 60 * 60 * 24 * 30 }); return token; };
const admin = state => state.accounts.find(account => account.role === 'admin');

const api = async (request, response, path) => {
  const state = await readState();
  const body = ['POST', 'PUT'].includes(request.method) ? await parseBody(request) : {};
  if (request.method === 'GET' && path === '/api/status') return json(response, 200, { setupRequired: !admin(state) });
  if (request.method === 'POST' && path === '/api/setup') {
    if (admin(state)) return failure(response, 409, 'An administrator already exists.');
    const name = username(body.username);
    if (!validUsername(name) || !validPassword(body.password)) return failure(response, 400, 'Use a valid username and a password with at least 8 characters.');
    const password = await hashPassword(body.password);
    const account = { id: randomUUID(), username: name, role: 'admin', passwordHash: password.hash, salt: password.salt, devices: [], playerData: { coins: 0, progress: {} }, createdAt: new Date().toISOString() };
    state.accounts.push(account);
    const deviceId = String(body.deviceId || randomUUID());
    account.devices.push({ id: deviceId, name: String(body.deviceName || 'Administrator device').slice(0, 64), createdAt: new Date().toISOString() });
    const token = newSession(state, account, deviceId);
    await writeState(state);
    return json(response, 201, { token, account: publicAccount(account) });
  }
  if (request.method === 'POST' && path === '/api/auth/request') {
    const account = state.accounts.find(value => value.username === username(body.username));
    if (!account || !(await passwordMatches(body.password || '', account))) return failure(response, 401, 'Incorrect username or password.');
    const deviceId = String(body.deviceId || '');
    if (!deviceId) return failure(response, 400, 'Device information is required.');
    if (account.devices.some(device => device.id === deviceId)) { const token = newSession(state, account, deviceId); await writeState(state); return json(response, 200, { token, account: publicAccount(account) }); }
    const code = String(Math.floor(100000 + Math.random() * 900000));
    state.notifications.push({ id: randomUUID(), type: 'device-code', accountId: account.id, username: account.username, deviceId, deviceName: String(body.deviceName || 'New device').slice(0, 64), code, createdAt: new Date().toISOString(), expiresAt: Date.now() + 1000 * 60 * 15, read: false });
    await writeState(state);
    return json(response, 202, { needsCode: true, message: 'A temporary code was sent to the administrator notifications.' });
  }
  if (request.method === 'POST' && path === '/api/auth/verify') {
    const account = state.accounts.find(value => value.username === username(body.username));
    const deviceId = String(body.deviceId || '');
    if (!account || !deviceId || !(await passwordMatches(body.password || '', account))) return failure(response, 401, 'Incorrect username or password.');
    const notification = state.notifications.find(value => value.type === 'device-code' && value.accountId === account.id && value.deviceId === deviceId && value.code === String(body.code || '') && value.expiresAt > Date.now());
    if (!notification) return failure(response, 401, 'That temporary code is invalid or expired.');
    account.devices.push({ id: deviceId, name: String(body.deviceName || 'New device').slice(0, 64), createdAt: new Date().toISOString() });
    state.notifications = state.notifications.filter(value => value.id !== notification.id);
    const token = newSession(state, account, deviceId);
    await writeState(state);
    return json(response, 200, { token, account: publicAccount(account) });
  }
  const account = sessionAccount(request, state);
  if (!account) return failure(response, 401, 'Sign in is required.');
  if (request.method === 'GET' && path === '/api/me') return json(response, 200, { account: publicAccount(account) });
  if (request.method === 'POST' && path === '/api/me/data') { account.playerData = { ...account.playerData, ...body.playerData, progress: body.playerData?.progress && typeof body.playerData.progress === 'object' ? body.playerData.progress : account.playerData.progress }; await writeState(state); return json(response, 200, { account: publicAccount(account) }); }
  if (request.method === 'POST' && path === '/api/me/reset-data') { account.playerData = { coins: 0, progress: {} }; await writeState(state); return json(response, 200, { account: publicAccount(account) }); }
  if (request.method === 'POST' && path === '/api/me/password') { if (!(await passwordMatches(body.currentPassword || '', account)) || !validPassword(body.newPassword)) return failure(response, 400, 'Enter your current password and a new password with at least 8 characters.'); const password = await hashPassword(body.newPassword); account.passwordHash = password.hash; account.salt = password.salt; await writeState(state); return json(response, 200, { account: publicAccount(account) }); }
  if (account.role !== 'admin') return failure(response, 403, 'Administrator access is required.');
  if (request.method === 'GET' && path === '/api/admin/accounts') return json(response, 200, { accounts: state.accounts.map(publicAccount), notifications: state.notifications.filter(value => value.expiresAt > Date.now()) });
  if (request.method === 'POST' && path === '/api/admin/accounts') { const name = username(body.username); if (!validUsername(name) || !validPassword(body.password)) return failure(response, 400, 'Use a valid username and a password with at least 8 characters.'); if (state.accounts.some(value => value.username === name)) return failure(response, 409, 'That username already exists.'); const password = await hashPassword(body.password); const created = { id: randomUUID(), username: name, role: 'player', passwordHash: password.hash, salt: password.salt, devices: [], playerData: { coins: 0, progress: {} }, createdAt: new Date().toISOString() }; state.accounts.push(created); await writeState(state); return json(response, 201, { account: publicAccount(created) }); }
  const target = state.accounts.find(value => value.id === body.accountId && value.role !== 'admin');
  if (!target) return failure(response, 404, 'Player account not found.');
  if (request.method === 'POST' && path === '/api/admin/reset-data') { target.playerData = { coins: 0, progress: {} }; await writeState(state); return json(response, 200, { account: publicAccount(target) }); }
  if (request.method === 'POST' && path === '/api/admin/reset-devices') { target.devices = []; state.sessions = state.sessions.filter(value => value.accountId !== target.id); await writeState(state); return json(response, 200, { account: publicAccount(target) }); }
  if (request.method === 'POST' && path === '/api/admin/reset-password') { if (!validPassword(body.password)) return failure(response, 400, 'Use a password with at least 8 characters.'); const password = await hashPassword(body.password); target.passwordHash = password.hash; target.salt = password.salt; state.sessions = state.sessions.filter(value => value.accountId !== target.id); await writeState(state); return json(response, 200, { account: publicAccount(target) }); }
  return failure(response, 404, 'Not found.');
};

const server = createServer(async (request, response) => {
  const url = new URL(request.url, `http://${request.headers.host}`);
  try {
    if (url.pathname.startsWith('/api/')) return await api(request, response, url.pathname);
    const requested = url.pathname === '/' ? 'index.html' : url.pathname.slice(1);
    if (requested === 'data' || requested.startsWith('data/') || requested === '.git' || requested.startsWith('.git/')) return failure(response, 403, 'Forbidden.');
    const file = normalize(join(root, requested));
    if (!file.startsWith(root)) return failure(response, 403, 'Forbidden.');
    const content = await readFile(file);
    response.writeHead(200, { 'Content-Type': contentTypes[extname(file)] || 'application/octet-stream' });
    response.end(content);
  } catch (error) {
    failure(response, error.message === 'Invalid request body' ? 400 : 404, error.message === 'Invalid request body' ? error.message : 'Not found.');
  }
});

server.listen(port, () => console.log(`COCONUT is running at http://localhost:${port}`));
