const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ROOT = __dirname;
const DATA_DIR = process.env.WEBCRAFT_DATA_DIR || path.join(ROOT, 'data');
const DB_PATH = path.join(DATA_DIR, 'webcraft-db.json');
const SECRET_PATH = path.join(DATA_DIR, 'server-secret.txt');
const PORT = Number(process.env.PORT || 3000);
const TOKEN_TTL_MS = 1000 * 60 * 60 * 24 * 7;
const PASSWORD_MIN_LENGTH = 8;
const LOGIN_WINDOW_MS = 1000 * 60 * 15;
const LOGIN_MAX_ATTEMPTS = 20;
const PUBLIC_ORIGINS = String(process.env.PUBLIC_ORIGIN || '')
  .split(',')
  .map(origin => origin.trim())
  .filter(Boolean);
const loginAttempts = new Map();

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.json': 'application/json; charset=utf-8'
};

const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'SAMEORIGIN',
  'Referrer-Policy': 'same-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https: http:; frame-src 'self' data: blob:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'"
};

function ensureStore() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(DB_PATH)) writeDb({ users: {} });
  if (!fs.existsSync(SECRET_PATH)) {
    fs.writeFileSync(SECRET_PATH, crypto.randomBytes(32).toString('hex'), 'utf8');
  }
}

function readDb() {
  ensureStore();
  try {
    const parsed = JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
    if (!parsed.users) parsed.users = {};
    return parsed;
  } catch (err) {
    return { users: {} };
  }
}

function writeDb(db) {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  const tmp = `${DB_PATH}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(db, null, 2), 'utf8');
  fs.renameSync(tmp, DB_PATH);
}

function getSecret() {
  ensureStore();
  return fs.readFileSync(SECRET_PATH, 'utf8').trim();
}

function send(res, status, body, headers = {}) {
  const payload = typeof body === 'string' ? body : JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type': typeof body === 'string' ? 'text/plain; charset=utf-8' : 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    ...SECURITY_HEADERS,
    ...headers
  });
  res.end(payload);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let raw = '';
    req.on('data', chunk => {
      raw += chunk;
      if (raw.length > 1024 * 1024) {
        reject(new Error('요청 데이터가 너무 큽니다.'));
        req.destroy();
      }
    });
    req.on('end', () => {
      try {
        resolve(raw ? JSON.parse(raw) : {});
      } catch (err) {
        reject(new Error('잘못된 JSON 요청입니다.'));
      }
    });
    req.on('error', reject);
  });
}
function normalizeUsername(value) {
  return String(value || '').trim().toLowerCase();
}

function validateUsername(username) {
  return /^[a-z0-9_-]{3,24}$/.test(username);
}

function normalizeEmail(value) {
  return String(value || '').trim().toLowerCase();
}

function requestOrigin(req) {
  const origin = req.headers.origin;
  if (origin) return origin;
  try {
    const referer = req.headers.referer;
    return referer ? new URL(referer).origin : '';
  } catch (err) {
    return '';
  }
}

function expectedOrigins(req) {
  const host = req.headers['x-forwarded-host'] || req.headers.host || '';
  const proto = req.headers['x-forwarded-proto'] || (host.startsWith('localhost') || host.startsWith('127.0.0.1') ? 'http' : 'https');
  const origins = new Set(PUBLIC_ORIGINS);
  if (host) {
    origins.add(`${proto}://${host}`);
    origins.add(`http://${host}`);
    origins.add(`https://${host}`);
  }
  return origins;
}

function assertSameOrigin(req) {
  if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) return true;
  const origin = requestOrigin(req);
  if (!origin) return true;
  return expectedOrigins(req).has(origin);
}

function clientIp(req) {
  return String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '')
    .split(',')[0]
    .trim();
}

function checkLoginRateLimit(req, username) {
  const now = Date.now();
  const key = `${clientIp(req)}:${username || 'unknown'}`;
  const current = loginAttempts.get(key) || [];
  const recent = current.filter(time => now - time < LOGIN_WINDOW_MS);
  recent.push(now);
  loginAttempts.set(key, recent);
  return recent.length <= LOGIN_MAX_ATTEMPTS;
}

function validateEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= 254;
}

function validatePasswordPolicy(password) {
  if (password.length < PASSWORD_MIN_LENGTH) return false;
  let score = 0;
  if (/[a-z]/.test(password)) score += 1;
  if (/[A-Z]/.test(password)) score += 1;
  if (/\d/.test(password)) score += 1;
  if (/[!@#$%^&*()_\+\-=\[\]{};':"\\|,.<>\/?`~]/.test(password)) score += 1;
  return score >= 3;
}

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex'), iterations = 120000) {
  const hash = crypto.pbkdf2Sync(String(password), salt, iterations, 32, 'sha256').toString('hex');
  return { salt, hash, iterations };
}

function verifyPassword(password, user) {
  if (!user || !user.salt || !user.hash) return false;
  const candidate = hashPassword(password, user.salt, user.iterations || 120000).hash;
  const saved = Buffer.from(user.hash, 'hex');
  const checked = Buffer.from(candidate, 'hex');
  if (saved.length !== checked.length) return false;
  return crypto.timingSafeEqual(saved, checked);
}

function signToken(username) {
  const issuedAt = Date.now();
  const payload = Buffer.from(JSON.stringify({ username, issuedAt })).toString('base64url');
  const sig = crypto.createHmac('sha256', getSecret()).update(payload).digest('base64url');
  return `${payload}.${sig}`;
}

function parseCookies(req) {
  return String(req.headers.cookie || '').split(';').reduce((cookies, part) => {
    const index = part.indexOf('=');
    if (index < 0) return cookies;
    const key = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();
    if (key) cookies[key] = decodeURIComponent(value);
    return cookies;
  }, {});
}

function isSecureRequest(req) {
  return req.headers['x-forwarded-proto'] === 'https' ||
    req.socket.encrypted ||
    PUBLIC_ORIGINS.some(origin => origin.startsWith('https://'));
}

function sessionCookie(req, token) {
  const parts = [
    `wc_session=${encodeURIComponent(token)}`,
    'HttpOnly',
    'SameSite=Lax',
    'Path=/',
    `Max-Age=${Math.floor(TOKEN_TTL_MS / 1000)}`
  ];
  if (isSecureRequest(req)) parts.push('Secure');
  return parts.join('; ');
}

function clearSessionCookie(req) {
  const parts = [
    'wc_session=',
    'HttpOnly',
    'SameSite=Lax',
    'Path=/',
    'Max-Age=0'
  ];
  if (isSecureRequest(req)) parts.push('Secure');
  return parts.join('; ');
}

function verifyToken(req) {
  const auth = req.headers.authorization || '';
  const cookies = parseCookies(req);
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : (cookies.wc_session || '');
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [payload, sig] = parts;
  const expected = crypto.createHmac('sha256', getSecret()).update(payload).digest('base64url');
  if (Buffer.byteLength(sig) !== Buffer.byteLength(expected)) return null;
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
  try {
    const parsed = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    if (!parsed.username || Date.now() - parsed.issuedAt > TOKEN_TTL_MS) return null;
    return parsed.username;
  } catch (err) {
    return null;
  }
}

function findUserByEmail(users, email) {
  return Object.entries(users).find(([, user]) => normalizeEmail(user.email) === email);
}

async function handleLogin(req, res) {
  const body = await readBody(req);
  const username = normalizeUsername(body.username);
  const email = normalizeEmail(body.email);
  const password = String(body.password || '');
  const passwordConfirm = String(body.passwordConfirm || '');
  const action = body.action === 'signup' ? 'signup' : 'login';

  if (!checkLoginRateLimit(req, username)) {
    return send(res, 429, { error: '로그인 시도가 너무 많습니다. 잠시 후 다시 시도하세요.' });
  }

  if (action === 'signup' && !validatePasswordPolicy(password)) {
    return send(res, 400, { error: '비밀번호는 8자 이상이며 소문자 영문, 대문자 영문, 숫자, 특수문자 중 3가지를 만족해야 합니다.' });
  }
  if (action === 'signup' && password !== passwordConfirm) {
    return send(res, 400, { error: '비밀번호가 서로 일치하지 않습니다.' });
  }

  if (!validateUsername(username)) {
    return send(res, 400, { error: '아이디는 영문 소문자, 숫자, _, - 조합 3~24자로 입력하세요.' });
  }
  if (password.length < PASSWORD_MIN_LENGTH) {
    return send(res, 400, { error: `비밀번호는 ${PASSWORD_MIN_LENGTH}자 이상이어야 합니다.` });
  }
  if (action === 'signup' && !validateEmail(email)) {
    return send(res, 400, { error: '사용할 수 있는 이메일 주소를 입력하세요.' });
  }

  const db = readDb();
  let user = db.users[username];
  let created = false;

  if (!user) {
    if (action !== 'signup') {
      return send(res, 401, { error: '아이디 또는 비밀번호가 맞지 않습니다.' });
    }
    if (findUserByEmail(db.users, email)) {
      return send(res, 409, { error: '이미 사용 중인 이메일입니다.' });
    }
    user = {
      email,
      ...hashPassword(password),
      projects: {},
      createdAt: new Date().toISOString()
    };
    db.users[username] = user;
    writeDb(db);
    created = true;
  } else if (action === 'signup') {
    return send(res, 409, { error: '이미 사용 중인 아이디입니다.' });
  } else if (!verifyPassword(password, user)) {
    return send(res, 401, { error: '아이디 또는 비밀번호가 맞지 않습니다.' });
  }

  return send(res, 200, { username, created }, {
    'Set-Cookie': sessionCookie(req, signToken(username))
  });
}
async function handleApi(req, res, url) {
  if (!assertSameOrigin(req)) {
    return send(res, 403, { error: '허용되지 않은 출처의 요청입니다.' });
  }
  if (!['GET', 'POST', 'DELETE'].includes(req.method)) {
    return send(res, 405, { error: '허용되지 않은 요청 방식입니다.' }, { Allow: 'GET, POST, DELETE' });
  }

  if (url.pathname === '/api/login') {
    if (req.method !== 'POST') {
      return send(res, 405, { error: '허용되지 않은 요청 방식입니다.' }, { Allow: 'POST' });
    }
    return handleLogin(req, res);
  }

  if (url.pathname === '/api/logout') {
    if (req.method !== 'POST') {
      return send(res, 405, { error: '허용되지 않은 요청 방식입니다.' }, { Allow: 'POST' });
    }
    return send(res, 200, { loggedOut: true }, {
      'Set-Cookie': clearSessionCookie(req)
    });
  }

  if (url.pathname === '/api/session') {
    if (req.method !== 'GET') {
      return send(res, 405, { error: '허용되지 않은 요청 방식입니다.' }, { Allow: 'GET' });
    }
    const sessionUser = verifyToken(req);
    if (!sessionUser) return send(res, 401, { error: '로그인이 필요합니다.' });
    return send(res, 200, { username: sessionUser });
  }

  const username = verifyToken(req);
  if (!username) return send(res, 401, { error: '로그인이 필요합니다.' });

  const db = readDb();
  const user = db.users[username];
  if (!user) return send(res, 401, { error: '계정을 찾을 수 없습니다.' });
  if (!user.projects) user.projects = {};

  if (req.method === 'GET' && url.pathname === '/api/projects') {
    const projects = Object.values(user.projects)
      .map(project => ({ id: project.id, title: project.title, updatedAt: project.updatedAt }))
      .sort((a, b) => String(b.updatedAt).localeCompare(String(a.updatedAt)));
    return send(res, 200, { projects });
  }

  if (req.method === 'POST' && url.pathname === '/api/projects') {
    const body = await readBody(req);
    const id = String(body.projectId || crypto.randomUUID());
    const title = String(body.title || '제목 없는 작품').trim().slice(0, 60) || '제목 없는 작품';
    const now = new Date().toISOString();
    user.projects[id] = { id, title, data: body.data || {}, updatedAt: now };
    writeDb(db);
    return send(res, 200, { project: { id, title, updatedAt: now } });
  }

  const match = url.pathname.match(/^\/api\/projects\/([^/]+)$/);
  if (req.method === 'GET' && match) {
    const project = user.projects[decodeURIComponent(match[1])];
    if (!project) return send(res, 404, { error: '작품을 찾을 수 없습니다.' });
    return send(res, 200, { project });
  }

  if (req.method === 'DELETE' && match) {
    const projectId = decodeURIComponent(match[1]);
    const project = user.projects[projectId];
    if (!project) return send(res, 404, { error: '작품을 찾을 수 없습니다.' });
    delete user.projects[projectId];
    writeDb(db);
    return send(res, 200, { deleted: true, projectId });
  }

  return send(res, 404, { error: 'API를 찾을 수 없습니다.' });
}
function serveStatic(req, res, url) {
  if (!['GET', 'HEAD'].includes(req.method)) {
    return send(res, 405, 'Method Not Allowed', { Allow: 'GET, HEAD' });
  }
  const requested = url.pathname === '/' ? '/index.html' : decodeURIComponent(url.pathname);
  const filePath = path.normalize(path.join(ROOT, requested));
  const rel = path.relative(ROOT, filePath);
  if (rel.startsWith('..') || path.isAbsolute(rel)) return send(res, 403, 'Forbidden');
  const firstPart = rel.split(path.sep)[0].toLowerCase();
  if (firstPart === 'data' || firstPart === '.git' || firstPart === '.agents' || firstPart === '.codex') {
    return send(res, 404, 'Not found');
  }
  if (path.basename(filePath).toLowerCase() === 'server-secret.txt') return send(res, 404, 'Not found');
  fs.readFile(filePath, (err, data) => {
    if (err) return send(res, 404, 'Not found');
    res.writeHead(200, {
      'Content-Type': MIME[path.extname(filePath).toLowerCase()] || 'application/octet-stream',
      ...SECURITY_HEADERS
    });
    res.end(req.method === 'HEAD' ? undefined : data);
  });
}

ensureStore();
http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  try {
    if (url.pathname.startsWith('/api/')) return await handleApi(req, res, url);
    return serveStatic(req, res, url);
  } catch (err) {
    return send(res, 500, { error: err.message || 'server error' });
  }
}).listen(PORT, () => {
  console.log(`WebCraft server running at http://localhost:${PORT}`);
});



