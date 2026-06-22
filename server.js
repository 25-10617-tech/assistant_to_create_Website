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

function validateEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= 254;
}

function validatePasswordPolicy(password) {
  return (
    password.length >= PASSWORD_MIN_LENGTH &&
    /[A-Za-z]/.test(password) &&
    /\d/.test(password) &&
    /[!@#$%^&*()_\+\-=\[\]{};':"\\|,.<>\/?`~]/.test(password)
  );
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

function verifyToken(req) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
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
  const action = body.action === 'signup' ? 'signup' : 'login';

  if (action === 'signup' && !validatePasswordPolicy(password)) {
    return send(res, 400, { error: '\ube44\ubc00\ubc88\ud638\ub294 8\uc790 \uc774\uc0c1, \uc54c\ud30c\ubcb3, \uc22b\uc790, \ud2b9\uc218\ubb38\uc790\ub97c \uac01\uac01 1\uac1c \uc774\uc0c1 \ud3ec\ud568\ud574\uc57c \ud569\ub2c8\ub2e4.' });
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
      return send(res, 404, { error: '가입된 계정이 없습니다. 먼저 회원가입을 해주세요.' });
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

  return send(res, 200, { token: signToken(username), username, created });
}

async function handleApi(req, res, url) {
  if (req.method === 'POST' && url.pathname === '/api/login') {
    return handleLogin(req, res);
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

  return send(res, 404, { error: 'API not found' });
}

function serveStatic(req, res, url) {
  const requested = url.pathname === '/' ? '/index.html' : decodeURIComponent(url.pathname);
  const filePath = path.normalize(path.join(ROOT, requested));
  if (!filePath.startsWith(ROOT)) return send(res, 403, 'Forbidden');
  fs.readFile(filePath, (err, data) => {
    if (err) return send(res, 404, 'Not found');
    res.writeHead(200, {
      'Content-Type': MIME[path.extname(filePath).toLowerCase()] || 'application/octet-stream'
    });
    res.end(data);
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
