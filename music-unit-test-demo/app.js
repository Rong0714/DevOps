const http = require('node:http');
const fs = require('node:fs/promises');
const path = require('node:path');
const { randomBytes, randomUUID } = require('node:crypto');
const {
  MAX_MP3_BYTES, hashPassword, authenticate, validateUpload
} = require('./logic');

const PUBLIC = path.join(__dirname, 'public');
const STORAGE = path.join(__dirname, 'uploads');
const DEMO_USER = 'demo';
const DEMO_PASSWORD = process.env.DEMO_PASSWORD || 'DemoPass123!';
const SESSION_MS = 60 * 60 * 1000;

async function readBody(req, maxBytes) {
  const parts = [];
  let size = 0;
  for await (const part of req) {
    size += part.length;
    if (size > maxBytes) {
      const error = new Error('Request is too large.');
      error.status = 413;
      throw error;
    }
    parts.push(part);
  }
  return Buffer.concat(parts);
}

function json(res, status, data) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(data));
}

function createApp({ uploadDir = STORAGE } = {}) {
  // A single demo user and short-lived sessions kept in memory.
  const account = { username: DEMO_USER, passwordHash: hashPassword(DEMO_PASSWORD) };
  const sessions = new Map();

  return http.createServer(async (req, res) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Content-Security-Policy', "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'");
    res.setHeader('Referrer-Policy', 'no-referrer');

    const url = new URL(req.url, 'http://localhost');
    const cookie = (req.headers.cookie || '').split(';').map(s => s.trim())
      .find(s => s.startsWith('session='));
    const token = cookie ? cookie.slice('session='.length) : null;
    const isLoggedIn = Boolean(token && (sessions.get(token) || 0) > Date.now());

    try {
      if (req.method === 'GET' && ['/', '/client.js', '/style.css'].includes(url.pathname)) {
        const files = {
          '/': ['index.html', 'text/html; charset=utf-8'],
          '/client.js': ['client.js', 'application/javascript; charset=utf-8'],
          '/style.css': ['style.css', 'text/css; charset=utf-8']
        };
        const [file, type] = files[url.pathname];
        const body = await fs.readFile(path.join(PUBLIC, file));
        res.writeHead(200, { 'Content-Type': type });
        return res.end(body);
      }

      if (req.method === 'POST' && url.pathname === '/api/login') {
        let info;
        try {
          info = JSON.parse((await readBody(req, 4096)).toString('utf8'));
        } catch {
          return json(res, 400, { error: 'Invalid login request.' });
        }
        if (!authenticate(info?.username, info?.password, account)) {
          return json(res, 401, { error: 'Incorrect username or password.' });
        }
        const session = randomBytes(32).toString('hex');
        sessions.set(session, Date.now() + SESSION_MS);
        const secure = req.socket.encrypted ? '; Secure' : '';
        res.setHeader('Set-Cookie', `session=${session}; HttpOnly; SameSite=Strict; Path=/; Max-Age=3600${secure}`);
        return json(res, 200, { message: 'Logged in.' });
      }

      if (req.method === 'POST' && url.pathname === '/api/logout') {
        if (token) sessions.delete(token);
        res.setHeader('Set-Cookie', 'session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');
        return json(res, 200, { message: 'Logged out.' });
      }

      if (req.method === 'GET' && url.pathname === '/api/session') {
        return json(res, 200, { loggedIn: isLoggedIn });
      }

      // All MP3 routes require a successful login.
      if (url.pathname.startsWith('/api/')) {
        if (!isLoggedIn) return json(res, 401, { error: 'Please log in first.' });

        if (req.method === 'POST' && url.pathname === '/api/upload') {
          if (req.headers['content-type'] !== 'audio/mpeg') {
            return json(res, 400, { error: 'Please select an MP3.' });
          }
          const body = await readBody(req, MAX_MP3_BYTES + 1);
          let fileName;
          try {
            fileName = decodeURIComponent(req.headers['x-filename'] || '');
          } catch {
            return json(res, 400, { error: 'Invalid filename.' });
          }
          const result = validateUpload(fileName, body);
          if (!result.ok) return json(res, 400, { error: result.error });

          await fs.mkdir(uploadDir, { recursive: true });
          const savedName = `${randomUUID()}-${result.fileName}`;
          await fs.writeFile(path.join(uploadDir, savedName), body, { flag: 'wx' });
          return json(res, 201, { message: 'MP3 saved.', fileName: result.fileName });
        }

        if (req.method === 'GET' && url.pathname === '/api/files') {
          await fs.mkdir(uploadDir, { recursive: true });
          const names = await fs.readdir(uploadDir);
          const files = names.filter(n => /^[0-9a-f-]{36}-[a-zA-Z0-9._-]+\.mp3$/.test(n))
            .map(id => ({ id, name: id.slice(37) }));
          return json(res, 200, { files });
        }

        if (req.method === 'GET' && url.pathname.startsWith('/api/audio/')) {
          let id;
          try {
            id = decodeURIComponent(url.pathname.slice('/api/audio/'.length));
          } catch {
            return json(res, 400, { error: 'Invalid file name.' });
          }
          if (!/^[0-9a-f-]{36}-[a-zA-Z0-9._-]+\.mp3$/.test(id)) {
            return json(res, 400, { error: 'Invalid file name.' });
          }
          try {
            const file = await fs.readFile(path.join(uploadDir, id));
            res.writeHead(200, { 'Content-Type': 'audio/mpeg', 'Cache-Control': 'no-store' });
            return res.end(file);
          } catch (error) {
            if (error.code === 'ENOENT') return json(res, 404, { error: 'File not found.' });
            throw error;
          }
        }
      }
      return json(res, 404, { error: 'Page not found.' });
    } catch (error) {
      if (!res.headersSent) json(res, error.status || 500, { error: error.status === 413 ? 'File too large.' : 'Server error.' });
      else res.end();
    }
  });
}

if (require.main === module) {
  const server = createApp();
  const port = Number(process.env.PORT) || 3000;
  server.listen(port, () => {
    console.log(`Open http://localhost:${port}`);
    console.log(`Demo login: ${DEMO_USER} / ${DEMO_PASSWORD}`);
  });
}

module.exports = { createApp };
