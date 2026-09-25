import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { URL } from 'node:url';

const ROOT = path.resolve(process.cwd());
const PUBLIC_DIR = path.resolve(ROOT, 'public');
const REQUESTED_FRONTEND_PORT = Number(process.env.FRONTEND_PORT || 5173);
const FRONTEND_PORT_MAX = Number(process.env.FRONTEND_PORT_MAX || 5199);
const BACKEND_PORT = Number(process.env.PORT || 4000);
const BACKEND_HOST = process.env.BACKEND_HOST || '127.0.0.1';
const FRONTEND_HOST = process.env.FRONTEND_HOST || '0.0.0.0';

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.webp': 'image/webp',
  '.gif': 'image/gif',
  '.ico': 'image/x-icon',
  '.txt': 'text/plain; charset=utf-8'
};

function safePath(urlPath) {
  const pathname = decodeURIComponent(urlPath.split('?')[0]);
  const resolved = path.resolve(PUBLIC_DIR, `.${pathname === '/' ? '/index.html' : pathname}`);
  if (resolved !== PUBLIC_DIR && !resolved.startsWith(`${PUBLIC_DIR}${path.sep}`)) return null;
  return resolved;
}

function proxyApi(req, res) {
  const proxyReq = http.request({
    hostname: BACKEND_HOST,
    port: BACKEND_PORT,
    path: req.url,
    method: req.method,
    headers: { ...req.headers, host: `${BACKEND_HOST}:${BACKEND_PORT}` }
  }, proxyRes => {
    res.writeHead(proxyRes.statusCode || 502, proxyRes.headers);
    proxyRes.pipe(res);
  });
  proxyReq.on('error', err => {
    res.writeHead(502, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify({ error: `Backend is unavailable on http://${BACKEND_HOST}:${BACKEND_PORT}`, detail: err.code || err.message }));
  });
  req.pipe(proxyReq);
}

function listen(server, startPort, host) {
  return new Promise((resolve, reject) => {
    let port = startPort;
    const tryListen = () => {
      const onError = (err) => {
        server.off('error', onError);
        if (err.code === 'EADDRINUSE' && process.env.FRONTEND_PORT_STRICT !== 'true' && port < FRONTEND_PORT_MAX) {
          port += 1;
          tryListen();
          return;
        }
        reject(err);
      };
      server.once('error', onError);
      server.listen(port, host, () => {
        server.off('error', onError);
        resolve(port);
      });
    };
    tryListen();
  });
}

const server = http.createServer((req, res) => {
  if (!req.url) return res.writeHead(400).end('Bad request');
  if (req.url.startsWith('/api/')) return proxyApi(req, res);
  if (req.url.startsWith('/uploads/')) {
    const uploadPath = path.resolve(ROOT, 'uploads', decodeURIComponent(req.url.split('?')[0].slice('/uploads/'.length)));
    const uploadsRoot = path.resolve(ROOT, 'uploads');
    if (!uploadPath.startsWith(`${uploadsRoot}${path.sep}`)) return res.writeHead(400).end('Bad request');
    return serveFile(uploadPath, res);
  }
  const filePath = safePath(req.url);
  if (!filePath) return res.writeHead(400).end('Bad request');
  serveFile(filePath, res);
});

function serveFile(filePath, res) {
  fs.stat(filePath, (err, stat) => {
    if (!err && stat.isFile()) {
      res.writeHead(200, {
        'Content-Type': MIME[path.extname(filePath).toLowerCase()] || 'application/octet-stream',
        'Cache-Control': 'no-cache'
      });
      return fs.createReadStream(filePath).pipe(res);
    }
    const fallback = path.join(PUBLIC_DIR, 'index.html');
    fs.createReadStream(fallback)
      .once('open', () => res.writeHead(200, { 'Content-Type': MIME['.html'], 'Cache-Control': 'no-cache' }))
      .on('error', () => res.writeHead(404).end('Not found'))
      .pipe(res);
  });
}

listen(server, REQUESTED_FRONTEND_PORT, FRONTEND_HOST)
  .then(port => {
    if (port !== REQUESTED_FRONTEND_PORT) {
      console.warn(`Port ${REQUESTED_FRONTEND_PORT} is already in use; using port ${port} instead.`);
    }
    console.log(`ClickBites frontend: http://localhost:${port}`);
    console.log(`LAN access: http://<your-laptop-ip>:${port}`);
    console.log(`API proxy: /api/* -> http://${BACKEND_HOST}:${BACKEND_PORT}`);
    console.log('Run "npm run server" in another CMD window for the backend.');
  })
  .catch(err => {
    if (err.code === 'EADDRINUSE') {
      console.error(`All frontend ports ${REQUESTED_FRONTEND_PORT}-${FRONTEND_PORT_MAX} are already in use.`);
      console.error(`Use FRONTEND_PORT=5200 npm run dev to choose another port.`);
    } else {
      console.error('Unable to start ClickBites frontend:', err);
    }
    process.exitCode = 1;
  });

process.on('SIGINT', () => server.close(() => process.exit(0)));
process.on('SIGTERM', () => server.close(() => process.exit(0)));
