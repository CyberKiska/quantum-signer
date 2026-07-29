import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { existsSync, watch } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildProject } from './build.mjs';
import { DOCUMENT_CSP, STANDARD_SECURITY_HEADERS, WORKER_CSP } from './security-headers.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const root = path.resolve(__dirname, '..');
const srcDir = path.join(root, 'src');
const distDir = path.join(root, 'dist');

const port = Number(process.env.PORT || 5173);
const host = '127.0.0.1';
const previewMode = process.argv.includes('--preview');

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.map': 'application/json; charset=utf-8',
};

async function serveFile(urlPath) {
  const filePath = path.join(distDir, urlPath === '/' ? 'index.html' : urlPath.replace(/^\//, ''));
  const normalized = path.normalize(filePath);
  const relative = path.relative(distDir, normalized);
  if (relative.startsWith('..') || path.isAbsolute(relative)) {
    return { status: 403, body: 'Forbidden', type: 'text/plain; charset=utf-8' };
  }

  if (!existsSync(normalized)) {
    return { status: 404, body: 'Not Found', type: 'text/plain; charset=utf-8' };
  }

  const ext = path.extname(normalized);
  const type = MIME[ext] || 'application/octet-stream';
  const body = await readFile(normalized);
  return { status: 200, body, type };
}

async function runBuild() {
  await buildProject({ minify: previewMode, sourcemap: !previewMode });
}

async function main() {
  await runBuild();

  const server = createServer(async (req, res) => {
    try {
      const url = req.url || '/';
      const response = await serveFile(url);
      const headers = {
        'Content-Type': response.type,
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        ...STANDARD_SECURITY_HEADERS,
      };
      // HSTS is ignored over this intentionally HTTP-only localhost server.
      delete headers['Strict-Transport-Security'];
      if (url.endsWith('/assets/worker.js')) headers['Content-Security-Policy'] = WORKER_CSP;
      else if (url === '/' || url.endsWith('/index.html')) headers['Content-Security-Policy'] = DOCUMENT_CSP;
      res.writeHead(response.status, headers);
      res.end(response.body);
    } catch (err) {
      res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end(err?.message || 'Internal Server Error');
    }
  });

  server.listen(port, host, () => {
    console.log(`${previewMode ? 'Local production preview' : 'Dev server'}: http://${host}:${port}`);
  });

  if (previewMode) return;

  let timer = null;
  watch(srcDir, { recursive: true }, () => {
    clearTimeout(timer);
    timer = setTimeout(async () => {
      try {
        await runBuild();
        console.log('Rebuilt.');
      } catch (err) {
        console.error('Build failed:', err?.message || err);
      }
    }, 120);
  });
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
