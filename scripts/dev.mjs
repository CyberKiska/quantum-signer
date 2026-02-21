import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { existsSync, watch } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildProject } from './build.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const root = path.resolve(__dirname, '..');
const srcDir = path.join(root, 'src');
const distDir = path.join(root, 'dist');

const port = Number(process.env.PORT || 5173);

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.map': 'application/json; charset=utf-8',
};

async function serveFile(urlPath) {
  const filePath = path.join(distDir, urlPath === '/' ? 'index.html' : urlPath.replace(/^\//, ''));
  const normalized = path.normalize(filePath);
  if (!normalized.startsWith(distDir)) {
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
  await buildProject({ minify: false });
}

async function main() {
  await runBuild();

  const server = createServer(async (req, res) => {
    try {
      const url = req.url || '/';
      const response = await serveFile(url);
      res.writeHead(response.status, { 'Content-Type': response.type });
      res.end(response.body);
    } catch (err) {
      res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end(err?.message || 'Internal Server Error');
    }
  });

  server.listen(port, () => {
    console.log(`Dev server: http://localhost:${port}`);
  });

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
