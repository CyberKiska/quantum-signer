import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import { buildStaticHeadersFile, META_DOCUMENT_CSP } from './security-headers.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const root = path.resolve(__dirname, '..');

export function normalizeBasePath(value) {
  if (!value || value.trim() === '') return '/';
  let out = value.trim();
  if (!out.startsWith('/')) out = `/${out}`;
  if (!out.endsWith('/')) out = `${out}/`;
  if (!/^\/(?:[A-Za-z0-9._~-]+\/)*$/u.test(out)) {
    throw new Error('BASE_PATH must contain only slash-delimited RFC 3986 unreserved path segments');
  }
  const segments = out.split('/').filter(Boolean);
  if (segments.some((segment) => segment === '.' || segment === '..')) {
    throw new Error('BASE_PATH must not contain dot segments');
  }
  return out;
}

export function normalizeBuildCommit(value) {
  const commit = String(value || 'local').trim().toLowerCase();
  if (commit === 'local' || /^[0-9a-f]{40,64}$/u.test(commit)) return commit;
  throw new Error('BUILD_COMMIT must be "local" or a 40-64 character lowercase hexadecimal commit id');
}

function normalizePrivateKeyOperations(value) {
  if (value === undefined || value === null || value === '') return 'enabled';
  if (value === 'enabled' || value === 'disabled') return value;
  throw new Error('PRIVATE_KEY_OPERATIONS must be exactly "enabled" or "disabled"');
}

export async function buildProject({ minify = true, sourcemap = !minify } = {}) {
  const distDir = path.join(root, 'dist');
  const assetsDir = path.join(distDir, 'assets');
  const srcDir = path.join(root, 'src');
  const basePath = normalizeBasePath(process.env.BASE_PATH || '/');
  const privateKeyOperations = normalizePrivateKeyOperations(process.env.PRIVATE_KEY_OPERATIONS);
  const buildCommit = normalizeBuildCommit(process.env.BUILD_COMMIT);

  await rm(distDir, { recursive: true, force: true });
  await mkdir(assetsDir, { recursive: true });

  const buildResult = await build({
    entryPoints: {
      app: path.join(srcDir, 'main.js'),
      worker: path.join(srcDir, 'worker.js'),
    },
    outdir: assetsDir,
    bundle: true,
    format: 'esm',
    platform: 'browser',
    target: ['es2022'],
    sourcemap,
    minify,
    metafile: true,
    logLevel: 'info',
  });

  const outputEntries = Object.entries(buildResult.metafile.outputs);
  const appOutput = outputEntries.find(([, output]) => output.entryPoint?.endsWith('src/main.js'));
  const workerOutput = outputEntries.find(([, output]) => output.entryPoint?.endsWith('src/worker.js'));
  if (!appOutput || !workerOutput) {
    throw new Error('Build metadata is missing the app or worker entry point');
  }

  const [, appMetadata] = appOutput;
  const [, workerMetadata] = workerOutput;
  const forbiddenAppInputs = Object.keys(appMetadata.inputs).filter(
    (input) => input.includes('@noble/post-quantum') || input.endsWith('src/crypto/algorithms.js')
  );
  if (forbiddenAppInputs.length > 0) {
    throw new Error(`Private-key implementation leaked into the UI bundle: ${forbiddenAppInputs.join(', ')}`);
  }
  if (appMetadata.bytes > 128 * 1024) {
    throw new Error(`UI bundle exceeds the 128 KiB production budget: ${appMetadata.bytes} bytes`);
  }
  if (workerMetadata.bytes > 256 * 1024) {
    throw new Error(`Crypto worker exceeds the 256 KiB production budget: ${workerMetadata.bytes} bytes`);
  }

  const [htmlTemplate, css, packageText, appBundle] = await Promise.all([
    readFile(path.join(srcDir, 'index.html'), 'utf8'),
    readFile(path.join(srcDir, 'styles.css'), 'utf8'),
    readFile(path.join(root, 'package.json'), 'utf8'),
    readFile(path.resolve(root, appOutput[0])),
  ]);

  const packageMetadata = JSON.parse(packageText);
  const appIntegrity = `sha384-${createHash('sha384').update(appBundle).digest('base64')}`;
  const styleIntegrity = `sha384-${createHash('sha384').update(css, 'utf8').digest('base64')}`;

  const html = htmlTemplate
    .replaceAll('%BASE_PATH%', basePath)
    .replaceAll('%DOCUMENT_CSP%', META_DOCUMENT_CSP)
    .replaceAll('%PRIVATE_KEY_OPERATIONS%', privateKeyOperations)
    .replaceAll('%BUILD_COMMIT%', buildCommit)
    .replaceAll('%BUILD_COMMIT_SHORT%', buildCommit === 'local' ? buildCommit : buildCommit.slice(0, 12))
    .replaceAll('%APP_INTEGRITY%', appIntegrity)
    .replaceAll('%STYLE_INTEGRITY%', styleIntegrity);
  const staticHeaders = buildStaticHeadersFile(basePath);

  await Promise.all([
    writeFile(path.join(distDir, 'index.html'), html, 'utf8'),
    writeFile(path.join(distDir, 'styles.css'), css, 'utf8'),
    writeFile(path.join(distDir, '.nojekyll'), '', 'utf8'),
    writeFile(path.join(distDir, '_headers'), staticHeaders, 'utf8'),
  ]);

  const artifactNames = [
    '.nojekyll',
    '_headers',
    'assets/app.js',
    'assets/worker.js',
    'index.html',
    'styles.css',
  ];
  const artifacts = [];
  for (const name of artifactNames) {
    const bytes = await readFile(path.join(distDir, name));
    artifacts.push({
      path: name,
      bytes: bytes.length,
      sha256: createHash('sha256').update(bytes).digest('hex'),
    });
  }
  const manifest = {
    schema: 'quantum-signer-build-manifest/v1',
    applicationVersion: packageMetadata.version,
    sourceCommit: buildCommit,
    basePath,
    privateKeyOperations,
    artifacts,
  };
  await writeFile(
    path.join(distDir, 'build-manifest.json'),
    `${JSON.stringify(manifest, null, 2)}\n`,
    'utf8'
  );

  console.log(`Build completed. basePath=${basePath} sourceCommit=${buildCommit}`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  buildProject().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
