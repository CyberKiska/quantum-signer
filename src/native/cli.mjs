#!/usr/bin/env node
import { constants, readSync } from 'node:fs';
import { open } from 'node:fs/promises';
import { createHash, getFips } from 'node:crypto';
import { parseArgs } from 'node:util';
import { createInterface } from 'node:readline/promises';
import { Writable } from 'node:stream';
import { pathToFileURL } from 'node:url';
import { listSuites, DEFAULT_SUITE_ID } from '../crypto/suite-metadata.js';
import { MAX_KEY_FILE_BYTES, MAX_PAYLOAD_FILE_BYTES, MAX_SIGNATURE_FILE_BYTES } from '../crypto/policy.js';
import { packPublicKey, unpackSecretKey, unpackSignatureV2 } from '../formats/containers.js';
import { encryptSecretKeyFile, decryptSecretKeyFile, isProtectedSecretKeyFile } from '../crypto/key-protection.js';
import { finalizePayloadVerification } from '../crypto/verify-policy.js';
import { assertNativeRuntime, generateNativeKey, publicKeyBytes, importLegacySecretKey, importPkcs8, checkPrivateKey } from './crypto.js';
import { createDetachedSignature } from './signing.js';

const HELP = `Quantum Signer — local Node/OpenSSL signing (Node.js 26+)
  node src/native/cli.mjs doctor
  node src/native/cli.mjs keygen --suite ML-DSA-87 --secret signer.pqse --public signer.pqpk
  node src/native/cli.mjs hash --file document.bin
  node src/native/cli.mjs sign --secret signer.pqse --file document.bin --expect-sha3-512 HEX --out document.qsig
  node src/native/cli.mjs verify --file document.bin --signature document.qsig --public signer.pqpk
  node src/native/cli.mjs public --secret signer.pqse --out signer.pqpk

New keys are encrypted PKCS#8 in PQSE 2; legacy PQSE 1/PQSK imports are supported.
Passwords are prompted without echo, or read from --passphrase-fd N (one UTF-8 line).
Never put passwords in command arguments. New passwords require 12+ code points.
Outputs are created exclusively with mode 0600; existing files are never replaced.
Use a private output directory; on Windows configure its ACL before key generation.
Signing requires the digest reviewed using 'hash'; filenames are not authenticated.
Verification without --public checks integrity only and exits 2 (untrusted signer).
Exit status: 0 success/trusted verification, 1 error/invalid, 2 valid embedded-only.
Native crypto is not a claim of FIPS module validation or hardware key isolation.`;

async function regularFile(file, limit) {
  const handle = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size > limit) throw new Error('Input must be a regular file within its size limit.');
    return { handle, stat };
  } catch (error) { await handle.close(); throw error; }
}

async function readBounded(file, limit) {
  const { handle, stat } = await regularFile(file, limit);
  const bytes = Buffer.alloc(stat.size + 1);
  let length = 0;
  try {
    while (length < bytes.length) {
      const { bytesRead } = await handle.read(bytes, length, bytes.length - length);
      if (!bytesRead) break;
      length += bytesRead;
    }
    if (length !== stat.size) throw new Error('Input changed while reading.');
    return bytes.subarray(0, length);
  } catch (error) { bytes.fill(0); throw error; }
  finally { await handle.close(); }
}

export async function hashFile(file) {
  const { handle, stat } = await regularFile(file, MAX_PAYLOAD_FILE_BYTES);
  const hash = createHash('sha3-512');
  const buffer = Buffer.alloc(1024 * 1024);
  let length = 0;
  try {
    while (true) {
      const { bytesRead } = await handle.read(buffer, 0, buffer.length);
      if (!bytesRead) break;
      length += bytesRead;
      if (length > MAX_PAYLOAD_FILE_BYTES) throw new Error('Payload exceeds size limit.');
      hash.update(buffer.subarray(0, bytesRead));
    }
    const after = await handle.stat();
    if (length !== stat.size || after.size !== stat.size || after.mtimeMs !== stat.mtimeMs || after.ctimeMs !== stat.ctimeMs) {
      throw new Error('Payload changed while hashing.');
    }
    return hash.digest();
  } finally { buffer.fill(0); await handle.close(); }
}

async function writeNew(file, bytes) {
  const handle = await open(file, 'wx', 0o600);
  try { await handle.writeFile(bytes); await handle.sync(); }
  finally { await handle.close(); }
}

async function password(fd, confirm = false) {
  if (fd !== undefined) {
    if (!/^(0|[3-9]|[1-9][0-9]+)$/u.test(fd) || !Number.isSafeInteger(Number(fd))) {
      throw new Error('Passphrase descriptor must be 0 or at least 3.');
    }
    const buffer = Buffer.alloc(1027);
    let n = 0;
    try {
      // Stop at LF without waiting for EOF or consuming a subsequent password.
      while (n < buffer.length) {
        const count = readSync(Number(fd), buffer, n, 1, null);
        if (!count) break;
        if (buffer[n++] === 10) break;
      }
      let end = n;
      if (buffer[end - 1] === 10) end--;
      if (buffer[end - 1] === 13) end--;
      if (!end || end > 1024) throw new Error('Invalid password length.');
      return new TextDecoder('utf-8', { fatal: true }).decode(buffer.subarray(0, end));
    } finally { buffer.fill(0); }
  }
  if (!process.stdin.isTTY) throw new Error('Use a terminal password prompt or --passphrase-fd.');
  const silent = new Writable({ write(_chunk, _encoding, callback) { callback(); } });
  const rl = createInterface({ input: process.stdin, output: silent, terminal: true });
  const abort = new AbortController();
  rl.on('SIGINT', () => abort.abort());
  try {
    process.stderr.write('Passphrase: ');
    const first = await rl.question('', { signal: abort.signal });
    process.stderr.write('\n');
    if (confirm) {
      process.stderr.write('Repeat passphrase: ');
      const second = await rl.question('', { signal: abort.signal });
      process.stderr.write('\n');
      if (first !== second) throw new Error('Passphrases differ.');
    }
    return first;
  } finally { rl.close(); silent.destroy(); }
}

async function loadPrivate(file, fd) {
  const encoded = await readBounded(file, MAX_KEY_FILE_BYTES);
  let plaintext;
  let raw;
  try {
    let suiteId;
    let key;
    if (isProtectedSecretKeyFile(encoded)) {
      const opened = await decryptSecretKeyFile(encoded, await password(fd));
      plaintext = opened.secretKeyFile;
      suiteId = opened.suiteId;
      if (opened.keyFormat === 'pkcs8') key = importPkcs8(suiteId, plaintext);
      else {
        const parsed = unpackSecretKey(plaintext);
        raw = parsed.keyBytes;
        if (parsed.suiteId !== suiteId) throw new Error('Protected key suite mismatch.');
        key = importLegacySecretKey(suiteId, raw);
      }
    } else {
      const parsed = unpackSecretKey(encoded);
      raw = parsed.keyBytes;
      suiteId = parsed.suiteId;
      key = importLegacySecretKey(suiteId, raw);
    }
    checkPrivateKey(suiteId, key);
    return { suiteId, key };
  } finally { encoded.fill(0); plaintext?.fill(0); raw?.fill(0); }
}

export async function main(args = process.argv.slice(2)) {
  assertNativeRuntime();
  const { values, positionals } = parseArgs({ args, allowPositionals: true, options: Object.fromEntries(
    ['suite', 'secret', 'public', 'file', 'signature', 'out', 'expect-sha3-512', 'passphrase-fd'].map(name => [name, { type: 'string', multiple: true }])
  ) });
  const command = positionals[0] || 'help';
  const rules = {
    help: [], doctor: [], hash: ['file'], keygen: ['suite', 'secret', 'public', 'passphrase-fd'],
    sign: ['secret', 'file', 'expect-sha3-512', 'out', 'passphrase-fd'],
    verify: ['file', 'signature', 'public'], public: ['secret', 'out', 'passphrase-fd'],
  };
  if (!Object.hasOwn(rules, command) || positionals.length > 1) throw new Error('Unknown command; use help.');
  for (const [name, entries] of Object.entries(values)) {
    if (entries.length !== 1 || !entries[0] || !rules[command].includes(name)) throw new Error(`Invalid or repeated option: --${name}`);
    values[name] = entries[0];
  }
  const need = name => { if (!values[name]) throw new Error(`Missing --${name}`); return values[name]; };
  if (command === 'help') { console.log(HELP); return 0; }
  if (command === 'doctor') {
    console.log(JSON.stringify({ node: process.versions.node, openssl: process.versions.openssl, fipsMode: getFips() === 1,
      signingProvider: 'node:crypto', moduleValidationEstablished: false }, null, 2));
    return 0;
  }
  if (command === 'hash') { console.log((await hashFile(need('file'))).toString('hex')); return 0; }
  if (command === 'keygen') {
    need('secret'); need('public');
    if (values.secret === values.public) throw new Error('Key output paths must differ.');
    const suite = values.suite ? listSuites().find(s => s.name.toLowerCase() === values.suite.toLowerCase()) : listSuites().find(s => s.id === DEFAULT_SUITE_ID);
    if (!suite) throw new Error('Unknown suite.');
    const passphrase = await password(values['passphrase-fd'], true);
    const key = generateNativeKey(suite.id);
    const der = key.export({ type: 'pkcs8', format: 'der' });
    try {
      const encrypted = await encryptSecretKeyFile({ suiteId: suite.id, secretKeyFile: der, passphrase, keyFormat: 'pkcs8' });
      await writeNew(values.secret, encrypted);
      await writeNew(values.public, packPublicKey({ suiteId: suite.id, keyBytes: publicKeyBytes(suite.id, key) }));
    } finally { der.fill(0); }
    console.log('Encrypted private key and public key created.');
    return 0;
  }
  if (command === 'verify') {
    const hash = await hashFile(need('file'));
    const parsed = unpackSignatureV2(await readBounded(need('signature'), MAX_SIGNATURE_FILE_BYTES));
    const publicFile = values.public ? await readBounded(values.public, MAX_KEY_FILE_BYTES) : null;
    const result = finalizePayloadVerification(parsed, publicFile, { computedHashHex: hash.toString('hex') });
    console.log(JSON.stringify(result, null, 2));
    return !result.valid ? 1 : result.trusted ? 0 : 2;
  }
  need('secret'); need('out');
  let hash;
  if (command === 'sign') {
    const expected = need('expect-sha3-512');
    if (!/^[0-9a-f]{128}$/u.test(expected)) throw new Error('Expected digest must be 128 lowercase hexadecimal characters.');
    hash = await hashFile(need('file'));
    if (hash.toString('hex') !== expected) throw new Error('Payload differs from the reviewed digest.');
  }
  const { suiteId, key } = await loadPrivate(values.secret, values['passphrase-fd']);
  const output = command === 'public' ? packPublicKey({ suiteId, keyBytes: publicKeyBytes(suiteId, key) }) : createDetachedSignature(suiteId, key, hash);
  await writeNew(values.out, output);
  console.log(command === 'public' ? 'Public key exported.' : 'Detached signature created and self-verified.');
  return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().then(code => { process.exitCode = code; }).catch(error => {
    // Do not print provider error stacks, input bytes, or passwords.
    console.error(`Quantum Signer: ${error.code ? String(error.code) : error.message}`);
    process.exitCode = 1;
  });
}
