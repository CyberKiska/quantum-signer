# Verified behavior and implementation reference

## Evidence boundary

Inspected 2026-09-25: application **2.1.0**, branch `release-2.1-hardening`. Runtime: macOS, Node **26.7.0** with OpenSSL **3.6.3**, FIPS mode false, built-in Chromium **152** browser against the loopback preview. Only disposable keys and synthetic payloads were used.

**Code-verified** means traced through active source. **Runtime-verified** means executed for this revision. **Inference** means an operational consequence, not a demonstrated guarantee. None of this is a certification or an independent audit.

## Active paths and dependencies — code-verified

| Source | Responsibility |
| --- | --- |
| `src/index.html`, `src/main.js`, `src/ui/layout.js` | Navigation, top-level and secure-context gates, Trusted Types worker policy, embedded worker creation, teardown on `pagehide`. The page holds only public data and the encrypted PQSE file of a newly generated key. |
| `src/ui/keys.js` | Signing key: generate, unlock, save PQSE/PQPK, lock, 15-minute idle lock. Verification public key: import, full fingerprint, canonical PQPK export, clear. |
| `src/ui/sign.js` | Sign input, digest/signer review, reviewed-value binding of the worker result, `.qsig` save. |
| `src/ui/verify.js`, `src/core/operation-gate.js` | Previews, review snapshot, deceptive-text warning, stale-result rejection, result display. |
| `src/ui/common.js` | DOM helpers and the worker client (timeouts terminate and lazily replace the worker). |
| `src/worker.js` | Allowlist (`HASH_*`, `VERIFY_*`, `SELFTEST`, `KEYGEN`, `UNLOCK`, `SIGN`), the only unlocked private key, startup KATs, busy rejection, progress. |
| `src/crypto/detached-signature.js` | QSIG construction and container self-verification shared by the CLI and the worker. |
| `src/crypto/browser-signing.js`, `src/crypto/pkcs8.js` | Worker-only noble signer, conditional ACVP self-tests, pairwise tests, strict RFC 9881/9909 PKCS#8. |
| `src/native/cli.mjs`, `src/native/crypto.js`, `src/native/signing.js` | File I/O, password input, native keys, conditional ACVP self-tests, pairwise tests, signing and self-verification, exit policy. |
| `src/crypto/verify-policy.js` | Shared fail-safe verification policy (browser and CLI). |
| `src/crypto/suite-metadata.js` | Single suite table and the verification-input guard used by both verifiers. |
| `src/formats/containers.js`, `src/crypto/policy.js` | Strict QSIG/PQPK/PQSK parsing and size limits. |
| `src/crypto/key-protection.js` | PQSE 3 (Argon2id + AES-256-GCM) and read-only PQSE 1/2. CLI and browser worker; the build refuses it in the main-thread bundle. |
| `scripts/build.mjs`, `scripts/security-headers.mjs`, `scripts/dev.mjs` | Bundling, SRI, CSP and headers, loopback serving. |
| `scripts/lib/` | Test-only JavaScript reference signer and protocol cases; never shipped. |

**Cryptographic providers:**

| Where | ML-DSA / SLH-DSA | SHA-3 | Key-file protection |
| --- | --- | --- | --- |
| CLI | `node:crypto` KeyObjects: `sign(null, msg, {key, context})` and `verify(null, …)` | `node:crypto` | Argon2id from `node:crypto`; AES-256-GCM from Node's WebCrypto |
| Browser worker | `@noble/post-quantum` **0.7.1** sign/verify | `@noble/hashes` **2.4.0** | Argon2id from `@noble/hashes`; AES-256-GCM, SHA-256 and randomness from Web Crypto |

**Why the browser still uses noble:**
- Chromium 152's WebCrypto rejects ML-DSA, SLH-DSA and SHA3 with `NotSupportedError` (runtime-verified).
- Node's WebCrypto ML-DSA is marked experimental and it has no SLH-DSA, so the CLI uses the stable `node:crypto` KeyObject API.
- The standalone CLI bundle contains no `node_modules` code (tested).
- Build tool: esbuild **0.28.2**.

## Signing and wire formats — code-verified

Application-specific binary formats, not CMS/JOSE/COSE. Integers are unsigned little-endian; full layout in `spec/qsig-v2.txt`, byte-exact example in `spec/qsig-v2-vector.json`.

| ID (hex) / suite | Raw public key | Legacy raw private key | Raw signature | Complete QSIG |
| --- | ---: | ---: | ---: | ---: |
| 01 / ML-DSA-44 | 1,312 | 2,560 | 2,420 | 3,906 |
| 02 / ML-DSA-65 | 1,952 | 4,032 | 3,309 | 5,435 |
| 03 / ML-DSA-87 | 2,592 | 4,896 | 4,627 | 7,393 |
| 11 / SLH-DSA-SHAKE-128s | 32 | 64 | 7,856 | 8,062 |
| 12 / SLH-DSA-SHAKE-192s | 48 | 96 | 16,224 | 16,446 |
| 13 / SLH-DSA-SHAKE-256s | 64 | 128 | 29,792 | 30,030 |

QSIG size is `174 + publicKeyLength + signatureLength`.

**Signing pipeline:**
1. Hash the exact payload with SHA3-512 and require it to equal the reviewed digest.
2. Before the first use of the suite, run the native self-tests: SHA3-256/512 KATs; verification of an ACVP-derived signature plus wrong-context, wrong-message and damaged-signature rejections; ML-DSA KeyGen from an ACVP seed; and a signature from the ACVP key checked against the ACVP public key. A failure latches every native operation closed.
3. Open the key and run a pairwise sign/verify test under the dedicated context `quantum-signer/pct/v1`.
4. Build the authenticated metadata: `0x10 || u16LE(pk.length) || pk || 0x11 || u16LE(33) || 0x01 || SHA3-256(pk)`. `authDigest = SHA3-256` of that block.
5. Build the 108-byte TBS: `"QSTB" || 02 00 || 02 00 || suiteId || 01 || 01 || 01 || payloadDigest[64] || authDigest[32]`.
6. Sign the TBS with pure ML-DSA/SLH-DSA under the context `quantum-signer/v2` (17 bytes). The provider adds `00 11 || ctx` once, making M' 127 bytes. There is no HashML-DSA, KMAC/cSHAKE or deterministic fallback; signing is randomized.
7. Verify the primitive, pack, reparse, and verify the container with the public key and digest; only then write the file.

**QSIG layout:**
- 118-byte fixed header; context length `0x11` at offset 108; 17-byte context at 118; authenticated metadata from 135; then the raw signature. No payload, no CRC, no trailing bytes.
- The display-metadata length must be 0.
- Tags must be exactly 0x10 then 0x11, and the fingerprint and metadata digest must match.

**PQPK/PQSK:** 12-byte header, raw key, CRC-32. PQSK (plaintext private) is legacy input only.

**PQSE 3:**
- Layout: 26-byte header (magic, 3.0, suite, KDF `02` Argon2id, AEAD `01` AES-256-GCM, flags, u32 memory KiB, u32 passes, u8 lanes, salt/IV lengths, reserved, u32 ciphertext length), then a 16-byte salt, a 12-byte IV, and the ciphertext with its tag. AAD is the first 54 bytes.
- Defaults: 256 MiB, 3 passes, 4 lanes. Accepted: 64 MiB–2 GiB, 1–10 passes, 1–16 lanes, checked before derivation.
- An RFC 9106 §5.3 Argon2id KAT runs before the first derivation. The runtime-measured file size for an ML-DSA seed key is 124 bytes.

**PQSE 1/2:** PBKDF2-HMAC-SHA-512, 22-byte header, AAD 50 bytes; read-only. Password failure and corruption both produce `E_KEY_DECRYPT_FAILED`.

## Verification result semantics — code- and runtime-verified

| Field | Meaning |
| --- | --- |
| `valid` | **The only acceptance decision.** Signature policy passes, payload matches, and an independently selected key was used. |
| `integrityValid` | Signature and payload are consistent with the resolved key, possibly the embedded one. Embedded-only gives `valid: false`, `integrityValid: true`, `code: E_SIGNER_UNTRUSTED`. |
| `trusted` | A selected key matched the embedded key and verified. |
| `cryptoValid` | The primitive verified for some candidate key. Diagnostic only; can be true on a binding mismatch. |
| `signaturePolicyValid` | Signature verified under the key-binding rules (not payload). |
| `payloadMatches`, `declaredHashHex`, `signedHashHex` | Digest comparison; `signedHashHex` is non-null only when signature policy passes. |

- Callers cannot inject or override these fields (tested with hostile diagnostics).
- CLI exit codes: 0 valid, 2 integrity-only, 1 anything else.
- A key-suite mismatch throws before any JSON is produced.

## Browser lifecycle and worker interface — code-verified

**Hashing and parsing:**
- Files hash in 4 MiB `slice()` chunks.
- Key and signature files are read whole.
- Fingerprints and the signature preview are computed on the main thread; hashing and PQ verification run in the worker.

**Worker startup and health:**
- The worker is a Blob module created from the SRI-covered bundle. Under the CSP `trusted-types qsig-worker`, the only policy accepts exactly that blob URL.
- Startup KATs (27 checks) cover SHA3-512 of the empty string, and for each suite a valid vector plus wrong-context, wrong-message and damaged-signature rejections.
- A failing KAT latches the worker closed.

**Deadlines and timeouts:**
- Preview deadlines: file 300 s, text 60 s. Verification deadlines: ML-DSA file 120 s and text 60 s; SLH-DSA file 300 s and text 180 s.
- **A timeout terminates the worker and fails its pending requests; the next action starts one fresh worker.** Crashes behave the same way, without restart loops.

**Result acceptance:**
- A result must match the reviewed input hash and length, declared digest, suite/profile/algorithm IDs, context, signature length and key fingerprints. Otherwise it is discarded.
- Changing inputs or the key invalidates the operation.

**Plain Text review:**
- States that CRLF is submitted as LF.
- Lists invisible, bidirectional and separator code points (U+00AD, U+061C, U+180E, U+200B–200F, U+202A–202E, U+2028–2029, U+2060–2064, U+2066–2069, U+FEFF and others).

**CSP:** `default-src 'none'`, `connect-src 'none'`, `script-src 'self'`, `worker-src blob:`, `require-trusted-types-for 'script'`, `trusted-types qsig-worker`. Response headers add framing denial, COOP/COEP/CORP, HSTS and nosniff.
- The application makes no fetch/XHR/WebSocket calls, uses no storage and registers no service worker.
- A compromised HTML origin can still replace the program.

**Internal worker messages** (repository integration only, not a public API):
- Request: `{id, type, payload}`, where `type` is one of `HASH_FILE {file}`, `HASH_TEXT {text}`, `VERIFY_FILE {file, sigFile, publicKeyFile?}`, `VERIFY_TEXT {text, sigFile, publicKeyFile?}`, `SELFTEST {}`, `KEYGEN {suiteId, passphrase}`, `UNLOCK {secretKeyFile, passphrase}` or `SIGN {file|text, expectedDigestHex, expectedFingerprintHex}`.
- `KEYGEN`/`UNLOCK` return `{suiteId, fingerprintHex, publicKeyFile}` (plus `secretKeyFile` as PQSE 3, or `legacy`); `SIGN` returns `{suiteId, fingerprintHex, hashHex, inputLength, signatureFile}`. No request returns a private key. Locking is worker termination.
- Replies: `{type:"RESULT", ok:true, result}`, `{type:"ERROR", ok:false, code, message, details}` or `{type:"PROGRESS", loaded, total, percent}`.
- `ok:true` means the operation completed, not that a signature is valid.

## Runtime verification performed (2.1.0)

`npm run check` passes. It covers the spec conformance vector, security headers, build config, the display-integrity and worker-client tests, the mutation corpora (1,566 QSIG, 1,328 PQPK and 2,576 PQSK mutations for ML-DSA-44, plus 7,715 all-suite native mutations × 2 key policies), the browser-boundary test with sampled all-suite mutations through the real worker bundle, the protocol self-test, native tests, the self-test fault injection, live local headers and the build.

Also run for this revision:
- `FULL_SELFTEST=1` (80/80) and `test:external-vectors`: Wycheproof ML-DSA 631/631; ACVP pure/external sigVer 87 cases across all six suites through both verifiers; 75 ML-DSA keyGen seeds natively.
- `check:repro` for `/` and `/quantum-signer/`, `test:release`, and `npm audit` (0 vulnerabilities).
- CLI round trip:
  - `doctor` gives `selfTest: pass`; keygen, sign and `verify --public` exit 0 with `valid: true`.
  - Without `--public`, `verify` exits 2 with `valid: false, integrityValid: true, E_SIGNER_UNTRUSTED`.
  - A keygen public-path collision exits 1 with `EEXIST` and leaves no private key; a 14-character password exits 1 with `E_KEY_PASSPHRASE_INVALID` and leaves no files.
  - `rewrap` preserves the fingerprint; a wrong digest is refused.
  - Outputs are mode 0600.
- Chromium 152:
  - Trusted Types block string `innerHTML`; the app starts with no CSP violations.
  - The self-test passes 27/27; the spec vector gives VALID with its key and integrity-only without it.
  - The bidi text warning is shown.

**Browser signing (2026-09-26, loopback preview in the built-in Chromium):** ML-DSA-44 keygen with default Argon2id ~2.7 s, unlock ~2.8 s, signing ~50 ms; SLH-DSA-SHAKE-128s keygen ~18 s, signing ~7 s. A browser-generated `.pqse` opens in the CLI with the same fingerprint; wrong passwords, lock and re-unlock behave as described. `browser-signing-test` and `test:browser-boundary` check OpenSSL/browser key and signature interoperability in both directions.

**Not established:**
- Firefox, Safari or mobile engines.
- Windows ACL behaviour.
- The interactive hidden-password prompt on every terminal.
- Timing and memory at maximum sizes.
- Published deployment headers and release provenance.
- OS memory erasure.
- Resilience against a compromised machine or origin.
