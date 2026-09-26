# Quantum Signer

Post-quantum detached signatures with two interfaces to one cryptographic core: a browser application and a native Node/OpenSSL command line tool. Both generate keys, sign and verify, and read and write the same key and signature files.

**Version: 2.1.0.** The browser signs in an isolated worker with pinned JavaScript cryptography; the CLI signs through Node/OpenSSL. The project does not claim FIPS module validation or independent security certification. See [release verification](docs/RELEASE.md) for authenticating downloaded artifacts.

For agent operation, use the [Quantum Signer skill](docs/quantum-signer/SKILL.md), with exact workflows, recovery steps, and code/runtime verification evidence.

## Command line

Use Node.js 26 or newer with ML-DSA and SLH-DSA support. From an authenticated source checkout:

```sh
node src/native/cli.mjs doctor
node src/native/cli.mjs keygen --secret signer.pqse --public signer.pqpk
node src/native/cli.mjs hash --file document.bin
node src/native/cli.mjs sign --secret signer.pqse --file document.bin --expect-sha3-512 REVIEWED_DIGEST --out document.qsig
node src/native/cli.mjs verify --file document.bin --signature document.qsig --public signer.pqpk
```

Replace `REVIEWED_DIGEST` with the exact SHA3-512 digest reviewed from the hash command. Passwords are prompted without echo. Automation can use `--passphrase-fd N` (never `0` on a terminal, which would echo); never put passwords in command arguments. New passwords require at least 15 code points (NIST SP 800-63B-4). Use a strong, unique password and secure backups.

New private keys are PKCS#8 (RFC 5958) encrypted inside PQSE 3 using Argon2id (RFC 9106; 256 MiB, 3 passes, 4 lanes) and AES-256-GCM. Legacy PQSE 1/2 (PBKDF2) and plaintext PQSK keys still load with a warning; migrate them with:

```sh
node src/native/cli.mjs rewrap --secret old.pqse --out signer-v3.pqse
```

QSIG signature compatibility is preserved. Outputs are created exclusively with mode 0600; `keygen` reserves both output paths before generating a key. Use a private output directory and appropriate Windows ACLs.

Before the first use of each suite, the CLI checks the OpenSSL provider against NIST ACVP data (SHA-3, verification, ML-DSA key generation and, before private operations, a signing round trip) and requires OpenSSL 3.5.0 or newer. Any failure stops all operations. `doctor` runs these checks for every suite.

Use `--suite ML-DSA-44`, `ML-DSA-65`, `ML-DSA-87` (default), `SLH-DSA-SHAKE-128s`, `SLH-DSA-SHAKE-192s`, or `SLH-DSA-SHAKE-256s` with `keygen`. Recover a public key with:

```sh
node src/native/cli.mjs public --secret signer.pqse --out signer.pqpk
```

The source CLI needs no third-party runtime cryptography. Signing, key generation, verification and SHA-3 use `node:crypto`; password protection uses standard Web Crypto. Private operations use native KeyObjects, pairwise key checks, and signature/container self-verification. There is no JavaScript signing fallback.

## Browser

```sh
npm ci
npm run preview
```

Open the displayed loopback address.

**Keys:** generate a key (passphrase of at least 15 code points) and save the encrypted `.pqse` and public `.pqpk`, or unlock an existing `.pqse` from the CLI. Browser keys are the same PQSE 3 / PKCS#8 files the CLI writes (ML-DSA keys are stored seed-only, RFC 9881), so either interface can use them. Legacy PQSE 1/2 and PQSK keys load with a migration warning.

**Sign:** select a file or plain text, review its SHA3-512 digest and the signer fingerprint, then sign. The worker signs only that reviewed digest with that key, as the CLI's `--expect-sha3-512` does, and the page re-parses the `.qsig` against the review before offering it.

**Verify:** select a public `.pqpk` key from a trusted source, then the original file/text and `.qsig`.

The private key lives only in the worker: it never crosses to the page, is never stored, and there is no plaintext export. **Lock** terminates the worker; so do 15 idle minutes, closing the tab and worker timeouts. Before its first private operation per suite, the worker checks its signer against NIST ACVP data (ML-DSA key generation and a signing round trip), and every generated or imported key passes a pairwise test. Signatures are hedged (fresh randomness from `crypto.getRandomValues`) and verified before release. Argon2id takes a few seconds; SLH-DSA signing in JavaScript takes several seconds per signature, ML-DSA milliseconds.

The browser runs public NIST known-answer tests at startup. Failure blocks worker operations. Worker bytes are embedded in the SRI-covered application bundle, and the build refuses private-key code in the main-thread bundle. Browser ML-DSA/SLH-DSA, SHA-3 and Argon2id use pinned noble libraries because stable Web Crypto does not provide them; AES-256-GCM, SHA-256 and randomness use Web Crypto.

A matching selected key gives `VALID`; an embedded key alone gives `UNTRUSTED` (integrity only); a mismatched selected key or changed payload gives `INVALID`. CLI exit statuses are respectively 0, 2, and 1. Verification results are fail-safe: `valid` is `true` only when the signature and payload check out *and* an independently selected key was used. The embedded-key case reports `valid: false`, `integrityValid: true` and code `E_SIGNER_UNTRUSTED`, because anyone can sign any file with their own embedded key. Integrations must accept only `valid: true`. A selected key is a trust input, not proof of its owner's identity: compare the full fingerprint through a trusted channel.

The browser enforces Trusted Types. Plain Text mode warns about invisible or bidirectional control characters; browsers submit CRLF as LF, so use File mode for existing files.

## Format and assurance

The [wire specification](spec/qsig-v2.txt) describes exact QSIG 2.0 bytes, authenticated metadata, contexts, reconstruction, legacy key files, PQSE 3, and applicable standards. [`spec/qsig-v2-vector.json`](spec/qsig-v2-vector.json) is a byte-exact conformance vector; `npm run test:spec` checks the specification's tables against it.

QSIG signs a structured 108-byte TBS containing SHA3-512 of the original payload and SHA3-256 of authenticated signer metadata, using the pure ML-DSA/SLH-DSA context API. It does not use KMAC/cSHAKE or the HashML-DSA/HashSLH-DSA variants. It is a custom protocol, not CMS, JOSE or COSE. Filename, timestamp and MIME type are not signed; nonempty display metadata is rejected. Text uses strict UTF-8 without Unicode or newline normalization.

Native KeyObjects reduce exposure of expanded private material to JavaScript. They do not provide hardware isolation, guaranteed erasure of passwords/runtime/OS copies, or protection from a compromised local machine. The JavaScript reference signer used for cross-implementation tests lives in `scripts/lib` and is excluded from all shipped bundles.

## Validation and release

```sh
npm run check
FULL_SELFTEST=1 npm run selftest
npm run test:external-vectors
npm run check:repro
BASE_PATH=/quantum-signer/ npm run check:repro
npm run test:release
```

CI runs full cryptographic checks on pull requests. Native/browser interoperability covers all six suites. `test:external-vectors` runs pinned Wycheproof ML-DSA vectors and pinned NIST ACVP sigVer (pure, external interface, all six parameter sets) through both verifiers, plus all ML-DSA ACVP keyGen seeds natively. It also covers all-suite container mutation corpora, policy injection, PQSE 2/3 tampering, native self-test fault injection, worker faults and release tampering.

The manual release workflow separates dependency-running builds from the job that attests the manifest. Authenticate provenance for the exact reviewed repository/workflow/ref/commit, then verify the full file inventory using a separately trusted checkout before running a downloaded artifact. Unsigned hashes and SRI alone do not authenticate an origin. See [release verification](docs/RELEASE.md) for commands and required operational controls.

`npm run package:release` creates `release/` with the standalone native CLI, browser build, licenses, specification and manifest. Run the authenticated standalone CLI as `node release/quantum-signer.mjs ...`.

GitHub Pages remains a manual, header-limited verification demo. Other static hosts should apply `dist/_headers` and validate the actual responses. Compromise of the HTML/origin can still falsify browser results and capture keys and passwords entered there; an authenticated local release is the stronger delivery model.

## Limitations and trust model

- No PKI: there is no certificate chain, key expiry, revocation or signer identity binding. The trust anchor is the full SHA3-256 fingerprint of a public key obtained through a trusted channel. A compromised key cannot be retired within the format; rotate keys and redistribute fingerprints out of band.
- No trusted time: filename, MIME type and timestamps are not signed, and there is no RFC 3161 timestamp token, so a signature does not prove *when* it was made.
- `.pqpk` files carry only a CRC-32, which detects damage but does not authenticate the key.
- The browser and CLI use different signer and verifier implementations (noble and OpenSSL); both are tested against the same NIST and Wycheproof vectors and against each other.
- Browser signing trusts the serving origin and the browser. While unlocked, the key and derived secrets are in JavaScript memory that cannot be reliably erased. For high-value keys, use the CLI or an authenticated local release on a dedicated origin.
- No FIPS 140-3 module validation, SP 800-90B entropy-source claim or independent third-party audit is claimed.

## License

GNU Affero General Public License v3.0 or later; see [LICENSE](LICENSE).

Browser cryptographic dependencies are [noble-hashes](https://github.com/paulmillr/noble-hashes) and [noble-post-quantum](https://github.com/paulmillr/noble-post-quantum), copyright Paul Miller, MIT licensed. Release artifacts include their license notices.
