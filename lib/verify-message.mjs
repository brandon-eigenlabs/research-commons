// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Research Commons Authors
// research-commons: verify an EIP-191 signature over a raw message.
//
// Recovers the signer address from (message, signature) and reports it. Trust
// policy lives in the CLI (peer registry + validity windows), not here — this
// only answers "who signed these bytes?".
//
// Usage:  MESSAGE=<string> SIGNATURE=0x… [ADDRESS=0x…] node verify-message.mjs
//         (--stdin reads MESSAGE from stdin)
// Output: {"recovered": "0x…", "valid": true|false}
//         `valid` is the match against ADDRESS when given, else just recovery success.
// Exit:   0 valid · 1 invalid/mismatch · 2 usage error
import { readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { createRequire } from 'node:module';

// viem resolution order: see sign-message.mjs (COMMONS_VIEM_DIR, repo root, cwd).
function loadViem(sub) {
  const roots = [
    process.env.COMMONS_VIEM_DIR,
    new URL('..', import.meta.url).pathname,  // repo root: `npm ci` here
    process.cwd() + '/',
  ].filter(Boolean);
  for (const root of roots) {
    try {
      const resolved = createRequire(root.endsWith('/') ? root : root + '/').resolve(sub);
      return import(new URL('file://' + resolved).href);
    } catch { /* try next root */ }
  }
  console.error('error: cannot locate viem. Run `npm ci` in the repo root, or set COMMONS_VIEM_DIR.');
  process.exit(2);
}
const { recoverMessageAddress } = await loadViem('viem');

let message;
if (process.argv.includes('--stdin')) {
  message = readFileSync(0, 'utf8');
} else {
  message = process.env.MESSAGE;
}
const signature = process.env.SIGNATURE;
const expected = process.env.ADDRESS;

if (message === undefined || !signature) {
  console.error('error: set MESSAGE (or --stdin) and SIGNATURE');
  process.exit(2);
}

try {
  const recovered = await recoverMessageAddress({ message, signature });
  const valid = expected ? recovered.toLowerCase() === expected.toLowerCase() : true;
  console.log(JSON.stringify({ recovered, valid }));
  process.exit(valid ? 0 : 1);
} catch (e) {
  // Malformed signature, wrong length, bad hex: not a crash, just invalid.
  console.log(JSON.stringify({ recovered: null, valid: false, error: e.shortMessage || e.message }));
  process.exit(1);
}
