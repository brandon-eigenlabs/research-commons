// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Research Commons Authors
// Batch EIP-191 recovery: one process, many messages. Reads JSON lines
// {message, signature, address} on stdin, writes {recovered, valid} per line.
import { readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { createRequire } from 'node:module';
function loadViem(sub) {
  const roots = [process.env.COMMONS_VIEM_DIR,
    new URL('..', import.meta.url).pathname,  // repo root: `npm ci` here
    process.cwd() + '/'].filter(Boolean);
  for (const root of roots) {
    try {
      const r = createRequire(root.endsWith('/') ? root : root + '/').resolve(sub);
      return import(new URL('file://' + r).href);
    } catch {}
  }
  console.error('error: cannot locate viem');
  process.exit(2);
}
const { recoverMessageAddress } = await loadViem('viem');
const lines = readFileSync(0, 'utf8').split('\n').filter(l => l.trim());
const out = [];
for (const line of lines) {
  let rec = null, valid = false;
  try {
    const { message, signature, address } = JSON.parse(line);
    rec = await recoverMessageAddress({ message, signature });
    valid = address ? rec.toLowerCase() === address.toLowerCase() : true;
  } catch (e) { rec = null; valid = false; }
  out.push(JSON.stringify({ recovered: rec, valid }));
}
console.log(out.join('\n'));
