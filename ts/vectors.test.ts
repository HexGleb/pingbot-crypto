/**
 * crypto.ts against the shared vectors (vectors/cl1.txt). Runs in the bridge's tests (laptop: npm test) and on its
 * own with Node 22.18 or later: `node --test ts/vectors.test.ts` from the crypto folder.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { kidOf, openCl0, openCl1, seal, subKeys, unb64u } from './crypto.ts';

/** vectors/cl1.txt, found upward from the working folder: the repo's root when published, laptop/ in the app's repo. */
function vectorsFile(): string {
  for (let dir = process.cwd(); ; dir = dirname(dir)) {
    for (const p of [join(dir, 'vectors', 'cl1.txt'), join(dir, 'crypto', 'vectors', 'cl1.txt')]) if (existsSync(p)) return p;
    if (dirname(dir) === dir) throw new Error('vectors/cl1.txt not found');
  }
}

const v = new Map<string, string>();
for (const line of readFileSync(vectorsFile(), 'utf8').split(/\r?\n/)) {
  if (!line.trim() || line.startsWith('#')) continue;
  const sp = line.indexOf(' ');
  v.set(line.slice(0, sp), line.slice(sp + 1));
}
const get = (name: string): string => {
  const s = v.get(name);
  if (s === undefined) throw new Error(`no vector ${name}`);
  return s;
};
const KEY = unb64u(get('key'));
const keyFor = (kid: string): Buffer | null => (kid === kidOf(KEY) ? KEY : null);

test('key id and subkeys', () => {
  assert.equal(KEY.length, 32);
  assert.equal(kidOf(KEY), get('kid'));
  const { enc, mac } = subKeys(KEY);
  assert.equal(enc.toString('hex'), get('enc_key'));
  assert.equal(mac.toString('hex'), get('mac_key'));
});

test('the vectors open to their plain text', () => {
  assert.equal(openCl1(get('down.cl1'), keyFor).json, get('down.plain'));
  assert.equal(openCl1(get('up.cl1'), keyFor).json, get('up.plain'));
  assert.equal(openCl1(get('ps51.cl1'), keyFor).json, get('ps51.plain'));
  assert.equal(openCl0(get('cl0')), get('down.plain'));
});

test('sealing with the given iv opens back to the same text', () => {
  // Node's zlib may pick other deflate blocks than the JVM's, so only the round trip is required here.
  for (const d of ['down', 'up']) {
    const env = seal(get(`${d}.plain`), KEY, Buffer.from(get(`${d}.iv`), 'hex'));
    assert.ok(env.startsWith(`CL1.${get('kid')}.`));
    assert.equal(openCl1(env, keyFor).json, get(`${d}.plain`));
  }
});

test('rejects are refused', () => {
  const rejects = [...v.keys()].filter((k) => k.startsWith('reject.'));
  assert.ok(rejects.length >= 4);
  for (const name of rejects) assert.throws(() => openCl1(get(name), keyFor), Error, name);
});

test('base64url is strict: only the canonical unpadded text decodes', () => {
  assert.deepEqual(unb64u('AQID_-8'), Buffer.from([1, 2, 3, 0xff, 0xef]));
  assert.equal(unb64u('').length, 0);
  for (const bad of ['AQID_-8=', 'AQID/+8', 'AQ ID', 'A', 'AQID_-9', 'AQ\nID', 'AQID_-8.', 'AR']) {
    assert.throws(() => unb64u(bad), /bad base64/, JSON.stringify(bad));
  }
});

test('subkeys kept per key id are only reused for the same key', () => {
  const env = get('down.cl1');
  assert.equal(openCl1(env, keyFor).json, get('down.plain'));
  const other = Buffer.from(KEY);
  other[0] ^= 1;
  assert.throws(() => openCl1(env, () => other), Error);
  assert.equal(openCl1(env, keyFor).json, get('down.plain'));
});
