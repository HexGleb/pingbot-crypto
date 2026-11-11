/**
 * CL0 / CL1 envelopes (SPEC.md), the bridge's side: byte-compatible with the app's Envelope.kt, python/cl_crypto.py
 * and vectors/cl1.txt. Node built-ins only. The bridge imports it through laptop/src/crypto.ts.
 */
import * as crypto from 'node:crypto';
import * as zlib from 'node:zlib';

const MAX_INFLATED = 1024 * 1024;

/** base64url without padding (Node's own encoder). */
export const b64u = (b: Buffer): string => b.toString('base64url');

/**
 * Strict base64url: only the canonical, unpadded encoding. Node's decoder skips what it can't read and takes
 * padding, `+` and `/`, so the answer is encoded again and must give back the input: a stray character, padding,
 * the standard alphabet, a dangling last character or unused trailing bits that aren't zero all fail.
 */
export function unb64u(s: string): Buffer {
  const b = Buffer.from(s, 'base64url');
  if (b.toString('base64url') !== s) throw new Error('bad base64');
  return b;
}

export const kidOf = (key: Buffer): string => crypto.createHash('sha256').update(key).digest().subarray(0, 4).toString('hex');

const hmac = (key: Buffer, data: Buffer): Buffer => crypto.createHmac('sha256', key).update(data).digest();

export function subKeys(key: Buffer): { enc: Buffer; mac: Buffer } {
  return { enc: hmac(key, Buffer.from('pingbot enc v1', 'ascii')), mac: hmac(key, Buffer.from('pingbot mac v1', 'ascii')) };
}

/** [subKeys] kept per key id for seal and open (two HMACs less per message); a different key under the same id derives its own. */
const derived = new Map<string, { key: Buffer; enc: Buffer; mac: Buffer }>();
const MAX_DERIVED = 16;

function keysFor(kid: string, key: Buffer): { enc: Buffer; mac: Buffer } {
  const hit = derived.get(kid);
  if (hit && hit.key.equals(key)) return hit;
  const d = { key: Buffer.from(key), ...subKeys(key) };
  derived.delete(kid);
  derived.set(kid, d);
  if (derived.size > MAX_DERIVED) derived.delete(derived.keys().next().value as string);
  return d;
}

export const deflate = (b: Buffer): Buffer => zlib.deflateRawSync(b, { level: 9 });

export function inflate(b: Buffer): Buffer {
  return zlib.inflateRawSync(b, { maxOutputLength: MAX_INFLATED });
}

/** JSON text -> "CL0.<b64u>" (no key) or "CL1.<kid>.<b64u(iv|ct|tag)>". */
export function seal(json: string, key?: Buffer, iv?: Buffer): string {
  const data = deflate(Buffer.from(json, 'utf8'));
  if (!key) return 'CL0.' + b64u(data);
  const kid = kidOf(key);
  const { enc, mac } = keysFor(kid, key);
  const v = iv ?? crypto.randomBytes(16);
  const c = crypto.createCipheriv('aes-256-cbc', enc, v);
  const ct = Buffer.concat([c.update(data), c.final()]);
  const tag = hmac(mac, Buffer.concat([Buffer.from(kid, 'ascii'), v, ct]));
  return `CL1.${kid}.${b64u(Buffer.concat([v, ct, tag]))}`;
}

export class EnvelopeError extends Error {}

/** Opens "CL1.<kid>.<body>" with the key for that kid; throws EnvelopeError with the reason. */
export function openCl1(text: string, keyFor: (kid: string) => Buffer | null): { json: string; kid: string } {
  const m = /^CL1\.([0-9a-f]{8})\.([A-Za-z0-9_-]+)$/.exec(text.trim());
  if (!m) throw new EnvelopeError('not a CL1 envelope');
  const kid = m[1];
  const key = keyFor(kid);
  if (!key) throw new EnvelopeError(`unknown key ${kid}`);
  let blob: Buffer;
  try { blob = unb64u(m[2]); } catch { throw new EnvelopeError('bad base64'); }
  if (blob.length < 64 || (blob.length - 48) % 16 !== 0) throw new EnvelopeError('bad length');
  const iv = blob.subarray(0, 16);
  const ct = blob.subarray(16, blob.length - 32);
  const tag = blob.subarray(blob.length - 32);
  const { enc, mac } = keysFor(kid, key);
  const want = hmac(mac, Buffer.concat([Buffer.from(kid, 'ascii'), iv, ct]));
  if (!crypto.timingSafeEqual(want, tag)) throw new EnvelopeError('bad signature');
  let plain: Buffer;
  try {
    const d = crypto.createDecipheriv('aes-256-cbc', enc, iv);
    plain = Buffer.concat([d.update(ct), d.final()]);
  } catch { throw new EnvelopeError('decrypt failed'); }
  try { return { json: inflate(plain).toString('utf8'), kid }; } catch { throw new EnvelopeError('inflate failed'); }
}

export function openCl0(text: string): string {
  return inflate(unb64u(text.trim().slice(4))).toString('utf8');
}

export const randomHex = (bytes: number): string => crypto.randomBytes(bytes).toString('hex');
