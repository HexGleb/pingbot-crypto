/**
 * CL0 / CL1 envelopes (SPEC.md), the bridge's side: byte-compatible with the app's Envelope.kt, python/cl_crypto.py
 * and vectors/cl1.txt. Node built-ins only. The bridge imports it through laptop/src/crypto.ts.
 */
import * as crypto from 'node:crypto';
import * as zlib from 'node:zlib';

const MAX_INFLATED = 1024 * 1024;

export const b64u = (b: Buffer): string => b.toString('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');

export function unb64u(s: string): Buffer {
  if (!/^[A-Za-z0-9_-]*$/.test(s) || s.length % 4 === 1) throw new Error('bad base64');
  const b = Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
  // Strict: unused trailing bits must be zero, so a flipped last character never decodes the same.
  if (b64u(b) !== s) throw new Error('bad base64');
  return b;
}

export const kidOf = (key: Buffer): string => crypto.createHash('sha256').update(key).digest().subarray(0, 4).toString('hex');

const hmac = (key: Buffer, data: Buffer): Buffer => crypto.createHmac('sha256', key).update(data).digest();

export function subKeys(key: Buffer): { enc: Buffer; mac: Buffer } {
  return { enc: hmac(key, Buffer.from('cursorlink enc v1', 'ascii')), mac: hmac(key, Buffer.from('cursorlink mac v1', 'ascii')) };
}

export const deflate = (b: Buffer): Buffer => zlib.deflateRawSync(b, { level: 9 });

export function inflate(b: Buffer): Buffer {
  return zlib.inflateRawSync(b, { maxOutputLength: MAX_INFLATED });
}

/** JSON text -> "CL0.<b64u>" (no key) or "CL1.<kid>.<b64u(iv|ct|tag)>". */
export function seal(json: string, key?: Buffer, iv?: Buffer): string {
  const data = deflate(Buffer.from(json, 'utf8'));
  if (!key) return 'CL0.' + b64u(data);
  const { enc, mac } = subKeys(key);
  const kid = kidOf(key);
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
  const { enc, mac } = subKeys(key);
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
