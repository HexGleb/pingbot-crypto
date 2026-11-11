"""PingBot envelope reference (CL0 / CL1). Needs: pip install cryptography."""
import base64, hashlib, hmac, json, os, time, zlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding


def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b'=').decode()
def unb64u(s): return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))
def kid_of(key): return hashlib.sha256(key).digest()[:4].hex()
def subkeys(key):
    return (hmac.new(key, b'pingbot enc v1', hashlib.sha256).digest(),
            hmac.new(key, b'pingbot mac v1', hashlib.sha256).digest())
def deflate(b):
    c = zlib.compressobj(9, zlib.DEFLATED, -15); return c.compress(b) + c.flush()
def inflate(b): return zlib.decompress(b, -15)


def seal(obj, key=None, iv=None):
    """obj -> 'CL1.<kid>.<b64u>' (key given) or 'CL0.<b64u>' (no key)."""
    data = deflate(json.dumps(obj, ensure_ascii=False, separators=(',', ':')).encode())
    if key is None:
        return 'CL0.' + b64u(data)
    enc, mac = subkeys(key)
    kid = kid_of(key)
    iv = iv or os.urandom(16)
    p = padding.PKCS7(128).padder(); data = p.update(data) + p.finalize()
    e = Cipher(algorithms.AES(enc), modes.CBC(iv)).encryptor()
    ct = e.update(data) + e.finalize()
    tag = hmac.new(mac, kid.encode() + iv + ct, hashlib.sha256).digest()
    return 'CL1.%s.%s' % (kid, b64u(iv + ct + tag))


def open_(env, key=None):
    """'CL0...' or 'CL1...' -> dict. Raises ValueError on a bad envelope."""
    if env.startswith('CL0.'):
        return json.loads(inflate(unb64u(env[4:])))
    if not env.startswith('CL1.'):
        raise ValueError('not an envelope')
    _, kid, body = env.split('.', 2)
    if kid != kid_of(key):
        raise ValueError('key id mismatch')
    blob = unb64u(body)
    iv, ct, tag = blob[:16], blob[16:-32], blob[-32:]
    enc, mac = subkeys(key)
    if not hmac.compare_digest(tag, hmac.new(mac, kid.encode() + iv + ct, hashlib.sha256).digest()):
        raise ValueError('bad tag')
    d = Cipher(algorithms.AES(enc), modes.CBC(iv)).decryptor()
    data = d.update(ct) + d.finalize()
    u = padding.PKCS7(128).unpadder(); data = u.update(data) + u.finalize()
    return json.loads(inflate(data))


def up(text='', key=None, **x):
    """A phone message: {"v":1,"d":"up","ts":..,"n":..,"text":..,"x":{..}} sealed with key."""
    o = {'v': 1, 'd': 'up', 'ts': int(time.time()), 'n': os.urandom(12).hex(), 'text': text}
    if x:
        o['x'] = x
    return seal(o, key)
