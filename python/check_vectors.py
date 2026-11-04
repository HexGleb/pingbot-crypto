"""cl_crypto.py (the Python reference) against vectors/cl1.txt. Run from the crypto folder:
python3 python/check_vectors.py   (needs: pip install cryptography)"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
# Published repo: cl_crypto.py sits next to this file. App repo: it lives in laptop/test-harness/.
sys.path.insert(0, os.path.join(HERE, '..', '..', 'laptop', 'test-harness'))
sys.path.insert(0, HERE)
import cl_crypto as c  # noqa: E402

v = {}
with open(os.path.join(HERE, '..', 'vectors', 'cl1.txt'), encoding='utf8') as f:
    for line in f:
        line = line.rstrip('\r\n')
        if line.strip() and not line.startswith('#'):
            name, _, value = line.partition(' ')
            v[name] = value

key = c.unb64u(v['key'])
enc, mac = c.subkeys(key)
assert len(key) == 32
assert c.kid_of(key) == v['kid'], 'kid'
assert enc.hex() == v['enc_key'] and mac.hex() == v['mac_key'], 'subkeys'

import json  # noqa: E402
for name, plain in (('down.cl1', 'down.plain'), ('up.cl1', 'up.plain'), ('ps51.cl1', 'ps51.plain'), ('cl0', 'down.plain')):
    assert c.open_(v[name], key) == json.loads(v[plain]), name
for d in ('down', 'up'):
    assert c.seal(json.loads(v[d + '.plain']), key, bytes.fromhex(v[d + '.iv'])) == v[d + '.cl1'], d + ' seal'

rejects = [k for k in v if k.startswith('reject.')]
assert len(rejects) >= 4
for name in rejects:
    try:
        c.open_(v[name], key)
    except Exception:
        continue
    raise AssertionError(name + ' opened')
print('cl1 vectors: ok')
