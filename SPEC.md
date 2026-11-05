# CL1: how PingBot encrypts between your laptop and your phone

PingBot has three parts. The **bridge** runs on your laptop next to Cursor. The **app** runs on your Android
phone. The **relay** is an ntfy server run by PingBot that passes messages between the two. CL1 makes sure
the relay, and anyone between you and it, only ever carries sealed envelopes it cannot read or change.

## 1. The key

- The bridge makes a key: 32 random bytes from the operating system's secure random source.
- You move it to the phone by scanning a QR code (or typing the code) shown on the laptop's own screen.
  The key never travels over the relay or any network. On PingBot's relay the QR code also carries a one-use
  claim id, which lets the account service link the two devices; the claim id is not a key.
- The key id (`kid`) is the first 4 bytes of SHA-256(key), as 8 lower-case hex characters. It names the key
  in every envelope and reveals nothing about it.
- Stored: on the laptop in a file only your user can read (mode 0600 outside Windows); on the phone
  encrypted with AES-256-GCM under a non-exportable Android Keystore key (`android/src/.../TokenCrypto.kt`),
  and the app forbids Android backups.

Two sub-keys come from the key, so the same bytes are never used for two jobs:

```
encKey = HMAC-SHA256(key, ascii("cursorlink enc v1"))
macKey = HMAC-SHA256(key, ascii("cursorlink mac v1"))
```

## 2. The envelope

```
CL1.<kid>.<b64u(iv[16] ‖ ct ‖ tag[32])>
  ct  = AES-256-CBC(encKey, iv, PKCS#7(rawDeflate(json)))
  tag = HMAC-SHA256(macKey, ascii(kid) ‖ iv ‖ ct)
```

- Encrypt-then-MAC. The opener checks the tag in constant time **before** decrypting anything, so a changed
  envelope is refused without touching the cipher (no padding oracle).
- `iv`: 16 fresh random bytes per envelope.
- `b64u`: base64url without padding, and it must be canonical (re-encoding gives the same text), so no two
  spellings of one envelope exist.
- `rawDeflate`: raw DEFLATE, level 9, over the UTF-8 JSON. An opened payload over 1 MiB is refused.
- `CL0.<b64u(rawDeflate(json))>` is the same JSON with no encryption. It exists only for a laptop and phone
  that were never paired, and is refused on both sides from the moment a key is paired.

## 3. What is inside, and why replays fail

```json
{"v":1,"d":"up","ts":1791100060,"n":"ffeeddccbbaa998877665544","text":"Keep it running","x":{"chat":"e5b0bf58"}}
```

These fields sit inside the encrypted, authenticated JSON, so the relay can neither read nor change them:

| Field | What it stops |
|---|---|
| `d` (`down` laptop to phone, `up` phone to laptop) | Reflection: an envelope sent back the other way is refused. |
| `ts` (Unix seconds) | Old envelopes: each side accepts only a window around its own clock and the relay's, 10 min ahead and back 24 h (the bridge) or 169 h (the app: the relay's 7-day cache and an hour). |
| `n` (12 random bytes) | Replays: the bridge accepts each nonce once (kept 48 h). The app keeps a digest of every envelope it opened for longer than its window (about 170 h) and drops a repeat. |

## 4. Pairing, re-pairing and unpairing

1. The bridge shows a new key as a QR code. It is **pending**: the bridge accepts only a pairing message under
   it, and only for 30 minutes.
2. The phone scans it and sends a pairing message sealed under that key. The bridge makes it current.
3. The bridge answers `paired`, sealed under the new key. Only that sealed answer makes the key current on the
   phone; a plain or wrongly keyed `paired` is ignored.
4. After a re-pair the phone still opens messages under the old key for 10 minutes, then forgets it.
5. Once paired, every message that is not a valid CL1 envelope is dropped on both sides. A plain "unpaired"
   notice is shown as unverified and can never talk the phone back into plain text.

## 5. What the relay still sees

Encryption hides content, not traffic. The relay sees:

- the topic names and the account that owns them;
- when each message is sent and how big it is (compression makes size depend a little on the content);
- the outer priority, which decides whether the phone gets a push now or picks the message up later;
- for push, Firebase gets a wake-up with the message id, topic, time and priority, never a title or body.

It keeps sealed envelopes for 7 days (`cache-duration: 168h`), then drops them.

## 6. Known limits

- **No forward secrecy.** One key serves a pairing until you re-pair. Someone who steals the key from the
  laptop or phone, and also kept the relay's traffic, can read what that key sealed. Re-pairing starts a new key.
- **Length leaks.** Compressing before encrypting makes envelope size depend on the content. Nobody but you
  controls what goes in, so the known attacks on this (which need the attacker's text mixed with a secret) do
  not fit, but sizes are visible.
- **The phone is trusted.** Whoever holds the paired phone can read the chats and send replies, approvals
  (if you turned phone approvals on) and new-agent requests to the bridge. The bridge's own rules, in its
  public code, decide what the phone may do.
- **This repo proves the recipe, not the app.** The app's other code is closed. This repo shows the exact
  crypto the app is built with, and that it matches the bridge byte for byte. It cannot show what the app does
  with text after decrypting it.

## 7. Test vectors

[`vectors/cl1.txt`](vectors/cl1.txt) holds a key, its sub-keys, two envelopes with their IVs and plain text
(one each way), a CL0 envelope, one made by the original PowerShell bridge, and four envelopes that must be
refused. The Kotlin, TypeScript and Python code in this repo all pass them; the Kotlin and Python sealers
reproduce the envelopes byte for byte.
