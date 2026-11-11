# PingBot crypto (CL1)

The encryption PingBot uses between your laptop and your phone, published so you can check it yourself.
The PingBot app and the PingBot bridge are both built from exactly this code.

- **What it is:** [SPEC.md](SPEC.md), in plain words: the key, the envelope, pairing, replay protection,
  what the relay can still see, and the known limits.
- **What it proves:** the relay that carries your messages (run by PingBot) cannot read or change them; the key
  only ever moves by QR code on your own screen; the app and the bridge implement the same recipe, byte for byte.
- **What it does not prove:** what the closed parts of the app do with a message after decrypting it
  (SPEC.md, section 6).

## What's here

| Path | What | Used by |
|---|---|---|
| `SPEC.md` | the CL1 specification | everyone |
| `vectors/cl1.txt` | test vectors every implementation must pass | all tests below |
| `kotlin/` | `Envelope.kt`: seal and open, key ids, sub-keys (pure Kotlin, JVM) | the Android app (its `:cl1` module) |
| `android/src/` | `TokenCrypto.kt`: how the app stores the pairing key (AES-GCM under a non-exportable Android Keystore key) | the Android app |
| `ts/` | `crypto.ts`: the same in TypeScript (Node built-ins only) | the laptop bridge |
| `python/` | `cl_crypto.py`, a short independent reference, and `check_vectors.py` | the bridge's tests |

## Check it

From this folder:

```
node --test ts/vectors.test.ts         # Node 22.18 or later
python3 python/check_vectors.py        # pip install cryptography
gradle :kotlin:test                    # Gradle 9, any JDK 17 or later
```

## How releases match

Each tag here (`cl1-v1.0.0`, ...) lists the app and bridge versions built from it. The app compiles `kotlin/`
and `android/src/` as they are here. The bridge bundles `ts/crypto.ts` into `pingbot.js`, which ships
unminified with its source map, so you can compare the two directly.

## Licence and reports

Apache License 2.0 ([LICENSE](LICENSE), [NOTICE](NOTICE)). Found a problem? See [SECURITY.md](SECURITY.md).
