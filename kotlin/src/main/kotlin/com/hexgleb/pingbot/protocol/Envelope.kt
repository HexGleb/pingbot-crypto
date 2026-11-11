package com.hexgleb.pingbot.protocol

import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import java.util.zip.Deflater
import java.util.zip.Inflater
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * The laptop protocol v2 envelopes (ntfy.ps1 v19):
 *
 * - `CL0.` + base64url(rawDeflate(json)): no encryption, only when opted in before pairing.
 * - `CL1.` + kid + `.` + base64url(iv16 ‖ AES-256-CBC(rawDeflate(json)) ‖ HMAC-SHA256 tag32),
 *   encrypt-then-MAC with keys derived from the paired 32-byte key.
 *
 * Works on JSON text only, so it has no Android dependencies. Never logs keys or contents.
 */
object Envelope {
    const val CL0 = "CL0."
    const val CL1 = "CL1."

    /** Inflated payloads larger than this are refused. */
    private const val MAX_INFLATED = 1 shl 20

    private val ENC_LABEL = "pingbot enc v1".toByteArray(Charsets.US_ASCII)
    private val MAC_LABEL = "pingbot mac v1".toByteArray(Charsets.US_ASCII)
    private val random = SecureRandom()

    /** Why an envelope couldn't be opened. Safe to log: no key material or contents. */
    class OpenError(val reason: String) : Exception(reason)

    fun isEnvelope(message: String?): Boolean = message != null && (message.startsWith(CL1) || message.startsWith(CL0))

    /** The key id of a CL1 envelope, or null. */
    fun kidOf(envelope: String): String? =
        if (envelope.startsWith(CL1)) envelope.substring(4).substringBefore('.', "").takeIf { it.length == 8 } else null

    /** Lowercase hex of the first 4 bytes of SHA-256(key). */
    fun keyId(key: ByteArray): String = hex(MessageDigest.getInstance("SHA-256").digest(key).copyOf(4))

    fun encKey(key: ByteArray): ByteArray = hmac(key, ENC_LABEL)
    fun macKey(key: ByteArray): ByteArray = hmac(key, MAC_LABEL)

    /**
     * Opens an envelope to its JSON text. [keyFor] returns the key for a kid (current, previous or
     * pending), or null. The tag is checked (constant time) before anything is decrypted.
     */
    fun open(envelope: String, keyFor: (String) -> ByteArray?): String {
        if (envelope.startsWith(CL0)) return inflate(unb64u(envelope.substring(4)))
        if (!envelope.startsWith(CL1)) throw OpenError("not an envelope")
        val rest = envelope.substring(4)
        val dot = rest.indexOf('.')
        if (dot != 8) throw OpenError("malformed")
        val kid = rest.substring(0, 8)
        val key = keyFor(kid) ?: throw OpenError("unknown key id")
        val body = rest.substring(9)
        val blob = try {
            Base64.getUrlDecoder().decode(body)
        } catch (e: IllegalArgumentException) {
            throw OpenError("bad base64")
        }
        // Strict: only the canonical encoding, so changing any character (even one that only
        // carries padding bits) fails instead of decoding to the same bytes.
        if (b64u(blob) != body) throw OpenError("bad base64")
        if (blob.size < 16 + 16 + 32) throw OpenError("too short")
        val keys = derived(kid, key)
        // The tag covers kid ‖ iv ‖ ct: the blob up to its last 32 bytes, read in place.
        val expected = macs.get().run {
            init(keys.mac)
            update(kid.toByteArray(Charsets.US_ASCII))
            update(blob, 0, blob.size - 32)
            doFinal()
        }
        if (!MessageDigest.isEqual(blob.copyOfRange(blob.size - 32, blob.size), expected)) throw OpenError("bad tag")
        val plain = try {
            ciphers.get().run {
                init(Cipher.DECRYPT_MODE, keys.enc, IvParameterSpec(blob, 0, 16))
                doFinal(blob, 16, blob.size - 48)
            }
        } catch (e: Exception) {
            throw OpenError("bad padding")
        }
        return inflate(plain)
    }

    /** Seals JSON text: CL1 under [key], or CL0 when [key] is null. [iv] only for tests. */
    fun seal(json: String, key: ByteArray?, iv: ByteArray? = null): String {
        val data = deflate(json.toByteArray(Charsets.UTF_8))
        if (key == null) return CL0 + b64u(data)
        val kid = keyId(key)
        val keys = derived(kid, key)
        val nonce = iv ?: ByteArray(16).also { random.nextBytes(it) }
        val ct = ciphers.get().run {
            init(Cipher.ENCRYPT_MODE, keys.enc, IvParameterSpec(nonce))
            doFinal(data)
        }
        val tag = macs.get().run {
            init(keys.mac)
            update(kid.toByteArray(Charsets.US_ASCII))
            update(nonce)
            doFinal(ct)
        }
        return CL1 + kid + "." + b64u(nonce + ct + tag)
    }

    /**
     * The two keys a paired key derives ([encKey], [macKey]), kept per key id so an open or a seal
     * doesn't derive them again (two HMACs each time). [raw] is compared first: a different key
     * under the same id derives its own.
     */
    private class Derived(val raw: ByteArray, val enc: SecretKeySpec, val mac: SecretKeySpec)

    private const val MAX_DERIVED = 16

    private val derivedKeys = object : LinkedHashMap<String, Derived>(MAX_DERIVED, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Derived>?): Boolean = size > MAX_DERIVED
    }

    private fun derived(kid: String, key: ByteArray): Derived {
        synchronized(derivedKeys) { derivedKeys[kid] }?.let { if (MessageDigest.isEqual(it.raw, key)) return it }
        val d = Derived(key.copyOf(), SecretKeySpec(encKey(key), "AES"), SecretKeySpec(macKey(key), "HmacSHA256"))
        synchronized(derivedKeys) { derivedKeys[kid] = d }
        return d
    }

    /** Drops the derived keys kept for [open] and [seal] (memory trimmed, keys retired); they are derived again when next used. */
    fun forgetDerivedKeys() {
        synchronized(derivedKeys) { derivedKeys.clear() }
    }

    /** One Mac and one Cipher per thread: `getInstance` looks the provider up each time; `init` resets them for each use. */
    private val macs: ThreadLocal<Mac> = ThreadLocal.withInitial { Mac.getInstance("HmacSHA256") }
    private val ciphers: ThreadLocal<Cipher> = ThreadLocal.withInitial { Cipher.getInstance("AES/CBC/PKCS5Padding") }

    /** 12 random bytes as 24 hex characters: the per-message nonce `n`. */
    fun nonce(): String = hex(ByteArray(12).also { random.nextBytes(it) })

    fun newKey(): ByteArray = ByteArray(32).also { random.nextBytes(it) }

    fun b64u(b: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(b)

    /** Lenient: accepts padding, standard alphabet and stray whitespace (manual entry). */
    fun unb64u(s: String): ByteArray {
        val clean = s.filterNot { it.isWhitespace() || it == '=' }.replace('+', '-').replace('/', '_')
        return Base64.getUrlDecoder().decode(clean)
    }

    /** Lowercase hex, from a table (no `String.format` per byte). */
    fun hex(b: ByteArray): String {
        val out = CharArray(b.size * 2)
        for (i in b.indices) {
            val v = b[i].toInt() and 0xff
            out[2 * i] = HEX[v ushr 4]
            out[2 * i + 1] = HEX[v and 0xf]
        }
        return String(out)
    }

    private val HEX = "0123456789abcdef".toCharArray()

    private fun hmac(key: ByteArray, data: ByteArray): ByteArray =
        macs.get().run {
            init(SecretKeySpec(key, "HmacSHA256"))
            doFinal(data)
        }

    private fun deflate(data: ByteArray): ByteArray {
        val d = Deflater(9, true)
        try {
            d.setInput(data)
            d.finish()
            val out = ByteArrayOutputStream(data.size / 2 + 64)
            val buf = ByteArray(8192)
            while (!d.finished()) out.write(buf, 0, d.deflate(buf))
            return out.toByteArray()
        } finally {
            d.end()
        }
    }

    private fun inflate(data: ByteArray): String {
        val inf = Inflater(true)
        try {
            // Raw inflate wants one spare byte after the stream (zlib's nowrap quirk).
            inf.setInput(data + 0)
            val out = ByteArrayOutputStream(data.size * 3 + 64)
            val buf = ByteArray(8192)
            while (!inf.finished()) {
                val n = try {
                    inf.inflate(buf)
                } catch (e: Exception) {
                    throw OpenError("bad deflate")
                }
                if (n == 0) {
                    if (inf.needsInput() || inf.needsDictionary()) break
                }
                out.write(buf, 0, n)
                if (out.size() > MAX_INFLATED) throw OpenError("too large")
            }
            if (!inf.finished()) throw OpenError("truncated")
            return out.toString(Charsets.UTF_8.name())
        } finally {
            inf.end()
        }
    }
}
