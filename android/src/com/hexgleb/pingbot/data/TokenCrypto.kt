package com.hexgleb.pingbot.data

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.InvalidKeyException
import java.security.KeyStore
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * AES-GCM with a non-exportable key in the Android Keystore: how the ntfy token and pairing keys
 * are stored. Never logs what it encrypts.
 */
class TokenCrypto {
    private val alias = "pingbot.token.v1"

    /** A Keystore failure that may pass (busy, locked, provider hiccup): try again later, don't forget the secret. */
    class TransientException(cause: Throwable) : Exception(cause.javaClass.simpleName, cause)

    private fun key(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getKey(alias, null) as? SecretKey)?.let { return it }
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        gen.init(
            KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build(),
        )
        return gen.generateKey()
    }

    fun encrypt(plain: String): String {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, key())
        val out = c.iv + c.doFinal(plain.toByteArray(Charsets.UTF_8))
        return Base64.encodeToString(out, Base64.NO_WRAP)
    }

    /**
     * The plain text, or null when it can never be decrypted (corrupt, or the Keystore key was
     * reset). Throws [TransientException] when the Keystore failed in a way that may pass.
     */
    fun decrypt(enc: String): String? {
        val all = try {
            Base64.decode(enc, Base64.NO_WRAP)
        } catch (e: IllegalArgumentException) {
            return null
        }
        if (all.size < 12 + 16) return null
        return try {
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, all, 0, 12))
            String(c.doFinal(all, 12, all.size - 12), Charsets.UTF_8)
        } catch (e: AEADBadTagException) {
            null
        } catch (e: InvalidKeyException) {
            // Includes KeyPermanentlyInvalidatedException.
            null
        } catch (e: Exception) {
            throw TransientException(e)
        }
    }
}
