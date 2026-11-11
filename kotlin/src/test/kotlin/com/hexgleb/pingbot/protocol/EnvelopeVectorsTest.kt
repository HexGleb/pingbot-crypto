package com.hexgleb.pingbot.protocol

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.File

/** Envelope against the shared vectors in crypto/vectors/cl1.txt (the same file the TypeScript and Python checks read). */
class EnvelopeVectorsTest {
    private val v: Map<String, String> = File(System.getProperty("cl1.vectors") ?: "../vectors/cl1.txt")
        .readLines(Charsets.UTF_8)
        .filter { it.isNotBlank() && !it.startsWith("#") }
        .associate { it.substringBefore(' ') to it.substringAfter(' ') }

    private val key = Envelope.unb64u(v.getValue("key"))
    private fun keys(kid: String): ByteArray? = if (kid == v["kid"]) key else null
    private fun bytes(hex: String) = ByteArray(hex.length / 2) { hex.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    @Test
    fun keyIdAndSubkeys() {
        assertEquals(32, key.size)
        assertEquals(v["kid"], Envelope.keyId(key))
        assertEquals(v["enc_key"], Envelope.hex(Envelope.encKey(key)))
        assertEquals(v["mac_key"], Envelope.hex(Envelope.macKey(key)))
    }

    @Test
    fun vectorsOpen() {
        assertEquals(v["down.plain"], Envelope.open(v.getValue("down.cl1"), ::keys))
        assertEquals(v["up.plain"], Envelope.open(v.getValue("up.cl1"), ::keys))
        assertEquals(v["down.plain"], Envelope.open(v.getValue("cl0"), ::keys))
        assertEquals(v["ps51.plain"], Envelope.open(v.getValue("ps51.cl1"), ::keys))
    }

    @Test
    fun sealingWithTheGivenIvReproducesTheVectors() {
        for (d in listOf("down", "up")) {
            assertEquals(v["$d.cl1"], Envelope.seal(v.getValue("$d.plain"), key, bytes(v.getValue("$d.iv"))))
        }
    }

    @Test
    fun aFreshSealOpensAndNeverRepeats() {
        val plain = v.getValue("up.plain")
        val a = Envelope.seal(plain, key)
        val b = Envelope.seal(plain, key)
        assertTrue(a != b)
        assertEquals(plain, Envelope.open(a, ::keys))
    }

    /** K20: the derived keys are kept per key id, but only for the key they came from. */
    @Test
    fun anotherKeyUnderTheSameIdDerivesItsOwn() {
        val env = v.getValue("down.cl1")
        assertEquals(v["down.plain"], Envelope.open(env, ::keys))
        val other = key.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
        try {
            Envelope.open(env) { other }
            fail("opened under another key")
        } catch (e: Envelope.OpenError) {
            assertEquals("bad tag", e.reason)
        }
        assertEquals("the right key still opens it", v["down.plain"], Envelope.open(env, ::keys))
        Envelope.forgetDerivedKeys()
        assertEquals(v["down.plain"], Envelope.open(env, ::keys))
        assertEquals(v["down.cl1"], Envelope.seal(v.getValue("down.plain"), key, bytes(v.getValue("down.iv"))))
    }

    @Test
    fun rejectsAreRefused() {
        val rejects = v.filterKeys { it.startsWith("reject.") }
        assertTrue(rejects.size >= 4)
        for ((name, env) in rejects) {
            try {
                Envelope.open(env, ::keys)
                fail("$name opened")
            } catch (e: Envelope.OpenError) {
                // refused, as it must be
            }
        }
    }
}
