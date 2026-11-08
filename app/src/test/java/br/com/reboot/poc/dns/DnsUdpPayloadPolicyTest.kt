package br.com.reboot.poc.dns

import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.ByteArrayOutputStream

class DnsUdpPayloadPolicyTest {

    private fun u16(value: Int) = byteArrayOf(
        (value ushr 8).toByte(),
        value.toByte()
    )

    private fun query(
        ednsSize: Int? = null
    ): ByteArray {
        val out = ByteArrayOutputStream()

        // Cabeçalho DNS.
        out.write(u16(0x1234))
        out.write(byteArrayOf(0x01, 0x00))
        out.write(u16(1)) // QDCOUNT
        out.write(u16(0)) // ANCOUNT
        out.write(u16(0)) // NSCOUNT
        out.write(u16(if (ednsSize != null) 1 else 0))

        // Consulta: example.org, A, IN.
        out.write(7)
        out.write("example".toByteArray())
        out.write(3)
        out.write("org".toByteArray())
        out.write(0)
        out.write(u16(1))
        out.write(u16(1))

        if (ednsSize != null) {
            out.write(0)       // Nome raiz
            out.write(u16(41)) // OPT
            out.write(u16(ednsSize))
            out.write(byteArrayOf(0, 0, 0, 0))
            out.write(u16(0))  // RDLENGTH
        }

        return out.toByteArray()
    }

    private fun response(
        size: Int,
        truncated: Boolean = false
    ): ByteArray =
        ByteArray(size).apply {
            this[0] = 0x12
            this[1] = 0x34
            this[2] = if (truncated) {
                0x83.toByte()
            } else {
                0x81.toByte()
            }
            this[3] = 0x80.toByte()
        }

    @Test
    fun legacyQueryUses512Bytes() {
        assertEquals(
            512,
            DnsUdpPayloadPolicy.advertisedLimit(query())
        )
    }

    @Test
    fun ednsQueryUsesAdvertisedLimit() {
        assertEquals(
            1232,
            DnsUdpPayloadPolicy.advertisedLimit(
                query(ednsSize = 1232)
            )
        )
    }

    @Test
    fun ednsLimitCannotExceedTunCapacity() {
        assertEquals(
            1472,
            DnsUdpPayloadPolicy.advertisedLimit(
                query(ednsSize = 4096)
            )
        )
    }

    @Test
    fun legacyOversizedResponseIsRejected() {
        assertEquals(
            DnsUdpPayloadDecision.TOO_LARGE,
            DnsUdpPayloadPolicy.evaluate(
                query(),
                response(600)
            )
        )
    }

    @Test
    fun ednsAllowsLargerResponse() {
        assertEquals(
            DnsUdpPayloadDecision.ACCEPTED,
            DnsUdpPayloadPolicy.evaluate(
                query(ednsSize = 1232),
                response(600)
            )
        )
    }

    @Test
    fun truncatedResponseIsIdentified() {
        assertEquals(
            DnsUdpPayloadDecision.TRUNCATED,
            DnsUdpPayloadPolicy.evaluate(
                query(),
                response(100, truncated = true)
            )
        )
    }

    @Test
    fun invalidResponseIsRejected() {
        assertEquals(
            DnsUdpPayloadDecision.INVALID_RESPONSE,
            DnsUdpPayloadPolicy.evaluate(
                query(),
                byteArrayOf(1, 2, 3)
            )
        )
    }

    @Test
    fun responseCannotExceedTunLimit() {
        assertEquals(
            DnsUdpPayloadDecision.TOO_LARGE,
            DnsUdpPayloadPolicy.evaluate(
                query(ednsSize = 4096),
                response(1473)
            )
        )
    }
}
