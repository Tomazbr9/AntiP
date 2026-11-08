package br.com.reboot.poc.dns

import org.junit.Assert.*
import org.junit.Test
import java.io.ByteArrayOutputStream

class DnsFallbackFailurePolicyTest {

    private fun u16(value: Int) = byteArrayOf(
        (value ushr 8).toByte(),
        value.toByte()
    )

    private fun query(): ByteArray {
        val out = ByteArrayOutputStream()

        out.write(u16(0x1234))
        out.write(u16(0x0100))
        out.write(u16(1))
        out.write(u16(0))
        out.write(u16(0))
        out.write(u16(0))

        out.write(7)
        out.write("example".toByteArray())
        out.write(3)
        out.write("org".toByteArray())
        out.write(0)

        out.write(u16(1)) // A
        out.write(u16(1)) // IN

        return out.toByteArray()
    }

    private fun resultBytes(
        result: DnsDeliveryDecision
    ): ByteArray {
        assertTrue(result is DnsDeliveryDecision.Send)
        return (result as DnsDeliveryDecision.Send).response
    }

    @Test
    fun tcpFailureProducesServfail() {
        val bytes = resultBytes(
            DnsFallbackFailurePolicy.decide(
                query(),
                DnsFallbackResult.TcpFailed
            )
        )

        assertEquals(0x12, bytes[0].toInt() and 0xFF)
        assertEquals(0x34, bytes[1].toInt() and 0xFF)
        assertEquals(0x80, bytes[2].toInt() and 0x80)
        assertEquals(2, bytes[3].toInt() and 0x0F)
        assertEquals(1, bytes[5].toInt() and 0xFF)
        assertEquals(0, bytes[7].toInt() and 0xFF)
    }

    @Test
    fun oversizedResponseProducesServfail() {
        val result = DnsFallbackFailurePolicy.decide(
            query(),
            DnsFallbackResult.ResponseTooLarge
        )

        val bytes = resultBytes(result)

        assertEquals(2, bytes[3].toInt() and 0x0F)
        assertTrue(bytes.size <= 512)
    }

    @Test
    fun invalidTcpResponseProducesServfail() {
        val bytes = resultBytes(
            DnsFallbackFailurePolicy.decide(
                query(),
                DnsFallbackResult.InvalidTcpResponse
            )
        )

        assertEquals(2, bytes[3].toInt() and 0x0F)
    }

    @Test
    fun invalidUdpResponseIsDropped() {
        assertEquals(
            DnsDeliveryDecision.Drop,
            DnsFallbackFailurePolicy.decide(
                query(),
                DnsFallbackResult.InvalidUdpResponse
            )
        )
    }

    @Test
    fun acceptedUdpResponseIsPreserved() {
        val response = query().copyOf().apply {
            this[2] = 0x81.toByte()
            this[3] = 0x80.toByte()
        }

        val result = DnsFallbackFailurePolicy.decide(
            query(),
            DnsFallbackResult.UdpAccepted(response)
        )

        assertArrayEquals(response, resultBytes(result))
    }

    @Test
    fun acceptedTcpResponseIsPreserved() {
        val response = query().copyOf().apply {
            this[2] = 0x81.toByte()
            this[3] = 0x80.toByte()
        }

        val result = DnsFallbackFailurePolicy.decide(
            query(),
            DnsFallbackResult.TcpAccepted(response)
        )

        assertArrayEquals(response, resultBytes(result))
    }

    @Test
    fun invalidQueryCannotProduceServfail() {
        val result = DnsFallbackFailurePolicy.decide(
            ByteArray(5),
            DnsFallbackResult.TcpFailed
        )

        assertEquals(DnsDeliveryDecision.Drop, result)
    }

    @Test
    fun servfailPreservesOriginalQuestion() {
        val original = query()
        val bytes = resultBytes(
            DnsFallbackFailurePolicy.decide(
                original,
                DnsFallbackResult.TcpFailed
            )
        )

        assertArrayEquals(
            original.copyOfRange(12, original.size),
            bytes.copyOfRange(12, bytes.size)
        )

        assertTrue(
            DnsMessageStructureValidator.validate(
                original,
                bytes
            )
        )
    }
}
