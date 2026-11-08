
package br.com.reboot.poc.dns

import org.junit.Assert.*
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.IOException

class DnsResponseSelectionCoordinatorTest {

    private fun u16(value: Int) = byteArrayOf(
        (value ushr 8).toByte(),
        value.toByte()
    )

    private fun query(ednsSize: Int? = null): ByteArray {
        val out = ByteArrayOutputStream()

        out.write(u16(0x1234))
        out.write(byteArrayOf(0x01, 0x00))
        out.write(u16(1))
        out.write(u16(0))
        out.write(u16(0))
        out.write(u16(if (ednsSize == null) 0 else 1))

        out.write(7)
        out.write("example".toByteArray())
        out.write(3)
        out.write("org".toByteArray())
        out.write(0)
        out.write(u16(1))
        out.write(u16(1))

        if (ednsSize != null) {
            out.write(0)
            out.write(u16(41))
            out.write(u16(ednsSize))
            out.write(byteArrayOf(0, 0, 0, 0))
            out.write(u16(0))
        }

        return out.toByteArray()
    }

    private fun response(
        size: Int = 100,
        truncated: Boolean = false
    ): ByteArray = ByteArray(size).apply {
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
    fun normalUdpResponseIsAcceptedWithoutTcp() {
        var tcpCalls = 0

        val selector = DnsResponseSelectionCoordinator {
            tcpCalls++
            response()
        }

        val result = selector.select(
            query(),
            response()
        )

        assertTrue(result is DnsFallbackResult.UdpAccepted)
        assertEquals(0, tcpCalls)
    }

    @Test
    fun truncatedUdpTriggersTcp() {
        var tcpCalls = 0

        val selector = DnsResponseSelectionCoordinator {
            tcpCalls++
            response(size = 400)
        }

        val result = selector.select(
            query(),
            response(truncated = true)
        )

        assertTrue(result is DnsFallbackResult.TcpAccepted)
        assertEquals(1, tcpCalls)
    }

    @Test
    fun tcpCannotExceedLegacyUdpLimit() {
        val selector = DnsResponseSelectionCoordinator {
            response(size = 900)
        }

        val result = selector.select(
            query(),
            response(truncated = true)
        )

        assertEquals(
            DnsFallbackResult.ResponseTooLarge,
            result
        )
    }

    @Test
    fun ednsAllowsLargerTcpResponse() {
        val selector = DnsResponseSelectionCoordinator {
            response(size = 900)
        }

        val result = selector.select(
            query(ednsSize = 1232),
            response(truncated = true)
        )

        assertTrue(result is DnsFallbackResult.TcpAccepted)
    }

    @Test
    fun responseCannotExceedTunMtu() {
        val selector = DnsResponseSelectionCoordinator {
            response(size = 1500)
        }

        val result = selector.select(
            query(ednsSize = 4096),
            response(truncated = true)
        )

        assertEquals(
            DnsFallbackResult.ResponseTooLarge,
            result
        )
    }

    @Test
    fun invalidUdpResponseIsRejectedWithoutTcp() {
        var tcpCalls = 0

        val selector = DnsResponseSelectionCoordinator {
            tcpCalls++
            response()
        }

        val result = selector.select(
            query(),
            byteArrayOf(1, 2, 3)
        )

        assertEquals(
            DnsFallbackResult.InvalidUdpResponse,
            result
        )
        assertEquals(0, tcpCalls)
    }

    @Test
    fun tcpFailureIsReported() {
        val selector = DnsResponseSelectionCoordinator {
            throw IOException("TCP unavailable")
        }

        val result = selector.select(
            query(),
            response(truncated = true)
        )

        assertEquals(
            DnsFallbackResult.TcpFailed,
            result
        )
    }

    @Test
    fun truncatedTcpResponseIsRejected() {
        val selector = DnsResponseSelectionCoordinator {
            response(truncated = true)
        }

        val result = selector.select(
            query(),
            response(truncated = true)
        )

        assertEquals(
            DnsFallbackResult.InvalidTcpResponse,
            result
        )
    }
}
