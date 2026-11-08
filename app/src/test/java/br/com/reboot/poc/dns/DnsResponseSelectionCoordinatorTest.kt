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

    private fun query(): ByteArray {
        val out = ByteArrayOutputStream()

        out.write(u16(0x1234))
        out.write(u16(0x0100))
        out.write(u16(1))
        out.write(u16(0))
        out.write(u16(0))
        out.write(u16(0))

        // example.org
        out.write(7)
        out.write("example".toByteArray())
        out.write(3)
        out.write("org".toByteArray())
        out.write(0)

        out.write(u16(1)) // A
        out.write(u16(1)) // IN

        return out.toByteArray()
    }

    private fun response(
        truncated: Boolean = false,
        withAnswer: Boolean = false
    ): ByteArray {
        val out = ByteArrayOutputStream()

        out.write(u16(0x1234))
        out.write(
            u16(if (truncated) 0x8380 else 0x8180)
        )
        out.write(u16(1))
        out.write(u16(if (withAnswer) 1 else 0))
        out.write(u16(0))
        out.write(u16(0))

        // Copia a pergunta original.
        val question = query()
        out.write(
            question,
            12,
            question.size - 12
        )

        if (withAnswer) {
            // Ponteiro para example.org.
            out.write(byteArrayOf(
                0xC0.toByte(), 0x0C
            ))

            out.write(u16(1)) // A
            out.write(u16(1)) // IN
            out.write(byteArrayOf(0, 0, 0, 60))
            out.write(u16(4))
            out.write(byteArrayOf(1, 2, 3, 4))
        }

        return out.toByteArray()
    }

    @Test
    fun validUdpResponseIsAcceptedWithoutTcp() {
        var tcpCalls = 0

        val selector = DnsResponseSelectionCoordinator {
            tcpCalls++
            response()
        }

        val result = selector.select(
            query(),
            response(withAnswer = true)
        )

        assertTrue(result is DnsFallbackResult.UdpAccepted)
        assertEquals(0, tcpCalls)
    }

    @Test
    fun truncatedUdpTriggersTcpFallback() {
        var tcpCalls = 0

        val selector = DnsResponseSelectionCoordinator {
            tcpCalls++
            response(withAnswer = true)
        }

        val result = selector.select(
            query(),
            response(truncated = true)
        )

        assertTrue(result is DnsFallbackResult.TcpAccepted)
        assertEquals(1, tcpCalls)
    }

    @Test
    fun invalidCompleteUdpResponseIsRejected() {
        var tcpCalls = 0

        val selector = DnsResponseSelectionCoordinator {
            tcpCalls++
            response()
        }

        val invalid = response().copyOf().apply {
            this[12] = 0x7F.toByte()
        }

        val result = selector.select(
            query(),
            invalid
        )

        assertEquals(
            DnsFallbackResult.InvalidUdpResponse,
            result
        )
        assertEquals(0, tcpCalls)
    }

    @Test
    fun invalidTcpResponseIsRejected() {
        val selector = DnsResponseSelectionCoordinator {
            response(withAnswer = true).copyOf().apply {
                // Adicionar bytes inesperados.
            } + byteArrayOf(1, 2)
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
    fun mismatchedTruncatedHeaderDoesNotCallTcp() {
        var tcpCalls = 0

        val selector = DnsResponseSelectionCoordinator {
            tcpCalls++
            response()
        }

        val invalid = response(
            truncated = true
        ).copyOf().apply {
            this[0] = 0x55
        }

        assertEquals(
            DnsFallbackResult.InvalidUdpResponse,
            selector.select(query(), invalid)
        )

        assertEquals(0, tcpCalls)
    }

    @Test
    fun tcpResponseWithTruncationIsRejected() {
        val selector = DnsResponseSelectionCoordinator {
            response(truncated = true)
        }

        assertEquals(
            DnsFallbackResult.InvalidTcpResponse,
            selector.select(
                query(),
                response(truncated = true)
            )
        )
    }
}
