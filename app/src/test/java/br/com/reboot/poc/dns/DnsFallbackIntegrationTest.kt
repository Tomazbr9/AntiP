package br.com.reboot.poc.dns

import org.junit.Assert.*
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.FilterInputStream
import java.io.IOException
import java.io.InputStream

class DnsFallbackIntegrationTest {

    private fun u16(value: Int) = byteArrayOf(
        (value ushr 8).toByte(),
        value.toByte()
    )

    private fun question(name: String): ByteArray {
        val out = ByteArrayOutputStream()

        name.split(".").forEach { label ->
            val bytes = label.toByteArray(Charsets.US_ASCII)
            out.write(bytes.size)
            out.write(bytes)
        }

        out.write(0)
        out.write(u16(1)) // A
        out.write(u16(1)) // IN

        return out.toByteArray()
    }

    private fun query(
        name: String = "example.org",
        ednsSize: Int? = null
    ): ByteArray {
        val out = ByteArrayOutputStream()

        out.write(u16(0x1234))
        out.write(u16(0x0100))
        out.write(u16(1)) // Question
        out.write(u16(0)) // Answer
        out.write(u16(0)) // Authority
        out.write(u16(if (ednsSize == null) 0 else 1))

        out.write(question(name))

        if (ednsSize != null) {
            out.write(0)       // Root name
            out.write(u16(41)) // OPT
            out.write(u16(ednsSize))
            out.write(byteArrayOf(0, 0, 0, 0))
            out.write(u16(0))
        }

        return out.toByteArray()
    }

    private fun response(
        name: String = "example.org",
        truncated: Boolean = false,
        dataSize: Int = 4
    ): ByteArray {
        val out = ByteArrayOutputStream()

        out.write(u16(0x1234))
        out.write(
            u16(if (truncated) 0x8380 else 0x8180)
        )

        out.write(u16(1)) // Question
        out.write(u16(1)) // Answer
        out.write(u16(0))
        out.write(u16(0))

        out.write(question(name))

        // Compressed name: pointer to question.
        out.write(byteArrayOf(0xC0.toByte(), 0x0C))

        // Tipo privado/desconhecido, para construir
        // RDATA opaco de tamanho controlado.
        out.write(u16(65000))
        out.write(u16(1))
        out.write(byteArrayOf(0, 0, 0, 60))
        out.write(u16(dataSize))
        out.write(ByteArray(dataSize) { 0x42 })

        return out.toByteArray()
    }

    private fun tcpExchange(
        query: ByteArray,
        response: ByteArray,
        partialReads: Boolean = false
    ): ByteArray {
        val encoded = DnsTcpMessageCodec.encode(response)
        val source = ByteArrayInputStream(encoded)

        val input: InputStream = if (partialReads) {
            object : FilterInputStream(source) {
                override fun read(
                    b: ByteArray,
                    off: Int,
                    len: Int
                ): Int {
                    return super.read(
                        b,
                        off,
                        minOf(len, 3)
                    )
                }
            }
        } else {
            source
        }

        val output = ByteArrayOutputStream()

        val result = DnsTcpExchange().execute(
            query = query,
            input = input,
            output = output
        )

        assertArrayEquals(
            DnsTcpMessageCodec.encode(query),
            output.toByteArray()
        )

        return result
    }

    @Test
    fun validUdpDoesNotUseTcp() {
        val q = query()
        var tcpCalls = 0

        val selector = DnsResponseSelectionCoordinator {
            tcpCalls++
            error("TCP must not be called")
        }

        val result = selector.select(q, response())

        assertTrue(result is DnsFallbackResult.UdpAccepted)
        assertEquals(0, tcpCalls)
    }

    @Test
    fun truncatedUdpUsesTcpExchange() {
        val q = query()
        val expected = response()
        var tcpCalls = 0

        val selector = DnsResponseSelectionCoordinator {
            tcpCalls++
            tcpExchange(it, expected, partialReads = true)
        }

        val result = selector.select(
            q,
            response(truncated = true)
        )

        assertTrue(result is DnsFallbackResult.TcpAccepted)
        assertEquals(1, tcpCalls)

        val accepted = result as DnsFallbackResult.TcpAccepted
        assertArrayEquals(expected, accepted.response)
    }

    @Test
    fun brokenTcpStreamReportsFailure() {
        val q = query()
        val expected = response()
        val incomplete = DnsTcpMessageCodec.encode(expected)
            .copyOf(10)

        val selector = DnsResponseSelectionCoordinator {
            DnsTcpExchange().execute(
                it,
                ByteArrayInputStream(incomplete),
                ByteArrayOutputStream()
            )
        }

        assertEquals(
            DnsFallbackResult.TcpFailed,
            selector.select(
                q,
                response(truncated = true)
            )
        )
    }

    @Test
    fun mismatchedQuestionIsRejected() {
        val selector = DnsResponseSelectionCoordinator {
            response(name = "another.org")
        }

        assertEquals(
            DnsFallbackResult.InvalidTcpResponse,
            selector.select(
                query(),
                response(truncated = true)
            )
        )
    }

    @Test
    fun malformedResourceRecordIsRejected() {
        val valid = response()
        val invalid = valid.copyOf()

        // RDLENGTH do último registro: valor maior
        // que os quatro bytes realmente presentes.
        val rdLengthOffset = invalid.size - 4 - 2
        invalid[rdLengthOffset] = 0
        invalid[rdLengthOffset + 1] = 100.toByte()

        val selector = DnsResponseSelectionCoordinator {
            invalid
        }

        assertEquals(
            DnsFallbackResult.InvalidTcpResponse,
            selector.select(
                query(),
                response(truncated = true)
            )
        )
    }

    @Test
    fun legacyClientRejectsLargeTcpResponse() {
        val selector = DnsResponseSelectionCoordinator {
            response(dataSize = 550)
        }

        assertEquals(
            DnsFallbackResult.ResponseTooLarge,
            selector.select(
                query(),
                response(truncated = true)
            )
        )
    }

    @Test
    fun ednsClientAcceptsLargerTcpResponse() {
        val selector = DnsResponseSelectionCoordinator {
            response(dataSize = 550)
        }

        val result = selector.select(
            query(ednsSize = 1232),
            response(truncated = true)
        )

        assertTrue(result is DnsFallbackResult.TcpAccepted)
    }

    @Test
    fun mtuLimitRejectsOversizedTcpResponse() {
        val selector = DnsResponseSelectionCoordinator {
            response(dataSize = 1500)
        }

        assertEquals(
            DnsFallbackResult.ResponseTooLarge,
            selector.select(
                query(ednsSize = 4096),
                response(truncated = true)
            )
        )
    }

    @Test
    fun wrongTransactionIdIsRejected() {
        val invalid = response().copyOf().apply {
            this[0] = 0x55
        }

        val selector = DnsResponseSelectionCoordinator {
            invalid
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
