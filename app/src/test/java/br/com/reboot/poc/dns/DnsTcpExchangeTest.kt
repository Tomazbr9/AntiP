package br.com.reboot.poc.dns

import org.junit.Assert.*
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.EOFException
import java.io.IOException

class DnsTcpExchangeTest {

    private val exchange = DnsTcpExchange()

    private fun query(): ByteArray =
        ByteArray(12).apply {
            this[0] = 0x12
            this[1] = 0x34
            this[2] = 0x01
        }

    private fun response(): ByteArray =
        query().apply {
            this[2] = 0x81.toByte()
            this[3] = 0x80.toByte()
        }

    @Test
    fun validExchangeReturnsResponse() {
        val expected = response()
        val input = ByteArrayInputStream(
            DnsTcpMessageCodec.encode(expected)
        )
        val output = ByteArrayOutputStream()

        val result = exchange.execute(
            query(),
            input,
            output
        )

        assertArrayEquals(expected, result)
        assertArrayEquals(
            DnsTcpMessageCodec.encode(query()),
            output.toByteArray()
        )
    }

    @Test
    fun incompleteResponseIsRejected() {
        val input = ByteArrayInputStream(
            byteArrayOf(0, 20, 1, 2, 3)
        )

        assertThrows(EOFException::class.java) {
            exchange.execute(
                query(),
                input,
                ByteArrayOutputStream()
            )
        }
    }

    @Test
    fun mismatchedTransactionIsRejected() {
        val wrongResponse = response().apply {
            this[0] = 0x55
        }

        val input = ByteArrayInputStream(
            DnsTcpMessageCodec.encode(wrongResponse)
        )

        assertThrows(IOException::class.java) {
            exchange.execute(
                query(),
                input,
                ByteArrayOutputStream()
            )
        }
    }

    @Test
    fun queryCannotBeAcceptedAsResponse() {
        val input = ByteArrayInputStream(
            DnsTcpMessageCodec.encode(query())
        )

        assertThrows(IOException::class.java) {
            exchange.execute(
                query(),
                input,
                ByteArrayOutputStream()
            )
        }
    }

    @Test
    fun invalidResponseLengthIsRejected() {
        val input = ByteArrayInputStream(
            byteArrayOf(0, 5)
        )

        assertThrows(IOException::class.java) {
            exchange.execute(
                query(),
                input,
                ByteArrayOutputStream()
            )
        }
    }

    @Test
    fun invalidQueryIsRejected() {
        assertThrows(IllegalArgumentException::class.java) {
            exchange.execute(
                ByteArray(5),
                ByteArrayInputStream(byteArrayOf()),
                ByteArrayOutputStream()
            )
        }
    }
}
