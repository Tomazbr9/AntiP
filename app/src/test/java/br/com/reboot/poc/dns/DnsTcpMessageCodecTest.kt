package br.com.reboot.poc.dns

import org.junit.Assert.*
import org.junit.Test

class DnsTcpMessageCodecTest {

    private fun dnsMessage(size: Int = 12): ByteArray {
        return ByteArray(size).apply {
            this[0] = 0x12
            this[1] = 0x34
        }
    }

    @Test
    fun encodeAddsTwoByteLengthPrefix() {
        val message = dnsMessage()

        val encoded = DnsTcpMessageCodec.encode(message)

        assertEquals(14, encoded.size)
        assertEquals(0, encoded[0].toInt())
        assertEquals(12, encoded[1].toInt())
    }

    @Test
    fun decodeRestoresOriginalMessage() {
        val original = dnsMessage(128)

        val encoded = DnsTcpMessageCodec.encode(original)

        assertArrayEquals(
            original,
            DnsTcpMessageCodec.decode(encoded)
        )
    }

    @Test
    fun supportsMessagesLargerThan255Bytes() {
        val original = dnsMessage(300)

        val encoded = DnsTcpMessageCodec.encode(original)

        assertEquals(1, encoded[0].toInt() and 0xFF)
        assertEquals(44, encoded[1].toInt() and 0xFF)

        assertArrayEquals(
            original,
            DnsTcpMessageCodec.decode(encoded)
        )
    }

    @Test
    fun rejectsIncompleteFrame() {
        val encoded = DnsTcpMessageCodec.encode(
            dnsMessage(100)
        )

        val incomplete = encoded.copyOf(50)

        assertNull(
            DnsTcpMessageCodec.decode(incomplete)
        )
    }

    @Test
    fun rejectsTrailingBytes() {
        val encoded = DnsTcpMessageCodec.encode(
            dnsMessage()
        )

        val invalid = encoded + byteArrayOf(1, 2)

        assertNull(
            DnsTcpMessageCodec.decode(invalid)
        )
    }

    @Test
    fun rejectsDnsMessageSmallerThanHeader() {
        assertThrows(IllegalArgumentException::class.java) {
            DnsTcpMessageCodec.encode(ByteArray(11))
        }
    }

    @Test
    fun rejectsOversizedDnsMessage() {
        assertThrows(IllegalArgumentException::class.java) {
            DnsTcpMessageCodec.encode(ByteArray(65536))
        }
    }

    @Test
    fun acceptsMaximumDnsMessageSize() {
        val original = dnsMessage(65535)

        assertArrayEquals(
            original,
            DnsTcpMessageCodec.decode(
                DnsTcpMessageCodec.encode(original)
            )
        )
    }
}
