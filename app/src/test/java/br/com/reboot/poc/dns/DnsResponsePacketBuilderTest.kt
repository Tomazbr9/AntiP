package br.com.reboot.poc.dns

import org.junit.Assert.*
import org.junit.Test

class DnsResponsePacketBuilderTest {

    private fun u16(data: ByteArray, offset: Int): Int =
        ((data[offset].toInt() and 0xFF) shl 8) or
                (data[offset + 1].toInt() and 0xFF)

    private fun put16(
        data: ByteArray,
        offset: Int,
        value: Int
    ) {
        data[offset] = (value ushr 8).toByte()
        data[offset + 1] = value.toByte()
    }

    private fun query(): ByteArray {
        val question = byteArrayOf(
            7, 101, 120, 97, 109, 112, 108, 101,
            3, 111, 114, 103, 0,
            0, 1, 0, 1
        )

        return ByteArray(12 + question.size).apply {
            put16(this, 0, 0x1234)
            put16(this, 2, 0x0100)
            put16(this, 4, 1)
            question.copyInto(this, 12)
        }
    }

    private fun dnsResponse(size: Int = 64): ByteArray {
        require(size >= 12)

        return ByteArray(size).apply {
            put16(this, 0, 0x1234)
            put16(this, 2, 0x8180)

            // Conteúdo de teste para conferir
            // preservação dos bytes pelo builder.
            for (i in 12 until size) {
                this[i] = (i and 0xFF).toByte()
            }
        }
    }

    private fun requestPacket(): ByteArray {
        val dns = query()
        val udpLength = 8 + dns.size
        val packet = ByteArray(20 + udpLength)

        packet[0] = 0x45
        put16(packet, 2, packet.size)
        packet[8] = 64
        packet[9] = 17

        // Cliente: 10.111.0.1
        byteArrayOf(10, 111, 0, 1)
            .copyInto(packet, 12)

        // DNS virtual: 10.111.0.2
        byteArrayOf(10, 111, 0, 2)
            .copyInto(packet, 16)

        put16(packet, 20, 53000)
        put16(packet, 22, 53)
        put16(packet, 24, udpLength)

        dns.copyInto(packet, 28)

        return packet
    }

    private fun build(response: ByteArray): ByteArray {
        val request = requestPacket()

        return requireNotNull(
            DnsResponsePacketBuilder.build(
                request,
                request.size,
                response
            )
        )
    }

    /**
     * Verificação independente do checksum.
     * Um cabeçalho com checksum válido deve
     * produzir o resultado 0xFFFF na soma
     * de complemento de um.
     */
    private fun validChecksum(bytes: ByteArray): Boolean {
        var sum = 0L
        var index = 0

        while (index + 1 < bytes.size) {
            val word =
                ((bytes[index].toInt() and 0xFF) shl 8) or
                        (bytes[index + 1].toInt() and 0xFF)

            sum += word.toLong()
            index += 2
        }

        if (index < bytes.size) {
            sum += (
                    (bytes[index].toInt() and 0xFF) shl 8
                    ).toLong()
        }

        while (sum > 0xFFFFL) {
            sum = (sum and 0xFFFFL) + (sum ushr 16)
        }

        return sum == 0xFFFFL
    }

    private fun udpPseudoHeader(
        packet: ByteArray
    ): ByteArray {
        val udpLength = u16(packet, 24)
        val pseudo = ByteArray(12 + udpLength)

        // Endereços IP de origem e destino.
        packet.copyInto(
            pseudo,
            destinationOffset = 0,
            startIndex = 12,
            endIndex = 20
        )

        pseudo[8] = 0
        pseudo[9] = 17
        put16(pseudo, 10, udpLength)

        packet.copyInto(
            pseudo,
            destinationOffset = 12,
            startIndex = 20,
            endIndex = 20 + udpLength
        )

        return pseudo
    }

    @Test
    fun buildsValidIpv4HeaderChecksum() {
        val packet = build(dnsResponse())

        assertTrue(
            validChecksum(packet.copyOfRange(0, 20))
        )
    }

    @Test
    fun buildsValidUdpChecksum() {
        val packet = build(dnsResponse())

        assertNotEquals(0, u16(packet, 26))
        assertTrue(
            validChecksum(udpPseudoHeader(packet))
        )
    }

    @Test
    fun handlesOddLengthDnsPayload() {
        val packet = build(dnsResponse(65))

        assertTrue(
            validChecksum(udpPseudoHeader(packet))
        )
    }

    @Test
    fun reversesIpv4Addresses() {
        val request = requestPacket()
        val packet = build(dnsResponse())

        assertArrayEquals(
            request.copyOfRange(16, 20),
            packet.copyOfRange(12, 16)
        )

        assertArrayEquals(
            request.copyOfRange(12, 16),
            packet.copyOfRange(16, 20)
        )
    }

    @Test
    fun reversesUdpPorts() {
        val packet = build(dnsResponse())

        assertEquals(53, u16(packet, 20))
        assertEquals(53000, u16(packet, 22))
    }

    @Test
    fun preservesDnsResponseBytes() {
        val dns = dnsResponse(100)
        val packet = build(dns)

        assertArrayEquals(
            dns,
            packet.copyOfRange(28, packet.size)
        )
    }

    @Test
    fun writesCorrectPacketLengths() {
        val dns = dnsResponse(120)
        val packet = build(dns)

        assertEquals(148, packet.size)
        assertEquals(packet.size, u16(packet, 2))
        assertEquals(128, u16(packet, 24))
        assertEquals(4, packet[0].toInt() ushr 4)
        assertEquals(17, packet[9].toInt() and 0xFF)
    }

    @Test
    fun acceptsMaximumMtu() {
        val packet = build(dnsResponse(1472))

        assertEquals(1500, packet.size)
        assertTrue(
            validChecksum(udpPseudoHeader(packet))
        )
    }

    @Test
    fun rejectsPayloadBeyondMtu() {
        val request = requestPacket()

        assertNull(
            DnsResponsePacketBuilder.build(
                request,
                request.size,
                dnsResponse(1473)
            )
        )
    }

    @Test
    fun rejectsMismatchedDnsTransactionId() {
        val request = requestPacket()
        val response = dnsResponse()

        response[0] = 0x55

        assertNull(
            DnsResponsePacketBuilder.build(
                request,
                request.size,
                response
            )
        )
    }

    @Test
    fun rejectsDnsQueryAsResponse() {
        val request = requestPacket()

        assertNull(
            DnsResponsePacketBuilder.build(
                request,
                request.size,
                query()
            )
        )
    }

    @Test
    fun rejectsWrongDestinationPort() {
        val request = requestPacket()
        put16(request, 22, 443)

        assertNull(
            DnsResponsePacketBuilder.build(
                request,
                request.size,
                dnsResponse()
            )
        )
    }

    @Test
    fun rejectsMalformedRequestLength() {
        val request = requestPacket()

        assertNull(
            DnsResponsePacketBuilder.build(
                request,
                request.size + 1,
                dnsResponse()
            )
        )
    }

    @Test
    fun rejectsFragmentedIpv4Request() {
        val request = requestPacket()

        // More Fragments flag.
        put16(request, 6, 0x2000)

        assertNull(
            DnsResponsePacketBuilder.build(
                request,
                request.size,
                dnsResponse()
            )
        )
    }
}
