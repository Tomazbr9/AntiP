package br.com.reboot.poc.dns

import org.junit.Assert.*
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.IOException

class DnsRelayPacketPlannerTest {

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
        out.write(u16(1))
        out.write(u16(1))

        return out.toByteArray()
    }

    private fun response(
        truncated: Boolean = false,
        rdataSize: Int = 4
    ): ByteArray {
        val out = ByteArrayOutputStream()

        out.write(u16(0x1234))
        out.write(u16(if (truncated) 0x8380 else 0x8180))
        out.write(u16(1))
        out.write(u16(1))
        out.write(u16(0))
        out.write(u16(0))

        val q = query()
        out.write(q, 12, q.size - 12)

        // Nome comprimido referenciando a pergunta.
        out.write(byteArrayOf(0xC0.toByte(), 0x0C))

        // Tipo privado: permite testar RDATA opaco.
        out.write(u16(65000))
        out.write(u16(1))
        out.write(byteArrayOf(0, 0, 0, 60))
        out.write(u16(rdataSize))
        out.write(ByteArray(rdataSize) { 0x42 })

        return out.toByteArray()
    }

    private fun ipv4UdpRequest(): ByteArray {
        val dns = query()
        val udpLength = 8 + dns.size
        val totalLength = 20 + udpLength

        val packet = ByteArray(totalLength)

        fun put16(offset: Int, value: Int) {
            packet[offset] = (value ushr 8).toByte()
            packet[offset + 1] = value.toByte()
        }

        // IPv4 sem opções.
        packet[0] = 0x45
        put16(2, totalLength)
        packet[8] = 64
        packet[9] = 17 // UDP

        // Origem: 10.111.0.1
        packet[12] = 10
        packet[13] = 111
        packet[14] = 0
        packet[15] = 1

        // Destino: 10.111.0.2
        packet[16] = 10
        packet[17] = 111
        packet[18] = 0
        packet[19] = 2

        put16(20, 53000)
        put16(22, 53)
        put16(24, udpLength)

        System.arraycopy(
            dns, 0, packet, 28, dns.size
        )

        return packet
    }

    private fun requireReady(
        plan: DnsPacketPlan
    ): DnsPacketPlan.Ready {
        assertTrue(plan is DnsPacketPlan.Ready)
        return plan as DnsPacketPlan.Ready
    }

    private fun dnsFromPacket(packet: ByteArray): ByteArray {
        val totalLength =
            ((packet[2].toInt() and 0xFF) shl 8) or
                    (packet[3].toInt() and 0xFF)

        assertEquals(packet.size, totalLength)
        assertTrue(packet.size <= 1500)

        val ihl = (packet[0].toInt() and 0x0F) * 4

        return packet.copyOfRange(ihl + 8, packet.size)
    }

    @Test
    fun validUdpBuildsReplyPacket() {
        var tcpCalls = 0
        val planner = DnsRelayPacketPlanner {
            tcpCalls++
            error("TCP should not be called")
        }

        val request = ipv4UdpRequest()
        val result = requireReady(
            planner.plan(request, request.size, response())
        )

        assertFalse(result.usedTcpFallback)
        assertEquals(0, tcpCalls)
        assertArrayEquals(
            response(),
            dnsFromPacket(result.packet)
        )

        // Endereços IPv4 invertidos.
        assertArrayEquals(
            request.copyOfRange(16, 20),
            result.packet.copyOfRange(12, 16)
        )

        // Porta origem 53 na resposta.
        assertEquals(0, result.packet[20].toInt() and 0xFF)
        assertEquals(53, result.packet[21].toInt() and 0xFF)
    }

    @Test
    fun truncatedUdpUsesTcpResponse() {
        var tcpCalls = 0

        val planner = DnsRelayPacketPlanner {
            tcpCalls++
            response()
        }

        val request = ipv4UdpRequest()
        val result = requireReady(
            planner.plan(
                request,
                request.size,
                response(truncated = true)
            )
        )

        assertTrue(result.usedTcpFallback)
        assertEquals(1, tcpCalls)

        assertArrayEquals(
            response(),
            dnsFromPacket(result.packet)
        )
    }

    @Test
    fun tcpFailureProducesServfailPacket() {
        val planner = DnsRelayPacketPlanner {
            throw IOException("Upstream unavailable")
        }

        val request = ipv4UdpRequest()
        val result = requireReady(
            planner.plan(
                request,
                request.size,
                response(truncated = true)
            )
        )

        assertFalse(result.usedTcpFallback)

        val dns = dnsFromPacket(result.packet)

        assertEquals(2, dns[3].toInt() and 0x0F)

        assertTrue(
            DnsMessageStructureValidator.validate(
                query(), dns
            )
        )
    }

    @Test
    fun oversizedTcpProducesServfail() {
        val planner = DnsRelayPacketPlanner {
            response(rdataSize = 600)
        }

        val request = ipv4UdpRequest()
        val result = requireReady(
            planner.plan(
                request,
                request.size,
                response(truncated = true)
            )
        )

        val dns = dnsFromPacket(result.packet)

        assertEquals(2, dns[3].toInt() and 0x0F)
        assertTrue(dns.size <= 512)
    }

    @Test
    fun invalidUdpResponseIsDropped() {
        var tcpCalls = 0
        val planner = DnsRelayPacketPlanner {
            tcpCalls++
            response()
        }

        val request = ipv4UdpRequest()
        val result = planner.plan(
            request,
            request.size,
            byteArrayOf(1, 2, 3)
        )

        assertEquals(DnsPacketPlan.Dropped, result)
        assertEquals(0, tcpCalls)
    }

    @Test
    fun invalidRequestPacketIsRejected() {
        val planner = DnsRelayPacketPlanner {
            response()
        }

        val invalid = byteArrayOf(1, 2, 3)

        assertEquals(
            DnsPacketPlan.InvalidQuery,
            planner.plan(
                invalid,
                invalid.size,
                response()
            )
        )
    }

    @Test
    fun malformedTcpResponseProducesServfail() {
        val planner = DnsRelayPacketPlanner {
            response().copyOf().apply {
                this[0] = 0x55
            }
        }

        val request = ipv4UdpRequest()
        val result = requireReady(
            planner.plan(
                request,
                request.size,
                response(truncated = true)
            )
        )

        val dns = dnsFromPacket(result.packet)

        assertEquals(2, dns[3].toInt() and 0x0F)
    }
}
