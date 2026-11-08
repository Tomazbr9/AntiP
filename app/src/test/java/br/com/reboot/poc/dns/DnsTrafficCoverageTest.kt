package br.com.reboot.poc

import br.com.reboot.poc.dns.DnsTrafficCoverage
import br.com.reboot.poc.dns.DnsTrafficKind
import org.junit.Assert.assertEquals
import org.junit.Test

class DnsTrafficCoverageTest {

    private fun ipv4Packet(
        protocol: Int,
        destinationPort: Int
    ): ByteArray {

        val transportSize = if (protocol == 17) 8 else 20
        val totalSize = 20 + transportSize
        val packet = ByteArray(totalSize)

        packet[0] = 0x45
        packet[2] = (totalSize ushr 8).toByte()
        packet[3] = totalSize.toByte()
        packet[9] = protocol.toByte()

        packet[22] = (destinationPort ushr 8).toByte()
        packet[23] = destinationPort.toByte()

        return packet
    }

    @Test
    fun identifiesUdpDns() {
        val packet = ipv4Packet(17, 53)

        assertEquals(
            DnsTrafficKind.IPV4_UDP_53,
            DnsTrafficCoverage.classify(packet, packet.size)
        )
    }

    @Test
    fun identifiesTcpDns() {
        val packet = ipv4Packet(6, 53)

        assertEquals(
            DnsTrafficKind.IPV4_TCP_53,
            DnsTrafficCoverage.classify(packet, packet.size)
        )
    }

    @Test
    fun identifiesTcp853() {
        val packet = ipv4Packet(6, 853)

        assertEquals(
            DnsTrafficKind.IPV4_TCP_853,
            DnsTrafficCoverage.classify(packet, packet.size)
        )
    }

    @Test
    fun otherTrafficIsNotDns() {
        val packet = ipv4Packet(6, 443)

        assertEquals(
            DnsTrafficKind.IPV4_OTHER,
            DnsTrafficCoverage.classify(packet, packet.size)
        )
    }

    @Test
    fun malformedPacketIsRejected() {
        assertEquals(
            DnsTrafficKind.MALFORMED,
            DnsTrafficCoverage.classify(
                byteArrayOf(0x45),
                1
            )
        )
    }

    @Test
    fun minimalIpv6PacketIsRecognized() {
        val packet = ByteArray(40)
        packet[0] = 0x60

        assertEquals(
            DnsTrafficKind.IPV6_OBSERVED,
            DnsTrafficCoverage.classify(packet, packet.size)
        )
    }
}
