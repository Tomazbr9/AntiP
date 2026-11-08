package br.com.reboot.poc.dns

enum class DnsTrafficKind {
    IPV4_UDP_53,
    IPV4_TCP_53,
    IPV4_TCP_853,
    IPV4_OTHER,
    IPV6_OBSERVED,
    UNKNOWN,
    MALFORMED
}

object DnsTrafficCoverage {

    fun classify(
        packet: ByteArray,
        length: Int
    ): DnsTrafficKind {

        if (length <= 0 || length > packet.size) {
            return DnsTrafficKind.MALFORMED
        }

        val version = (packet[0].toInt() ushr 4) and 0x0F

        return when (version) {
            4 -> classifyIpv4(packet, length)
            6 -> classifyIpv6(packet, length)
            else -> DnsTrafficKind.UNKNOWN
        }
    }

    private fun classifyIpv4(
        packet: ByteArray,
        length: Int
    ): DnsTrafficKind {

        if (length < 20) return DnsTrafficKind.MALFORMED

        val headerLength =
            (packet[0].toInt() and 0x0F) * 4

        if (headerLength < 20 || headerLength > length) {
            return DnsTrafficKind.MALFORMED
        }

        fun u16(offset: Int): Int =
            ((packet[offset].toInt() and 0xFF) shl 8) or
                    (packet[offset + 1].toInt() and 0xFF)

        val totalLength = u16(2)

        if (totalLength < headerLength ||
            totalLength > length
        ) {
            return DnsTrafficKind.MALFORMED
        }

        // Fragmentos não iniciais não possuem,
        // necessariamente, cabeçalho de transporte.
        val fragmentOffset = u16(6) and 0x1FFF

        if (fragmentOffset != 0) {
            return DnsTrafficKind.IPV4_OTHER
        }

        val protocol = packet[9].toInt() and 0xFF

        if (protocol != 6 && protocol != 17) {
            return DnsTrafficKind.IPV4_OTHER
        }

        val minTransportHeader =
            if (protocol == 17) 8 else 20

        if (headerLength + minTransportHeader > totalLength) {
            return DnsTrafficKind.MALFORMED
        }

        val destinationPort = u16(headerLength + 2)

        return when {
            protocol == 17 && destinationPort == 53 ->
                DnsTrafficKind.IPV4_UDP_53

            protocol == 6 && destinationPort == 53 ->
                DnsTrafficKind.IPV4_TCP_53

            protocol == 6 && destinationPort == 853 ->
                DnsTrafficKind.IPV4_TCP_853

            else -> DnsTrafficKind.IPV4_OTHER
        }
    }

    private fun classifyIpv6(
        packet: ByteArray,
        length: Int
    ): DnsTrafficKind {

        if (length < 40) return DnsTrafficKind.MALFORMED

        val payloadLength =
            ((packet[4].toInt() and 0xFF) shl 8) or
                    (packet[5].toInt() and 0xFF)

        if (payloadLength + 40 > length) {
            return DnsTrafficKind.MALFORMED
        }

        // Não interpretamos extensões IPv6 neste incremento.
        return DnsTrafficKind.IPV6_OBSERVED
    }
}
