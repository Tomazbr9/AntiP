package br.com.reboot.poc.dns

sealed interface DnsPacketPlan {

    data class Ready(
        val packet: ByteArray,
        val usedTcpFallback: Boolean
    ) : DnsPacketPlan

    data object InvalidQuery : DnsPacketPlan
    data object Dropped : DnsPacketPlan
    data object PacketBuildFailed : DnsPacketPlan
}

/**
 * Prepara o pacote IPv4/UDP de resposta DNS.
 *
 * Não acessa a rede diretamente.
 * Não depende do Android.
 * Não escreve no TUN.
 *
 * O chamador fornece a resposta UDP upstream.
 * A função tcpForward é utilizada somente
 * quando o seletor solicitar fallback.
 */
class DnsRelayPacketPlanner(
    tcpForward: (ByteArray) -> ByteArray
) {

    private val selector =
        DnsResponseSelectionCoordinator(tcpForward)

    fun plan(
        requestPacket: ByteArray,
        requestLength: Int,
        udpResponse: ByteArray
    ): DnsPacketPlan {

        // Extrair a consulta do pacote real.
        val query = DnsQueryExtractor.extract(
            requestPacket,
            requestLength
        ) ?: return DnsPacketPlan.InvalidQuery

        // Selecionar resposta UDP ou TCP.
        val result = selector.select(
            query = query.payload,
            udpResponse = udpResponse
        )

        // Traduzir falhas em SERVFAIL ou descarte.
        val delivery = DnsFallbackFailurePolicy.decide(
            query = query.payload,
            result = result
        )

        if (delivery is DnsDeliveryDecision.Drop) {
            return DnsPacketPlan.Dropped
        }

        val response = (
                delivery as DnsDeliveryDecision.Send
                ).response

        // Defesa adicional: a política de entrega
        // jamais deve encaminhar uma resposta
        // completa inválida ou maior que o limite.
        if (
            DnsUdpPayloadPolicy.evaluate(
                query.payload,
                response
            ) != DnsUdpPayloadDecision.ACCEPTED
        ) {
            return DnsPacketPlan.Dropped
        }

        if (!DnsMessageStructureValidator.validate(
                query.payload,
                response
            )
        ) {
            return DnsPacketPlan.Dropped
        }

        val packet = DnsResponsePacketBuilder.build(
            request = requestPacket,
            requestLength = requestLength,
            dnsResponse = response
        ) ?: return DnsPacketPlan.PacketBuildFailed

        return DnsPacketPlan.Ready(
            packet = packet,
            usedTcpFallback =
                result is DnsFallbackResult.TcpAccepted
        )
    }
}
