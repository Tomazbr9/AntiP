package br.com.reboot.poc.dns

sealed interface DnsDeliveryDecision {

    data class Send(
        val response: ByteArray
    ) : DnsDeliveryDecision

    data object Drop : DnsDeliveryDecision
}

/**
 * Traduz resultados de resolução em decisões
 * para uma futura camada de entrega UDP.
 *
 * Não envia dados e não escreve no TUN.
 */
object DnsFallbackFailurePolicy {

    fun decide(
        query: ByteArray,
        result: DnsFallbackResult
    ): DnsDeliveryDecision {

        return when (result) {

            is DnsFallbackResult.UdpAccepted ->
                DnsDeliveryDecision.Send(
                    result.response.copyOf()
                )

            is DnsFallbackResult.TcpAccepted ->
                DnsDeliveryDecision.Send(
                    result.response.copyOf()
                )

            DnsFallbackResult.InvalidUdpResponse ->
                DnsDeliveryDecision.Drop

            DnsFallbackResult.TcpFailed,
            DnsFallbackResult.InvalidTcpResponse,
            DnsFallbackResult.ResponseTooLarge -> {

                val servfail =
                    DnsServfailResponseBuilder.build(query)

                if (servfail != null) {
                    DnsDeliveryDecision.Send(servfail)
                } else {
                    DnsDeliveryDecision.Drop
                }
            }
        }
    }
}
