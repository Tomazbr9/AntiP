package br.com.reboot.poc.dns

/**
 * Combina validação de tamanho UDP e fallback TCP.
 *
 * Não depende do Android.
 * Não cria sockets e não escreve no TUN.
 */
class DnsResponseSelectionCoordinator(
    tcpForward: (ByteArray) -> ByteArray
) {

    private val fallback = DnsTcpFallbackCoordinator(
        tcpForward = tcpForward
    )

    fun select(
        query: ByteArray,
        udpResponse: ByteArray
    ): DnsFallbackResult {

        // 1. Validar a resposta UDP e o limite
        // anunciado pelo cliente.
        val udpDecision = DnsUdpPayloadPolicy.evaluate(
            query = query,
            response = udpResponse
        )

        when (udpDecision) {
            DnsUdpPayloadDecision.INVALID_QUERY,
            DnsUdpPayloadDecision.INVALID_RESPONSE -> {
                return DnsFallbackResult.InvalidUdpResponse
            }

            DnsUdpPayloadDecision.TOO_LARGE -> {
                return DnsFallbackResult.ResponseTooLarge
            }

            DnsUdpPayloadDecision.ACCEPTED,
            DnsUdpPayloadDecision.TRUNCATED -> Unit
        }

        // 2. Usar o coordenador existente.
        // Ele só chama TCP se a resposta UDP
        // tiver o bit TC ativado.
        val result = fallback.resolve(
            query = query,
            udpResponse = udpResponse
        )

        // 3. Validar novamente o tamanho quando
        // o resultado vier do TCP.
        return when (result) {
            is DnsFallbackResult.TcpAccepted -> {
                when (
                    DnsUdpPayloadPolicy.evaluate(
                        query = query,
                        response = result.response
                    )
                ) {
                    DnsUdpPayloadDecision.ACCEPTED -> result

                    DnsUdpPayloadDecision.TOO_LARGE ->
                        DnsFallbackResult.ResponseTooLarge

                    DnsUdpPayloadDecision.TRUNCATED,
                    DnsUdpPayloadDecision.INVALID_QUERY,
                    DnsUdpPayloadDecision.INVALID_RESPONSE ->
                        DnsFallbackResult.InvalidTcpResponse
                }
            }

            else -> result
        }
    }
}
