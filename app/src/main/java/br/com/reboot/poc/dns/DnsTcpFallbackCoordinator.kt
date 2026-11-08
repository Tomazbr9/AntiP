
package br.com.reboot.poc.dns

sealed interface DnsFallbackResult {
    data class UdpAccepted(
        val response: ByteArray
    ) : DnsFallbackResult

    data class TcpAccepted(
        val response: ByteArray
    ) : DnsFallbackResult

    data object InvalidUdpResponse : DnsFallbackResult

    data object InvalidTcpResponse : DnsFallbackResult

    data object ResponseTooLarge : DnsFallbackResult

    data object TcpFailed : DnsFallbackResult
}

/**
 * Coordena um fallback DNS UDP -> TCP.
 *
 * A chamada TCP é injetada para permitir
 * testes sem Android ou acesso à rede.
 *
 * Não escreve no TUN e não inicia sockets
 * por conta própria.
 */
class DnsTcpFallbackCoordinator(
    private val tcpForward: (ByteArray) -> ByteArray,
    private val maxDnsPayloadBytes: Int = 1472
) {
    init {
        require(maxDnsPayloadBytes in 12..1472)
    }

    fun resolve(
        query: ByteArray,
        udpResponse: ByteArray
    ): DnsFallbackResult {
        if (!validEnvelope(query, udpResponse)) {
            return DnsFallbackResult.InvalidUdpResponse
        }

        val truncated =
            (udpResponse[2].toInt() and 0x02) != 0

        if (!truncated) {
            return if (udpResponse.size <= maxDnsPayloadBytes) {
                DnsFallbackResult.UdpAccepted(
                    udpResponse.copyOf()
                )
            } else {
                DnsFallbackResult.ResponseTooLarge
            }
        }

        val tcpResponse = try {
            tcpForward(query.copyOf())
        } catch (ex: Exception) {
            return DnsFallbackResult.TcpFailed
        }

        if (!validEnvelope(query, tcpResponse)) {
            return DnsFallbackResult.InvalidTcpResponse
        }

        // Não aceitar resposta TCP ainda truncada.
        if ((tcpResponse[2].toInt() and 0x02) != 0) {
            return DnsFallbackResult.InvalidTcpResponse
        }

        if (tcpResponse.size > maxDnsPayloadBytes) {
            return DnsFallbackResult.ResponseTooLarge
        }

        return DnsFallbackResult.TcpAccepted(
            tcpResponse.copyOf()
        )
    }

    private fun validEnvelope(
        query: ByteArray,
        response: ByteArray
    ): Boolean {
        if (query.size < 12 || response.size < 12) {
            return false
        }

        if ((query[2].toInt() and 0x80) != 0) {
            return false
        }

        if ((response[2].toInt() and 0x80) == 0) {
            return false
        }

        return query[0] == response[0] &&
                query[1] == response[1]
    }
}
