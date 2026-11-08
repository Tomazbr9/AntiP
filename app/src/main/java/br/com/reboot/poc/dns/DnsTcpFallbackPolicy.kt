package br.com.reboot.poc.dns

enum class DnsTcpFallbackDecision {
    NOT_REQUIRED,
    TCP_RETRY_REQUIRED,
    INVALID_RESPONSE
}

/**
 * Identifica respostas DNS UDP truncadas.
 *
 * Esta classe não executa conexões TCP,
 * não altera pacotes e não modifica a VPN.
 */
object DnsTcpFallbackPolicy {

    fun evaluate(
        query: ByteArray,
        response: ByteArray
    ): DnsTcpFallbackDecision {

        if (query.size < 12 || response.size < 12) {
            return DnsTcpFallbackDecision.INVALID_RESPONSE
        }

        // A consulta deve ter QR=0.
        if ((query[2].toInt() and 0x80) != 0) {
            return DnsTcpFallbackDecision.INVALID_RESPONSE
        }

        // A resposta deve ter QR=1.
        if ((response[2].toInt() and 0x80) == 0) {
            return DnsTcpFallbackDecision.INVALID_RESPONSE
        }

        // Mesmo transaction ID da consulta.
        if (
            query[0] != response[0] ||
            query[1] != response[1]
        ) {
            return DnsTcpFallbackDecision.INVALID_RESPONSE
        }

        // TC: bit 1 do terceiro byte (0x02).
        val truncated =
            (response[2].toInt() and 0x02) != 0

        return if (truncated) {
            DnsTcpFallbackDecision.TCP_RETRY_REQUIRED
        } else {
            DnsTcpFallbackDecision.NOT_REQUIRED
        }
    }
}
