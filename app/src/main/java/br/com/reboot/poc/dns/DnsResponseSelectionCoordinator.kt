package br.com.reboot.poc.dns

/**
 * Seleciona a resposta DNS utilizável.
 *
 * Respostas completas precisam passar pela
 * validação estrutural antes da aceitação.
 *
 * Não depende do Android e não escreve no TUN.
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

        // 1. Verificar limites e cabeçalho UDP.
        val udpDecision = DnsUdpPayloadPolicy.evaluate(
            query = query,
            response = udpResponse
        )

        when (udpDecision) {
            DnsUdpPayloadDecision.INVALID_QUERY,
            DnsUdpPayloadDecision.INVALID_RESPONSE ->
                return DnsFallbackResult.InvalidUdpResponse

            DnsUdpPayloadDecision.TOO_LARGE ->
                return DnsFallbackResult.ResponseTooLarge

            DnsUdpPayloadDecision.ACCEPTED,
            DnsUdpPayloadDecision.TRUNCATED -> Unit
        }

        // 2. Resposta completa: validar antes
        // de aceitar. Não consultar TCP.
        if (udpDecision == DnsUdpPayloadDecision.ACCEPTED) {
            if (!DnsMessageStructureValidator.validate(
                    query, udpResponse
                )
            ) {
                return DnsFallbackResult.InvalidUdpResponse
            }

            return DnsFallbackResult.UdpAccepted(
                udpResponse.copyOf()
            )
        }

        // 3. TC=1: verificar cabeçalho básico.
        // Não usar o parser completo aqui.
        if (!validTruncatedHeader(query, udpResponse)) {
            return DnsFallbackResult.InvalidUdpResponse
        }

        // 4. Executar uma tentativa TCP.
        val result = fallback.resolve(
            query = query,
            udpResponse = udpResponse
        )

        // 5. Validar a resposta TCP completa.
        return when (result) {
            is DnsFallbackResult.TcpAccepted -> {
                val tcpResponse = result.response

                when (
                    DnsUdpPayloadPolicy.evaluate(
                        query,
                        tcpResponse
                    )
                ) {
                    DnsUdpPayloadDecision.TOO_LARGE ->
                        DnsFallbackResult.ResponseTooLarge

                    DnsUdpPayloadDecision.ACCEPTED -> {
                        if (DnsMessageStructureValidator.validate(
                                query,
                                tcpResponse
                            )
                        ) {
                            result
                        } else {
                            DnsFallbackResult.InvalidTcpResponse
                        }
                    }

                    else ->
                        DnsFallbackResult.InvalidTcpResponse
                }
            }

            else -> result
        }
    }

    /**
     * Respostas truncadas podem não conter
     * todas as perguntas e registros.
     * Conferimos apenas o cabeçalho disponível.
     */
    private fun validTruncatedHeader(
        query: ByteArray,
        response: ByteArray
    ): Boolean {
        if (query.size < 12 || response.size < 12) {
            return false
        }

        fun u16(bytes: ByteArray, pos: Int): Int =
            ((bytes[pos].toInt() and 0xFF) shl 8) or
                    (bytes[pos + 1].toInt() and 0xFF)

        val queryFlags = u16(query, 2)
        val responseFlags = u16(response, 2)

        val sameId =
            query[0] == response[0] &&
                    query[1] == response[1]

        val sameOpcode =
            (queryFlags and 0x7800) ==
                    (responseFlags and 0x7800)

        val queryQrIsZero =
            (queryFlags and 0x8000) == 0

        val responseQrIsOne =
            (responseFlags and 0x8000) != 0

        val truncated =
            (responseFlags and 0x0200) != 0

        val reservedBitIsZero =
            (responseFlags and 0x0040) == 0

        return sameId &&
                sameOpcode &&
                queryQrIsZero &&
                responseQrIsOne &&
                truncated &&
                reservedBitIsZero
    }
}
