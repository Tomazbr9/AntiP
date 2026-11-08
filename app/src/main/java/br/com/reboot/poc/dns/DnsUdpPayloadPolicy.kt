package br.com.reboot.poc.dns

enum class DnsUdpPayloadDecision {
    ACCEPTED,
    TRUNCATED,
    TOO_LARGE,
    INVALID_QUERY,
    INVALID_RESPONSE
}

/**
 * Lê a capacidade UDP anunciada em uma consulta DNS
 * e avalia o tamanho de uma resposta.
 *
 * Não altera respostas e não escreve no TUN.
 */
object DnsUdpPayloadPolicy {

    private const val LEGACY_LIMIT = 512
    private const val TUN_LIMIT = 1472
    private const val OPT_TYPE = 41

    fun advertisedLimit(query: ByteArray): Int? {
        if (query.size < 12) return null

        fun u16(pos: Int): Int =
            ((query[pos].toInt() and 0xFF) shl 8) or
                    (query[pos + 1].toInt() and 0xFF)

        // Somente consultas.
        if ((query[2].toInt() and 0x80) != 0) {
            return null
        }

        val questionCount = u16(4)
        val answerCount = u16(6)
        val authorityCount = u16(8)
        val additionalCount = u16(10)

        fun skipName(start: Int): Int? {
            var pos = start

            while (pos < query.size) {
                val value = query[pos].toInt() and 0xFF

                when {
                    value == 0 -> return pos + 1

                    (value and 0xC0) == 0xC0 -> {
                        if (pos + 1 >= query.size) {
                            return null
                        }

                        val pointer =
                            ((value and 0x3F) shl 8) or
                                    (query[pos + 1].toInt() and 0xFF)

                        if (pointer < 12 || pointer >= pos) {
                            return null
                        }

                        return pos + 2
                    }

                    (value and 0xC0) != 0 -> return null

                    value > 63 -> return null

                    pos + 1 + value > query.size ->
                        return null

                    else -> pos += value + 1
                }
            }

            return null
        }

        var offset = 12

        repeat(questionCount) {
            offset = skipName(offset) ?: return null

            if (query.size - offset < 4) return null

            offset += 4
        }

        var ednsLimit: Int? = null

        val recordCount =
            answerCount + authorityCount + additionalCount

        repeat(recordCount) { index ->
            val nameStart = offset

            offset = skipName(offset) ?: return null

            if (query.size - offset < 10) return null

            val type = u16(offset)
            val dnsClass = u16(offset + 2)
            val dataLength = u16(offset + 8)

            offset += 10

            if (dataLength > query.size - offset) {
                return null
            }

            val isAdditional =
                index >= answerCount + authorityCount

            if (type == OPT_TYPE) {
                // OPT deve aparecer apenas na seção Additional,
                // com nome raiz e sem duplicação.
                if (!isAdditional ||
                    ednsLimit != null ||
                    query[nameStart].toInt() != 0 ||
                    offset - nameStart != 11
                ) {
                    return null
                }

                ednsLimit = dnsClass
            }

            offset += dataLength
        }

        // Rejeita bytes extras não descritos
        // pelas contagens do cabeçalho.
        if (offset != query.size) return null

        return (ednsLimit ?: LEGACY_LIMIT)
            .coerceAtLeast(LEGACY_LIMIT)
            .coerceAtMost(TUN_LIMIT)
    }

    fun evaluate(
        query: ByteArray,
        response: ByteArray
    ): DnsUdpPayloadDecision {

        val limit = advertisedLimit(query)
            ?: return DnsUdpPayloadDecision.INVALID_QUERY

        if (response.size < 12) {
            return DnsUdpPayloadDecision.INVALID_RESPONSE
        }

        // A resposta deve ter QR=1 e o mesmo ID.
        if ((response[2].toInt() and 0x80) == 0 ||
            response[0] != query[0] ||
            response[1] != query[1]
        ) {
            return DnsUdpPayloadDecision.INVALID_RESPONSE
        }

        if (response.size > limit) {
            return DnsUdpPayloadDecision.TOO_LARGE
        }

        val truncated =
            (response[2].toInt() and 0x02) != 0

        return if (truncated) {
            DnsUdpPayloadDecision.TRUNCATED
        } else {
            DnsUdpPayloadDecision.ACCEPTED
        }
    }
}
