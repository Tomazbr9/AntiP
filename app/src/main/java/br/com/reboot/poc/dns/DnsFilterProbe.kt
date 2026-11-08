package br.com.reboot.poc.dns

import java.util.Locale

object DnsFilterProbe {

    private const val TEST_DOMAIN =
        "nudity.testcategory.com"

    /**
     * Identifica apenas uma consulta DNS A/IN
     * para o domínio oficial de diagnóstico.
     *
     * Não registra nomes de domínios.
     */
    fun isTestQuery(payload: ByteArray): Boolean {
        if (payload.size < 17) return false

        fun u8(index: Int): Int =
            payload[index].toInt() and 0xFF

        fun u16(index: Int): Int =
            (u8(index) shl 8) or u8(index + 1)

        // Apenas consultas com uma pergunta.
        if ((u8(2) and 0x80) != 0) return false
        if (u16(4) != 1) return false

        var offset = 12
        val labels = mutableListOf<String>()

        while (offset < payload.size) {
            val length = u8(offset)
            offset++

            if (length == 0) break

            // Não aceita nomes comprimidos ou inválidos.
            if (length > 63 ||
                offset + length > payload.size
            ) return false

            val label = String(
                payload,
                offset,
                length,
                Charsets.US_ASCII
            )

            labels.add(label)
            offset += length
        }

        if (offset + 4 > payload.size) return false

        val domain = labels.joinToString(".")
            .lowercase(Locale.ROOT)

        val qtype = u16(offset)
        val qclass = u16(offset + 2)

        return domain == TEST_DOMAIN &&
                qtype == 1 &&
                qclass == 1
    }


    fun inspect(
        queryPayload: ByteArray,
        responsePayload: ByteArray
    ): String? {
        // O diagnóstico só se aplica ao
        // domínio específico de teste.
        if (!isTestQuery(queryPayload)) return null

        if (queryPayload.size < 12 ||
            responsePayload.size < 12
        ) {
            return "INVALID_RESPONSE"
        }

        fun transactionId(payload: ByteArray): Int {
            return (
                    (payload[0].toInt() and 0xFF) shl 8
                    ) or (payload[1].toInt() and 0xFF)
        }

        // Não aceitar uma resposta DNS que pertença
        // a outra transação.
        if (
            transactionId(queryPayload) !=
            transactionId(responsePayload)
        ) {
            return "MISMATCHED_RESPONSE"
        }

        val inspection =
            DnsResponseInspector.inspect(responsePayload)
                ?: return "INVALID_RESPONSE"

        return when {
            inspection.responseCode != 0 ->
                "DNS_ERROR_${inspection.responseCode}"

            inspection.hasZeroIpv4 ->
                "BLOCK_RESPONSE_OBSERVED"

            inspection.ipv4Answers > 0 ->
                "NON_ZERO_IPV4_RESPONSE"

            else ->
                "NO_IPV4_ANSWER"
        }
    }

}
