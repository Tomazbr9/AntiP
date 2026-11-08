
package br.com.reboot.poc.dns

/**
 * Constrói uma resposta DNS SERVFAIL mínima
 * a partir de uma consulta convencional.
 *
 * Não depende do Android.
 */
object DnsServfailResponseBuilder {

    fun build(query: ByteArray): ByteArray? {
        if (query.size < 17 || query.size > 65535) {
            return null
        }

        // Exige uma consulta estruturalmente
        // válida segundo a política atual.
        val limit = DnsUdpPayloadPolicy.advertisedLimit(query)
            ?: return null

        fun u8(index: Int) = query[index].toInt() and 0xFF

        fun u16(index: Int) =
            (u8(index) shl 8) or u8(index + 1)

        val flags = u16(2)

        // QR deve ser zero e TC também.
        if ((flags and 0x8200) != 0) return null

        // Suportamos uma única pergunta.
        if (u16(4) != 1) return null

        var offset = 12
        var nameLength = 1

        // Nesta versão aceitamos perguntas com
        // nomes não comprimidos.
        while (true) {
            if (offset >= query.size) return null

            val labelLength = u8(offset)

            // Rótulo comprimido ou reservado.
            if (labelLength > 63) return null

            offset++

            if (labelLength == 0) break

            if (labelLength > query.size - offset) {
                return null
            }

            nameLength += labelLength + 1
            if (nameLength > 255) return null

            offset += labelLength
        }

        // QTYPE e QCLASS.
        if (query.size - offset < 4) return null

        val questionEnd = offset + 4

        if (questionEnd > limit) return null

        val response = query.copyOfRange(0, questionEnd)

        // QR=1, preservar OPCODE e RD,
        // RCODE=2 (SERVFAIL).
        val responseFlags =
            0x8000 or
                    (flags and 0x7800) or
                    (flags and 0x0100) or
                    0x0002

        response[2] = (responseFlags ushr 8).toByte()
        response[3] = responseFlags.toByte()

        // Uma pergunta, nenhuma resposta,
        // nenhum registro Authority/Additional.
        response[4] = 0
        response[5] = 1

        for (index in 6..11) {
            response[index] = 0
        }

        return response
    }
}
