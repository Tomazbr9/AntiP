package br.com.reboot.poc.dns

/**
 * Valida a estrutura externa de consultas e
 * respostas DNS completas.
 *
 * Não valida semanticamente todos os formatos
 * de RDATA nem autentica a origem do servidor.
 */
object DnsMessageStructureValidator {

    private data class Name(
        val labels: List<String>,
        val nextOffset: Int
    )

    private data class Question(
        val name: List<String>,
        val type: Int,
        val dnsClass: Int
    )

    private data class ParsedMessage(
        val id: Int,
        val flags: Int,
        val question: Question
    )

    fun validate(
        query: ByteArray,
        response: ByteArray
    ): Boolean {
        val request = parse(query, expectResponse = false)
            ?: return false

        val reply = parse(response, expectResponse = true)
            ?: return false

        val requestOpcode = request.flags and 0x7800
        val responseOpcode = reply.flags and 0x7800

        return request.id == reply.id &&
                requestOpcode == responseOpcode &&
                request.question == reply.question
    }

    private fun parse(
        data: ByteArray,
        expectResponse: Boolean
    ): ParsedMessage? {
        if (data.size < 12 || data.size > 65535) {
            return null
        }

        fun u8(i: Int) = data[i].toInt() and 0xFF

        fun u16(i: Int) =
            (u8(i) shl 8) or u8(i + 1)

        val flags = u16(2)
        val isResponse = (flags and 0x8000) != 0

        if (isResponse != expectResponse) return null

        // Reservado: bit Z deve ser zero.
        if ((flags and 0x0040) != 0) return null

        // Neste incremento exigimos mensagens completas.
        if ((flags and 0x0200) != 0) return null

        val qdCount = u16(4)
        val anCount = u16(6)
        val nsCount = u16(8)
        val arCount = u16(10)

        // Escopo: consultas convencionais de 1 pergunta.
        if (qdCount != 1) return null

        if (!expectResponse &&
            (anCount != 0 || nsCount != 0)
        ) return null

        var offset = 12

        val questionName = readName(data, offset)
            ?: return null

        offset = questionName.nextOffset

        if (data.size - offset < 4) return null

        val question = Question(
            name = questionName.labels,
            type = u16(offset),
            dnsClass = u16(offset + 2)
        )

        offset += 4
        var optSeen = false

        val totalRecords = anCount + nsCount + arCount

        repeat(totalRecords) { index ->
            val name = readName(data, offset)
                ?: return null

            offset = name.nextOffset

            if (data.size - offset < 10) return null

            val type = u16(offset)
            val rdLength = u16(offset + 8)

            offset += 10

            if (rdLength > data.size - offset) {
                return null
            }

            val inAdditional = index >= anCount + nsCount

            if (type == 41) {
                if (!inAdditional ||
                    optSeen ||
                    name.labels.isNotEmpty()
                ) return null

                optSeen = true
            }

            offset += rdLength
        }

        if (offset != data.size) return null

        return ParsedMessage(
            id = u16(0),
            flags = flags,
            question = question
        )
    }

    /**
     * Retorna o nome normalizado e o offset após
     * sua representação no fluxo original.
     *
     * Ponteiros precisam apontar para trás.
     */
    private fun readName(
        data: ByteArray,
        start: Int
    ): Name? {
        var cursor = start
        var nextOffset = -1
        var steps = 0
        var wireLength = 1

        val labels = mutableListOf<String>()

        while (true) {
            if (cursor >= data.size ||
                cursor < 12 ||
                ++steps > 128
            ) return null

            val value = data[cursor].toInt() and 0xFF

            if (value == 0) {
                if (nextOffset == -1) {
                    nextOffset = cursor + 1
                }
                return Name(labels, nextOffset)
            }

            if ((value and 0xC0) == 0xC0) {
                if (cursor + 1 >= data.size) return null

                val target =
                    ((value and 0x3F) shl 8) or
                            (data[cursor + 1].toInt() and 0xFF)

                if (target < 12 || target >= cursor) {
                    return null
                }

                if (nextOffset == -1) {
                    nextOffset = cursor + 2
                }

                cursor = target
                continue
            }

            if ((value and 0xC0) != 0 ||
                value > 63
            ) return null

            val end = cursor + 1 + value

            if (end > data.size) return null

            wireLength += 1 + value
            if (wireLength > 255) return null

            // Representação hexadecimal evita confundir
            // bytes arbitrários dos rótulos DNS.
            val label = (cursor + 1 until end)
                .joinToString("") { index ->
                    val byte = data[index].toInt() and 0xFF
                    val normalized =
                        if (byte in 65..90) byte + 32
                        else byte
                    normalized.toString(16).padStart(2, '0')
                }

            labels.add(label)
            cursor = end
        }
    }
}
