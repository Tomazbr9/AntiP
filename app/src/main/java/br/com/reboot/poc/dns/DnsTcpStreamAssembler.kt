package br.com.reboot.poc.dns

/**
 * Reconstrói mensagens DNS a partir de um fluxo de bytes
 * no formato DNS sobre TCP (prefixo de 2 bytes + mensagem).
 *
 * Cada instância representa um único fluxo TCP.
 * Deve ser utilizada por uma única thread.
 *
 * Não realiza remontagem de segmentos TCP por número
 * de sequência: recebe bytes já ordenados e contínuos.
 */
class DnsTcpStreamAssembler(
    private val maxMessageSize: Int = 65535
) {

    init {
        require(maxMessageSize in 12..65535) {
            "Invalid maximum DNS message size"
        }
    }

    // Máximo de uma mensagem DNS mais seu prefixo.
    private val buffer = ByteArray(maxMessageSize + 2)

    private var bufferedBytes = 0
    private var expectedFrameSize = -1
    private var failed = false

    /**
     * Recebe bytes do fluxo e devolve as mensagens
     * DNS completas encontradas.
     *
     * Pode retornar uma lista vazia quando ainda
     * faltarem bytes.
     */
    fun append(
        data: ByteArray,
        offset: Int = 0,
        length: Int = data.size - offset
    ): List<ByteArray> {

        check(!failed) {
            "Assembler is in failed state"
        }

        require(
            offset >= 0 &&
                    length >= 0 &&
                    offset <= data.size &&
                    length <= data.size - offset
        ) {
            "Invalid input range"
        }

        val messages = mutableListOf<ByteArray>()
        var position = offset
        val end = offset + length

        while (position < end) {

            // Primeiro, reunir os dois bytes do prefixo.
            if (bufferedBytes < 2) {
                val needed = 2 - bufferedBytes
                val available = end - position
                val amount = minOf(needed, available)

                System.arraycopy(
                    data,
                    position,
                    buffer,
                    bufferedBytes,
                    amount
                )

                bufferedBytes += amount
                position += amount

                if (bufferedBytes < 2) {
                    break
                }
            }

            // O prefixo representa o tamanho do DNS,
            // sem incluir os próprios dois bytes.
            if (expectedFrameSize == -1) {
                val dnsLength =
                    ((buffer[0].toInt() and 0xFF) shl 8) or
                            (buffer[1].toInt() and 0xFF)

                if (dnsLength !in 12..maxMessageSize) {
                    failed = true

                    throw IllegalArgumentException(
                        "Invalid DNS frame length: $dnsLength"
                    )
                }

                expectedFrameSize = dnsLength + 2
            }

            // Completar o corpo do frame.
            val needed = expectedFrameSize - bufferedBytes
            val available = end - position
            val amount = minOf(needed, available)

            if (amount > 0) {
                System.arraycopy(
                    data,
                    position,
                    buffer,
                    bufferedBytes,
                    amount
                )

                bufferedBytes += amount
                position += amount
            }

            if (bufferedBytes < expectedFrameSize) {
                break
            }

            // Retornar somente a mensagem DNS,
            // sem o prefixo de tamanho.
            messages.add(
                buffer.copyOfRange(2, expectedFrameSize)
            )

            // Preparar para a próxima mensagem.
            bufferedBytes = 0
            expectedFrameSize = -1
        }

        return messages
    }

    fun pendingBytes(): Int = bufferedBytes

    fun isFailed(): Boolean = failed
}
