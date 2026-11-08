package br.com.reboot.poc.dns

/**
 * Codifica e decodifica uma mensagem DNS
 * com o prefixo de tamanho do DNS sobre TCP.
 *
 * Não implementa conexões, sockets ou pacotes IP.
 */
object DnsTcpMessageCodec {

    private const val MIN_DNS_MESSAGE_SIZE = 12
    private const val MAX_DNS_MESSAGE_SIZE = 65535

    fun encode(message: ByteArray): ByteArray {
        require(
            message.size in
                    MIN_DNS_MESSAGE_SIZE..MAX_DNS_MESSAGE_SIZE
        ) {
            "Invalid DNS message size"
        }

        val length = message.size

        return ByteArray(length + 2).also { result ->
            result[0] = (length ushr 8).toByte()
            result[1] = length.toByte()

            System.arraycopy(
                message,
                0,
                result,
                2,
                length
            )
        }
    }

    /**
     * Decodifica exatamente um frame completo.
     *
     * Retorna null quando o frame está incompleto
     * ou possui estrutura inválida.
     */
    fun decode(frame: ByteArray): ByteArray? {
        if (frame.size < 2) return null

        val length =
            ((frame[0].toInt() and 0xFF) shl 8) or
                    (frame[1].toInt() and 0xFF)

        if (length < MIN_DNS_MESSAGE_SIZE) {
            return null
        }

        if (frame.size != length + 2) {
            return null
        }

        return frame.copyOfRange(2, frame.size)
    }
}
