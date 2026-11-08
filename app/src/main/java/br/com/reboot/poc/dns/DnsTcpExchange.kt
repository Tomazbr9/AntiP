package br.com.reboot.poc.dns

import java.io.InputStream
import java.io.OutputStream
import java.io.EOFException
import java.io.IOException

/**
 * Executa uma única troca DNS sobre um fluxo TCP
 * previamente estabelecido.
 *
 * Não cria sockets nem depende do Android.
 * O chamador é responsável pelo timeout e fechamento.
 */
class DnsTcpExchange {

    fun execute(
        query: ByteArray,
        input: InputStream,
        output: OutputStream
    ): ByteArray {

        require(query.size in 12..65535) {
            "Invalid DNS query length"
        }

        // Uma consulta não pode ter QR = 1.
        require((query[2].toInt() and 0x80) == 0) {
            "Expected DNS query"
        }

        val encoded = DnsTcpMessageCodec.encode(query)

        output.write(encoded)
        output.flush()

        val prefix = ByteArray(2)
        readExactly(input, prefix)

        val responseLength =
            ((prefix[0].toInt() and 0xFF) shl 8) or
                    (prefix[1].toInt() and 0xFF)

        if (responseLength !in 12..65535) {
            throw IOException("Invalid DNS response length")
        }

        val response = ByteArray(responseLength)
        readExactly(input, response)

        // Mesmo identificador da consulta.
        if (
            query[0] != response[0] ||
            query[1] != response[1]
        ) {
            throw IOException("DNS transaction ID mismatch")
        }

        // A resposta precisa ter QR = 1.
        if ((response[2].toInt() and 0x80) == 0) {
            throw IOException("Expected DNS response")
        }

        return response
    }

    private fun readExactly(
        input: InputStream,
        target: ByteArray
    ) {
        var offset = 0

        while (offset < target.size) {
            val count = input.read(
                target,
                offset,
                target.size - offset
            )

            if (count < 0) {
                throw EOFException(
                    "Unexpected end of DNS TCP stream"
                )
            }

            if (count == 0) {
                val single = input.read()

                if (single < 0) {
                    throw EOFException(
                        "Unexpected end of DNS TCP stream"
                    )
                }

                target[offset++] = single.toByte()
                continue
            }

            offset += count
        }
    }
}
