package br.com.reboot.poc.dns

import org.junit.Assert.*
import org.junit.Test
import java.io.ByteArrayOutputStream

class DnsMessageStructureValidatorTest {

    private fun u16(value: Int) = byteArrayOf(
        (value ushr 8).toByte(),
        value.toByte()
    )

    private fun domain(
        value: String = "example.org"
    ): ByteArray {
        val out = ByteArrayOutputStream()

        value.split(".").forEach { part ->
            val bytes = part.toByteArray(Charsets.US_ASCII)
            out.write(bytes.size)
            out.write(bytes)
        }

        out.write(0)
        return out.toByteArray()
    }

    private fun message(
        isResponse: Boolean,
        domainName: String = "example.org",
        withAnswer: Boolean = false
    ): ByteArray {
        val out = ByteArrayOutputStream()

        out.write(u16(0x1234))
        out.write(
            u16(if (isResponse) 0x8180 else 0x0100)
        )

        out.write(u16(1)) // QDCOUNT
        out.write(
            u16(if (withAnswer) 1 else 0)
        )
        out.write(u16(0)) // NSCOUNT
        out.write(u16(0)) // ARCOUNT

        out.write(domain(domainName))
        out.write(u16(1)) // A
        out.write(u16(1)) // IN

        if (withAnswer) {
            // Ponteiro para o nome na pergunta.
            out.write(byteArrayOf(
                0xC0.toByte(),
                0x0C
            ))

            out.write(u16(1)) // A
            out.write(u16(1)) // IN
            out.write(byteArrayOf(0, 0, 0, 60)) // TTL
            out.write(u16(4))
            out.write(byteArrayOf(1, 2, 3, 4))
        }

        return out.toByteArray()
    }

    @Test
    fun validResponseWithoutAnswers() {
        assertTrue(
            DnsMessageStructureValidator.validate(
                message(false),
                message(true)
            )
        )
    }

    @Test
    fun validCompressedAnswer() {
        assertTrue(
            DnsMessageStructureValidator.validate(
                message(false),
                message(true, withAnswer = true)
            )
        )
    }

    @Test
    fun mismatchedQuestionIsRejected() {
        assertFalse(
            DnsMessageStructureValidator.validate(
                message(false),
                message(true, domainName = "other.org")
            )
        )
    }

    @Test
    fun differentLetterCaseIsAccepted() {
        assertTrue(
            DnsMessageStructureValidator.validate(
                message(false, domainName = "Example.Org"),
                message(true, domainName = "example.org")
            )
        )
    }

    @Test
    fun malformedAnswerLengthIsRejected() {
        val response = message(
            true,
            withAnswer = true
        ).copyOf()

        // O RDLENGTH fica seis bytes antes
        // do fim neste registro A.
        response[response.size - 6] = 0
        response[response.size - 5] = 10

        assertFalse(
            DnsMessageStructureValidator.validate(
                message(false),
                response
            )
        )
    }

    @Test
    fun selfReferencingPointerIsRejected() {
        val response = message(
            true,
            withAnswer = true
        ).copyOf()

        val pointerPosition = response.size - 16

        // Ponteiro para o próprio início do nome.
        response[pointerPosition] = 0xC0.toByte()
        response[pointerPosition + 1] =
            pointerPosition.toByte()

        assertFalse(
            DnsMessageStructureValidator.validate(
                message(false),
                response
            )
        )
    }

    @Test
    fun trailingBytesAreRejected() {
        val response =
            message(true) + byteArrayOf(1, 2, 3)

        assertFalse(
            DnsMessageStructureValidator.validate(
                message(false),
                response
            )
        )
    }

    @Test
    fun mismatchedTransactionIdIsRejected() {
        val response = message(true).copyOf()
        response[0] = 0x55

        assertFalse(
            DnsMessageStructureValidator.validate(
                message(false),
                response
            )
        )
    }

    @Test
    fun truncatedResponseIsNotFullyValidated() {
        val response = message(true).copyOf()

        // Ativar TC.
        response[2] =
            (response[2].toInt() or 0x02).toByte()

        assertFalse(
            DnsMessageStructureValidator.validate(
                message(false),
                response
            )
        )
    }
}
