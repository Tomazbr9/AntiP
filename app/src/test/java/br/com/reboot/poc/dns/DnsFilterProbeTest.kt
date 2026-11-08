package br.com.reboot.poc

import br.com.reboot.poc.dns.DnsFilterProbe
import org.junit.Assert.*
import org.junit.Test
import java.io.ByteArrayOutputStream

class DnsFilterProbeTest {

    private fun u16(value: Int) = byteArrayOf(
        (value ushr 8).toByte(),
        value.toByte()
    )

    private fun question(
        domain: String,
        type: Int = 1
    ): ByteArray {
        val output = ByteArrayOutputStream()

        domain.split(".").forEach { label ->
            val bytes = label.toByteArray(Charsets.US_ASCII)
            output.write(bytes.size)
            output.write(bytes)
        }

        output.write(0)
        output.write(u16(type))
        output.write(u16(1))

        return output.toByteArray()
    }

    private fun query(
        domain: String = "nudity.testcategory.com",
        id: Int = 1234,
        type: Int = 1
    ): ByteArray {
        val output = ByteArrayOutputStream()

        output.write(u16(id))
        output.write(byteArrayOf(0x01, 0x00))
        output.write(u16(1))
        output.write(u16(0))
        output.write(u16(0))
        output.write(u16(0))
        output.write(question(domain, type))

        return output.toByteArray()
    }

    private fun response(
        id: Int = 1234,
        rcode: Int = 0,
        ipv4: ByteArray? = byteArrayOf(0, 0, 0, 0)
    ): ByteArray {
        val output = ByteArrayOutputStream()

        output.write(u16(id))
        output.write(byteArrayOf(
            0x81.toByte(),
            (0x80 or rcode).toByte()
        ))

        output.write(u16(1))
        output.write(u16(if (ipv4 == null) 0 else 1))
        output.write(u16(0))
        output.write(u16(0))

        output.write(question("nudity.testcategory.com"))

        if (ipv4 != null) {
            // Nome comprimido apontando para a pergunta.
            output.write(
                byteArrayOf(0xC0.toByte(), 0x0C)
            )

            output.write(u16(1))
            output.write(u16(1))
            output.write(byteArrayOf(0, 0, 0, 60))
            output.write(u16(4))
            output.write(ipv4)
        }

        return output.toByteArray()
    }

    @Test
    fun zeroIpv4IsObservedAsBlockResponse() {
        assertEquals(
            "BLOCK_RESPONSE_OBSERVED",
            DnsFilterProbe.inspect(
                query(),
                response()
            )
        )
    }

    @Test
    fun normalIpv4IsNotClassifiedAsBlocked() {
        assertEquals(
            "NON_ZERO_IPV4_RESPONSE",
            DnsFilterProbe.inspect(
                query(),
                response(
                    ipv4 = byteArrayOf(1, 2, 3, 4)
                )
            )
        )
    }

    @Test
    fun nxdomainIsReportedAsDnsError() {
        assertEquals(
            "DNS_ERROR_3",
            DnsFilterProbe.inspect(
                query(),
                response(rcode = 3, ipv4 = null)
            )
        )
    }

    @Test
    fun invalidResponseIsRejected() {
        assertEquals(
            "INVALID_RESPONSE",
            DnsFilterProbe.inspect(
                query(),
                byteArrayOf(1, 2, 3)
            )
        )
    }

    @Test
    fun mismatchedTransactionIsRejected() {
        assertEquals(
            "MISMATCHED_RESPONSE",
            DnsFilterProbe.inspect(
                query(id = 1234),
                response(id = 4321)
            )
        )
    }

    @Test
    fun unrelatedDomainIsIgnored() {
        assertNull(
            DnsFilterProbe.inspect(
                query(domain = "example.org"),
                response()
            )
        )
    }

    @Test
    fun aaaaQueryIsIgnored() {
        assertNull(
            DnsFilterProbe.inspect(
                query(type = 28),
                response()
            )
        )
    }

    @Test
    fun noIpv4AnswerIsNotConsideredBlocked() {
        assertEquals(
            "NO_IPV4_ANSWER",
            DnsFilterProbe.inspect(
                query(),
                response(ipv4 = null)
            )
        )
    }
}
