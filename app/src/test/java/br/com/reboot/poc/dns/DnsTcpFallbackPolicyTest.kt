package br.com.reboot.poc.dns

import org.junit.Assert.assertEquals
import org.junit.Test

class DnsTcpFallbackPolicyTest {

    private fun query() = ByteArray(12).apply {
        this[0] = 0x12
        this[1] = 0x34
        this[2] = 0x01
    }

    private fun response(truncated: Boolean) =
        query().apply {
            this[2] = if (truncated) {
                0x83.toByte() // QR=1, TC=1, RD=1
            } else {
                0x81.toByte() // QR=1, TC=0, RD=1
            }
            this[3] = 0x80.toByte()
        }

    @Test
    fun normalResponseDoesNotRequireTcp() {
        assertEquals(
            DnsTcpFallbackDecision.NOT_REQUIRED,
            DnsTcpFallbackPolicy.evaluate(
                query(),
                response(false)
            )
        )
    }

    @Test
    fun truncatedResponseRequiresTcpRetry() {
        assertEquals(
            DnsTcpFallbackDecision.TCP_RETRY_REQUIRED,
            DnsTcpFallbackPolicy.evaluate(
                query(),
                response(true)
            )
        )
    }

    @Test
    fun mismatchedTransactionIsInvalid() {
        val invalid = response(true).apply {
            this[0] = 0x55
        }

        assertEquals(
            DnsTcpFallbackDecision.INVALID_RESPONSE,
            DnsTcpFallbackPolicy.evaluate(
                query(),
                invalid
            )
        )
    }

    @Test
    fun shortResponseIsInvalid() {
        assertEquals(
            DnsTcpFallbackDecision.INVALID_RESPONSE,
            DnsTcpFallbackPolicy.evaluate(
                query(),
                byteArrayOf(1, 2, 3)
            )
        )
    }

    @Test
    fun queryCannotBeTreatedAsResponse() {
        assertEquals(
            DnsTcpFallbackDecision.INVALID_RESPONSE,
            DnsTcpFallbackPolicy.evaluate(
                query(),
                query()
            )
        )
    }
}
