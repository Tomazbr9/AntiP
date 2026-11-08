package br.com.reboot.poc.dns

import org.junit.Assert.*
import org.junit.Test
import java.io.IOException

class DnsTcpFallbackCoordinatorTest {

    private fun query(): ByteArray =
        ByteArray(12).apply {
            this[0] = 0x12
            this[1] = 0x34
            this[2] = 0x01
        }

    private fun response(
        truncated: Boolean = false,
        size: Int = 12
    ): ByteArray =
        ByteArray(size).apply {
            this[0] = 0x12
            this[1] = 0x34
            this[2] = if (truncated) {
                0x83.toByte()
            } else {
                0x81.toByte()
            }
            this[3] = 0x80.toByte()
        }

    @Test
    fun normalUdpResponseDoesNotCallTcp() {
        var tcpCalled = false

        val coordinator = DnsTcpFallbackCoordinator(
            tcpForward = {
                tcpCalled = true
                error("Unexpected TCP call")
            }
        )

        val result = coordinator.resolve(
            query(),
            response()
        )

        assertTrue(result is DnsFallbackResult.UdpAccepted)
        assertFalse(tcpCalled)
    }

    @Test
    fun truncatedUdpTriggersTcpFallback() {
        var calls = 0

        val coordinator = DnsTcpFallbackCoordinator(
            tcpForward = {
                calls++
                response()
            }
        )

        val result = coordinator.resolve(
            query(),
            response(truncated = true)
        )

        assertTrue(result is DnsFallbackResult.TcpAccepted)
        assertEquals(1, calls)
    }

    @Test
    fun invalidUdpResponseDoesNotCallTcp() {
        var calls = 0

        val coordinator = DnsTcpFallbackCoordinator(
            tcpForward = {
                calls++
                response()
            }
        )

        val result = coordinator.resolve(
            query(),
            ByteArray(5)
        )

        assertEquals(
            DnsFallbackResult.InvalidUdpResponse,
            result
        )
        assertEquals(0, calls)
    }

    @Test
    fun tcpFailureIsReported() {
        val coordinator = DnsTcpFallbackCoordinator(
            tcpForward = {
                throw IOException("Connection failed")
            }
        )

        assertEquals(
            DnsFallbackResult.TcpFailed,
            coordinator.resolve(
                query(),
                response(truncated = true)
            )
        )
    }

    @Test
    fun oversizedTcpResponseIsRejected() {
        val coordinator = DnsTcpFallbackCoordinator(
            tcpForward = {
                response(size = 1500)
            }
        )

        assertEquals(
            DnsFallbackResult.ResponseTooLarge,
            coordinator.resolve(
                query(),
                response(truncated = true)
            )
        )
    }

    @Test
    fun mismatchedTcpResponseIsRejected() {
        val coordinator = DnsTcpFallbackCoordinator(
            tcpForward = {
                response().apply {
                    this[0] = 0x55
                }
            }
        )

        assertEquals(
            DnsFallbackResult.InvalidTcpResponse,
            coordinator.resolve(
                query(),
                response(truncated = true)
            )
        )
    }

    @Test
    fun truncatedTcpResponseIsRejected() {
        val coordinator = DnsTcpFallbackCoordinator(
            tcpForward = {
                response(truncated = true)
            }
        )

        assertEquals(
            DnsFallbackResult.InvalidTcpResponse,
            coordinator.resolve(
                query(),
                response(truncated = true)
            )
        )
    }

    @Test
    fun oversizedUdpResponseIsRejected() {
        val coordinator = DnsTcpFallbackCoordinator(
            tcpForward = {
                error("TCP must not be called")
            }
        )

        assertEquals(
            DnsFallbackResult.ResponseTooLarge,
            coordinator.resolve(
                query(),
                response(size = 1473)
            )
        )
    }
}
