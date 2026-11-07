package br.com.reboot.poc

import br.com.reboot.poc.dns.*
import org.junit.Assert.assertEquals
import org.junit.Test

class DnsHealthEvaluatorTest {

    private val evaluator = DnsHealthEvaluator()

    private fun snapshot(
        received: Long = 0,
        written: Long = 0,
        failed: Long = 0,
        rejected: Long = 0,
        consecutiveFailures: Long = 0,
        lastActivityMillis: Long = -1,
        lastSuccessMillis: Long = -1
    ) = DnsHealthSnapshot(
        received = received,
        written = written,
        failed = failed,
        rejected = rejected,
        consecutiveFailures = consecutiveFailures,
        lastActivityMillis = lastActivityMillis,
        lastSuccessMillis = lastSuccessMillis
    )

    @Test
    fun noTrafficReturnsIdle() {
        assertEquals(
            DnsHealthStatus.IDLE,
            evaluator.evaluate(snapshot(), 100_000)
        )
    }

    @Test
    fun recentSuccessfulWriteReturnsHealthy() {
        assertEquals(
            DnsHealthStatus.HEALTHY,
            evaluator.evaluate(
                snapshot(
                    received = 1,
                    written = 1,
                    lastActivityMillis = 90_000,
                    lastSuccessMillis = 90_000
                ),
                100_000
            )
        )
    }

    @Test
    fun repeatedFailuresReturnDegraded() {
        assertEquals(
            DnsHealthStatus.DEGRADED,
            evaluator.evaluate(
                snapshot(
                    received = 3,
                    failed = 3,
                    consecutiveFailures = 3,
                    lastActivityMillis = 99_000
                ),
                100_000
            )
        )
    }

    @Test
    fun oldTelemetryReturnsUnknown() {
        assertEquals(
            DnsHealthStatus.UNKNOWN,
            evaluator.evaluate(
                snapshot(
                    received = 1,
                    written = 1,
                    lastActivityMillis = 10_000,
                    lastSuccessMillis = 10_000
                ),
                100_000
            )
        )
    }

    @Test
    fun successfulWriteResetsFailureState() {
        assertEquals(
            DnsHealthStatus.HEALTHY,
            evaluator.evaluate(
                snapshot(
                    received = 5,
                    written = 2,
                    failed = 3,
                    consecutiveFailures = 0,
                    lastActivityMillis = 99_000,
                    lastSuccessMillis = 99_000
                ),
                100_000
            )
        )
    }

    @Test
    fun clockMismatchReturnsUnknown() {
        assertEquals(
            DnsHealthStatus.UNKNOWN,
            evaluator.evaluate(
                snapshot(
                    received = 1,
                    lastActivityMillis = 200_000
                ),
                100_000
            )
        )
    }
}
