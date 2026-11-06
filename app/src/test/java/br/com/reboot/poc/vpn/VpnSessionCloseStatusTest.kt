package br.com.reboot.poc.vpn

import br.com.reboot.poc.vpn.VpnSessionResources
import br.com.reboot.poc.vpn.VpnResourceCloseStatus
import org.junit.Assert.*
import org.junit.Test

class VpnSessionCloseStatusTest {

    @Test
    fun initialStatusIsNotStarted() {
        val session = VpnSessionResources(1L)

        assertEquals(
            VpnResourceCloseStatus.NOT_STARTED,
            session.closeStatus
        )
    }

    @Test
    fun successfulCloseUpdatesStatus() {
        val session = VpnSessionResources(1L)

        session.register(AutoCloseable {})

        session.close()

        assertEquals(
            VpnResourceCloseStatus.SUCCEEDED,
            session.closeStatus
        )

        assertTrue(session.isStopped())
    }

    @Test
    fun failedCloseUpdatesStatus() {
        val session = VpnSessionResources(1L)

        session.register(
            AutoCloseable {
                throw IllegalStateException("Simulated failure")
            }
        )

        try {
            session.close()
            fail("Expected close failure")
        } catch (_: IllegalStateException) {
            // Falha propagada corretamente.
        }

        assertEquals(
            VpnResourceCloseStatus.FAILED,
            session.closeStatus
        )

        assertTrue(session.isStopped())
    }

    @Test
    fun everyResourceIsAttemptedAfterFailure() {
        val session = VpnSessionResources(1L)
        val closed = mutableListOf<String>()

        session.register(
            AutoCloseable {
                closed.add("first")
            }
        )

        session.register(
            AutoCloseable {
                closed.add("second")
                throw IllegalStateException("Failure")
            }
        )

        session.register(
            AutoCloseable {
                closed.add("third")
            }
        )

        try {
            session.close()
            fail("Expected failure")
        } catch (_: IllegalStateException) {
            // O fechamento continua para os demais.
        }

        assertEquals(
            listOf("third", "second", "first"),
            closed
        )

        assertEquals(
            VpnResourceCloseStatus.FAILED,
            session.closeStatus
        )
    }

    @Test
    fun repeatedCloseDoesNotCloseResourcesTwice() {
        val session = VpnSessionResources(1L)
        var closeCount = 0

        session.register(
            AutoCloseable {
                closeCount++
            }
        )

        session.close()
        session.close()

        assertEquals(1, closeCount)

        assertEquals(
            VpnResourceCloseStatus.SUCCEEDED,
            session.closeStatus
        )
    }

    @Test
    fun emptySessionCanBeClosed() {
        val session = VpnSessionResources(1L)

        session.close()

        assertEquals(
            VpnResourceCloseStatus.SUCCEEDED,
            session.closeStatus
        )
    }
}
