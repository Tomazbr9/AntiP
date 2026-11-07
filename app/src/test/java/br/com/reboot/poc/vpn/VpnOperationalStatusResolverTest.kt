package br.com.reboot.poc

import br.com.reboot.poc.vpn.*
import org.junit.Assert.assertEquals
import org.junit.Test
import java.util.UUID

class VpnOperationalStatusResolverTest {

    private val sessionKey = UUID.randomUUID().toString()

    @Test
    fun activeSnapshotReturnsActive() {
        val result = VpnOperationalStatusResolver.resolve(
            VpnOperationalSnapshot.Active(sessionKey)
        )

        assertEquals(VpnOperationalStatus.ACTIVE, result)
    }

    @Test
    fun unknownSnapshotNeverReturnsInactive() {
        val result = VpnOperationalStatusResolver.resolve(
            VpnOperationalSnapshot.Unknown
        )

        assertEquals(VpnOperationalStatus.UNKNOWN, result)
    }

    @Test
    fun confirmedStopReturnsInactive() {
        val result = VpnOperationalStatusResolver.resolve(
            snapshot = VpnOperationalSnapshot.Unknown,
            stopResult = VpnStopResult.STOPPED
        )

        assertEquals(VpnOperationalStatus.INACTIVE, result)
    }

    @Test
    fun failedStopReturnsError() {
        val result = VpnOperationalStatusResolver.resolve(
            snapshot = VpnOperationalSnapshot.Unknown,
            stopResult = VpnStopResult.STOPPED_WITH_ERRORS
        )

        assertEquals(VpnOperationalStatus.ERROR, result)
    }

    @Test
    fun staleStopDoesNotConfirmInactivity() {
        val result = VpnOperationalStatusResolver.resolve(
            snapshot = VpnOperationalSnapshot.Unknown,
            stopResult = VpnStopResult.STALE_SESSION
        )

        assertEquals(VpnOperationalStatus.UNKNOWN, result)
    }

    @Test
    fun invalidStopStateDoesNotConfirmInactivity() {
        val result = VpnOperationalStatusResolver.resolve(
            snapshot = VpnOperationalSnapshot.Unknown,
            stopResult = VpnStopResult.INVALID_STATE
        )

        assertEquals(VpnOperationalStatus.UNKNOWN, result)
    }
}
