package br.com.reboot.poc.vpn

enum class VpnOperationalStatus {
    ACTIVE,
    INACTIVE,
    UNKNOWN,
    ERROR
}

/**
 * Classifica a evidência operacional disponível.
 *
 * Não consulta o Android e não inicia ou
 * encerra sessões VPN.
 */
object VpnOperationalStatusResolver {

    fun resolve(
        snapshot: VpnOperationalSnapshot,
        stopResult: VpnStopResult? = null
    ): VpnOperationalStatus {

        if (stopResult != null) {
            return when (stopResult) {
                VpnStopResult.STOPPED ->
                    VpnOperationalStatus.INACTIVE

                VpnStopResult.STOPPED_WITH_ERRORS ->
                    VpnOperationalStatus.ERROR

                VpnStopResult.STALE_SESSION,
                VpnStopResult.INVALID_STATE ->
                    VpnOperationalStatus.UNKNOWN
            }
        }

        return when (snapshot) {
            is VpnOperationalSnapshot.Active ->
                VpnOperationalStatus.ACTIVE

            VpnOperationalSnapshot.Unknown ->
                VpnOperationalStatus.UNKNOWN

            // Este estado somente deve ser fornecido
            // por uma verificação operacional confiável.
            VpnOperationalSnapshot.Inactive ->
                VpnOperationalStatus.INACTIVE
        }
    }
}
