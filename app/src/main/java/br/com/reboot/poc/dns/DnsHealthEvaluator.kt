package br.com.reboot.poc.dns

enum class DnsHealthStatus {
    HEALTHY,
    DEGRADED,
    IDLE,
    UNKNOWN
}

class DnsHealthEvaluator(
    private val freshnessMillis: Long = 60_000L,
    private val failureThreshold: Long = 3L
) {

    init {
        require(freshnessMillis > 0)
        require(failureThreshold > 0)
    }

    fun evaluate(
        snapshot: DnsHealthSnapshot,
        nowMillis: Long
    ): DnsHealthStatus {

        if (snapshot.lastActivityMillis < 0L) {
            return DnsHealthStatus.IDLE
        }

        if (nowMillis < snapshot.lastActivityMillis) {
            return DnsHealthStatus.UNKNOWN
        }

        val activityAge =
            nowMillis - snapshot.lastActivityMillis

        if (activityAge > freshnessMillis) {
            return DnsHealthStatus.UNKNOWN
        }

        if (
            snapshot.consecutiveFailures >= failureThreshold
        ) {
            return DnsHealthStatus.DEGRADED
        }

        val lastSuccess = snapshot.lastSuccessMillis

        if (
            lastSuccess >= 0L &&
            nowMillis >= lastSuccess &&
            nowMillis - lastSuccess <= freshnessMillis
        ) {
            return DnsHealthStatus.HEALTHY
        }

        if (
            snapshot.written == 0L &&
            (snapshot.failed > 0L || snapshot.rejected > 0L)
        ) {
            return DnsHealthStatus.DEGRADED
        }

        return DnsHealthStatus.IDLE
    }
}
