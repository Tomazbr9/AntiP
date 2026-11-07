package br.com.reboot.poc.dns

data class DnsHealthSnapshot(
    val received: Long,
    val written: Long,
    val failed: Long,
    val rejected: Long,
    val consecutiveFailures: Long,
    val lastActivityMillis: Long,
    val lastSuccessMillis: Long
)
