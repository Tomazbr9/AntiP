package br.com.reboot.poc.protection


interface PendingStopCleanupRepository {
    fun load(): PendingStopCleanup?
    fun save(value: PendingStopCleanup)
    fun clear()
}
