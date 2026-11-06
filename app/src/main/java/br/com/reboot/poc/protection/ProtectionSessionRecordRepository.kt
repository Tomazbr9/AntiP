package br.com.reboot.poc.protection


interface ProtectionSessionRecordRepository {
    fun save(record: ProtectionSessionRecord)
    fun load(): ProtectionSessionRecord?
    fun clear()
}
