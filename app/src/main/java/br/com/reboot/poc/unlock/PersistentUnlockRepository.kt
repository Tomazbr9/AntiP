package br.com.reboot.poc.unlock


interface PersistentUnlockRepository {
    fun save(request: StoredUnlockRequest)
    fun load(): StoredUnlockRequest?
    fun clear()
}
