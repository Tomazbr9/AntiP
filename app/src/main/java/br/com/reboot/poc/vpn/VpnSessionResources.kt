package br.com.reboot.poc.vpn

import java.util.concurrent.atomic.AtomicBoolean

/**
 * Associa os recursos de uma execução da VPN
 * a um identificador de sessão.
 *
 * A classe não depende do Android, permitindo
 * testes unitários na JVM.
 */
class VpnSessionResources(
    val sessionId: Long,
    val identity: VpnSessionIdentity = VpnSessionIdentity.create(sessionId)
) : AutoCloseable {

    init {
        require(identity.localId == sessionId) {
            "Session identity mismatch"
        }
    }

    val sessionKey: String
        get() = identity.sessionKey

    private val scope = VpnResourceScope()
    private val stopped = AtomicBoolean(false)

    @Volatile
    var closeStatus = VpnResourceCloseStatus.NOT_STARTED
        private set

    @Volatile
    private var reader: Thread? = null

    fun <T : AutoCloseable> register(resource: T): T {
        return scope.register(resource)
    }

    fun setReader(thread: Thread) {
        check(!stopped.get()) {
            "VPN session already stopped"
        }

        synchronized(this) {
            check(!stopped.get()) {
                "VPN session already stopped"
            }
            check(reader == null) {
                "VPN reader already assigned"
            }
            reader = thread
        }
    }

    fun isStopped(): Boolean = stopped.get()


    override fun close() {
        val threadToInterrupt: Thread?

        synchronized(this) {
            if (!stopped.compareAndSet(false, true)) {
                return
            }

            closeStatus = VpnResourceCloseStatus.IN_PROGRESS
            threadToInterrupt = reader
        }

        try {
            // Fecha os recursos registrados na scope.
            // A scope preserva a ordem inversa.
            scope.close()

            closeStatus = VpnResourceCloseStatus.SUCCEEDED

        } catch (ex: Throwable) {
            // Registrar a falha sem ocultá-la
            // do RebootDnsVpnService.
            closeStatus = VpnResourceCloseStatus.FAILED
            throw ex

        } finally {
            if (threadToInterrupt !== Thread.currentThread()) {
                threadToInterrupt?.interrupt()
            }
        }
    }

    fun awaitReaderTermination(
        timeoutMillis: Long = 1000L
    ): Boolean {
        require(timeoutMillis >= 0L)

        val thread = synchronized(this) {
            reader
        } ?: return true

        if (thread === Thread.currentThread()) {
            return false
        }

        return try {
            thread.join(timeoutMillis)
            !thread.isAlive
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            false
        }
    }



}
