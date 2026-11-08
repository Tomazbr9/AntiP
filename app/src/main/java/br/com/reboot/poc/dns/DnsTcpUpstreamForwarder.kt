package br.com.reboot.poc.dns

import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Encaminha consultas DNS por TCP.
 *
 * Cada consulta utiliza um novo socket.
 * A proteção contra o loop da VPN ocorre
 * antes da conexão com o servidor DNS.
 *
 * Não deve ser chamado na thread principal.
 */
class DnsTcpUpstreamForwarder(
    private val protectSocket: (Socket) -> Boolean,
    private val destination: InetSocketAddress =
        InetSocketAddress("1.1.1.3", 53),
    private val connectTimeoutMillis: Int = 1500,
    private val readTimeoutMillis: Int = 1500,
    private val exchange: DnsTcpExchange = DnsTcpExchange()
) : AutoCloseable {

    init {
        require(connectTimeoutMillis > 0)
        require(readTimeoutMillis > 0)
    }

    private val lock = Any()
    private val sockets = mutableSetOf<Socket>()
    private var closed = false

    fun forward(query: ByteArray): ByteArray {
        require(query.size in 12..65535) {
            "Invalid DNS query length"
        }

        val socket = Socket()

        // Registrar antes de conectar permite
        // cancelar conexões pendentes no close().
        synchronized(lock) {
            if (closed) {
                socket.close()
                throw IOException("DNS TCP forwarder is closed")
            }

            sockets.add(socket)
        }

        try {
            socket.use {
                // Deve acontecer antes do connect().
                if (!protectSocket(it)) {
                    throw IOException(
                        "Failed to protect DNS TCP socket"
                    )
                }

                it.soTimeout = readTimeoutMillis

                it.connect(
                    destination,
                    connectTimeoutMillis
                )

                return exchange.execute(
                    query = query,
                    input = it.getInputStream(),
                    output = it.getOutputStream()
                )
            }
        } finally {
            synchronized(lock) {
                sockets.remove(socket)
            }

            // Garante fechamento mesmo se alguma
            // etapa anterior lançar uma exceção.
            socket.close()
        }
    }

    fun activeCount(): Int =
        synchronized(lock) {
            sockets.size
        }

    fun isClosed(): Boolean =
        synchronized(lock) {
            closed
        }

    override fun close() {
        val pending: List<Socket>

        synchronized(lock) {
            if (closed) return

            closed = true
            pending = sockets.toList()
            sockets.clear()
        }

        // Não segurar o lock durante o fechamento.
        pending.forEach { socket ->
            try {
                socket.close()
            } catch (_: IOException) {
                // Continuar fechando os demais sockets.
            }
        }
    }
}
