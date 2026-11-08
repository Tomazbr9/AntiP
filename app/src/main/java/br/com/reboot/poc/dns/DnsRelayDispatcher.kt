package br.com.reboot.poc.dns

import android.util.Log
import java.io.FileOutputStream
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import android.os.SystemClock


class DnsRelayDispatcher(
    private val forwarder: DnsUpstreamForwarder,
    private val output: FileOutputStream
) {
    companion object {
        private const val TAG = "RebootDnsPoc"
    }

    private val active = AtomicBoolean(true)
    private val writeLock = Any()

    private val executor = DnsTaskExecutor(
        workers = 4,
        queueCapacity = 32
    )

    private val received = AtomicLong()
    private val written = AtomicLong()
    private val failed = AtomicLong()
    private val rejected = AtomicLong()
    private val consecutiveFailures = AtomicLong()
    private val lastActivityMillis = AtomicLong(-1L)
    private val lastSuccessMillis = AtomicLong(-1L)

    fun healthSnapshot(): DnsHealthSnapshot {
        return DnsHealthSnapshot(
            received = received.get(),
            written = written.get(),
            failed = failed.get(),
            rejected = rejected.get(),
            consecutiveFailures = consecutiveFailures.get(),
            lastActivityMillis = lastActivityMillis.get(),
            lastSuccessMillis = lastSuccessMillis.get()
        )
    }

    private fun recordFailure() {
        failed.incrementAndGet()
        consecutiveFailures.incrementAndGet()
        lastActivityMillis.set(SystemClock.elapsedRealtime())
    }


    private fun recordSuccess() {
        written.incrementAndGet()
        consecutiveFailures.set(0L)

        val now = SystemClock.elapsedRealtime()

        lastActivityMillis.set(now)
        lastSuccessMillis.set(now)
    }
    fun submit(
        packet: ByteArray,
        length: Int,
        query: DnsQuery
    ) {
        if (!active.get()) return

        // O leitor TUN reutiliza o buffer.
        // Copia os bytes antes de entregar ao worker.
        if (length <= 0 || length > packet.size) {
            recordFailure()
            return
        }

        val requestCopy = packet.copyOf(length)

        // Evita compartilhar um payload mutável
        // entre a thread leitora e os workers.
        val queryCopy = query.copy(
            payload = query.payload.copyOf()
        )

        received.incrementAndGet()
        lastActivityMillis.set(SystemClock.elapsedRealtime())

        val accepted = executor.submit {
            if (active.get()) {
                process(requestCopy, queryCopy)
            }
        }

        if (!accepted && active.get()) {
            rejected.incrementAndGet()

            consecutiveFailures.incrementAndGet()
            lastActivityMillis.set(SystemClock.elapsedRealtime())

            Log.w(
                TAG,
                "dns_relay_queue_full_or_closed"
            )
        }
    }
    private fun process(
        request: ByteArray,
        query: DnsQuery
    ) {
        try {
            val response = forwarder.forward(query)

            if (!active.get()) return

            val probe = DnsFilterProbe.inspect(
                queryPayload = query.payload,
                responsePayload = response
            )

            if (probe != null) {
                Log.i(
                    TAG,
                    "DNS_FILTER_PROBE result=$probe"
                )
            }

            val replyPacket =
                DnsResponsePacketBuilder.build(
                    request = request,
                    requestLength = request.size,
                    dnsResponse = response
                )

            if (replyPacket == null) {
                recordFailure()

                Log.w(
                    TAG,
                    "dns_relay_packet_rejected"
                )
                return
            }

            synchronized(writeLock) {
                if (active.get()) {
                    output.write(replyPacket)

                    recordSuccess()
                    val total = written.get()

                    Log.i(
                        TAG,
                        "DNS_RELAY_OK " +
                                "tunWritten=$total " +
                                "responseBytes=${replyPacket.size}"
                    )
                }
            }

        } catch (ex: Exception) {
            if (active.get()) {
                recordFailure()

                Log.w(
                    TAG,
                    "dns_relay_failed " +
                            "type=${ex.javaClass.simpleName}"
                )
            }
        }
    }

    fun close() {
        synchronized(writeLock) {
            if (!active.compareAndSet(true, false)) {
                return
            }

            executor.close()
            forwarder.close()

            Log.i(
                TAG,
                "dns_upstream_sockets_closed"
            )

            Log.i(
                TAG,
                "dns_relay_stopped " +
                        "received=${received.get()} " +
                        "written=${written.get()} " +
                        "failed=${failed.get()} " +
                        "rejected=${rejected.get()}"
            )
        }
    }
}
