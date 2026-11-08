package br.com.reboot.poc.dns

import org.junit.Assert.*
import org.junit.Test
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import kotlin.concurrent.thread

class DnsTcpUpstreamForwarderTest {

    private fun query(): ByteArray =
        ByteArray(12).apply {
            this[0] = 0x12
            this[1] = 0x34
            this[2] = 0x01
        }

    @Test
    fun forwardsQueryAndReceivesResponse() {
        ServerSocket(
            0, 1, InetAddress.getLoopbackAddress()
        ).use { server ->

            val worker = thread {
                server.accept().use { client ->
                    val input = DataInputStream(
                        client.getInputStream()
                    )

                    val size = input.readUnsignedShort()
                    val request = ByteArray(size)
                    input.readFully(request)

                    val response = request.copyOf().apply {
                        this[2] = 0x81.toByte()
                        this[3] = 0x80.toByte()
                    }

                    val output = DataOutputStream(
                        client.getOutputStream()
                    )

                    output.writeShort(response.size)
                    output.write(response)
                    output.flush()
                }
            }

            var protectedBeforeConnect = false

            val forwarder = DnsTcpUpstreamForwarder(
                protectSocket = { socket ->
                    protectedBeforeConnect = !socket.isConnected
                    true
                },
                destination = InetSocketAddress(
                    InetAddress.getLoopbackAddress(),
                    server.localPort
                )
            )

            try {
                val response = forwarder.forward(query())

                assertTrue(protectedBeforeConnect)
                assertEquals(12, response.size)
                assertEquals(
                    0x80,
                    response[2].toInt() and 0x80
                )
                assertEquals(0, forwarder.activeCount())
            } finally {
                forwarder.close()
                worker.join(2000)
            }
        }
    }

    @Test
    fun rejectsSocketWhenProtectionFails() {
        val forwarder = DnsTcpUpstreamForwarder(
            protectSocket = { false },
            destination = InetSocketAddress(
                InetAddress.getLoopbackAddress(),
                53
            )
        )

        try {
            assertThrows(IOException::class.java) {
                forwarder.forward(query())
            }

            assertEquals(0, forwarder.activeCount())
        } finally {
            forwarder.close()
        }
    }

    @Test
    fun closedForwarderRejectsNewQueries() {
        val forwarder = DnsTcpUpstreamForwarder(
            protectSocket = { true }
        )

        forwarder.close()

        assertTrue(forwarder.isClosed())

        assertThrows(IOException::class.java) {
            forwarder.forward(query())
        }
    }

    @Test
    fun readTimeoutIsPropagated() {
        ServerSocket(
            0, 1, InetAddress.getLoopbackAddress()
        ).use { server ->

            val worker = thread {
                server.accept().use { client ->
                    // Mantém a conexão aberta sem enviar
                    // uma resposta dentro do timeout.
                    Thread.sleep(400)
                }
            }

            val forwarder = DnsTcpUpstreamForwarder(
                protectSocket = { true },
                destination = InetSocketAddress(
                    InetAddress.getLoopbackAddress(),
                    server.localPort
                ),
                readTimeoutMillis = 100
            )

            try {
                assertThrows(
                    SocketTimeoutException::class.java
                ) {
                    forwarder.forward(query())
                }
            } finally {
                forwarder.close()
                worker.join(2000)
            }
        }
    }
}
