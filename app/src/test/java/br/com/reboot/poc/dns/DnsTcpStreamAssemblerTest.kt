package br.com.reboot.poc.dns

import org.junit.Assert.*
import org.junit.Test

class DnsTcpStreamAssemblerTest {

    private fun message(
        size: Int = 12,
        id: Int = 1
    ): ByteArray {
        return ByteArray(size).apply {
            this[0] = (id ushr 8).toByte()
            this[1] = id.toByte()
        }
    }

    private fun frame(data: ByteArray): ByteArray {
        return byteArrayOf(
            (data.size ushr 8).toByte(),
            data.size.toByte()
        ) + data
    }

    @Test
    fun completeMessageIsReturned() {
        val assembler = DnsTcpStreamAssembler()
        val dns = message()

        val result = assembler.append(frame(dns))

        assertEquals(1, result.size)
        assertArrayEquals(dns, result[0])
        assertEquals(0, assembler.pendingBytes())
    }

    @Test
    fun fragmentedMessageIsReassembled() {
        val assembler = DnsTcpStreamAssembler()
        val dns = message(100)
        val encoded = frame(dns)

        assertTrue(
            assembler.append(
                encoded.copyOfRange(0, 1)
            ).isEmpty()
        )

        assertTrue(
            assembler.append(
                encoded.copyOfRange(1, 30)
            ).isEmpty()
        )

        val result = assembler.append(
            encoded.copyOfRange(30, encoded.size)
        )

        assertEquals(1, result.size)
        assertArrayEquals(dns, result[0])
    }

    @Test
    fun multipleMessagesInOneChunk() {
        val assembler = DnsTcpStreamAssembler()

        val first = message(12, 1)
        val second = message(30, 2)

        val result = assembler.append(
            frame(first) + frame(second)
        )

        assertEquals(2, result.size)
        assertArrayEquals(first, result[0])
        assertArrayEquals(second, result[1])
    }

    @Test
    fun completeMessageAndPartialNextMessage() {
        val assembler = DnsTcpStreamAssembler()

        val first = message(12, 1)
        val second = message(40, 2)
        val secondFrame = frame(second)

        val result = assembler.append(
            frame(first) + secondFrame.copyOfRange(0, 10)
        )

        assertEquals(1, result.size)
        assertArrayEquals(first, result[0])
        assertEquals(10, assembler.pendingBytes())

        val remaining = assembler.append(
            secondFrame.copyOfRange(
                10,
                secondFrame.size
            )
        )

        assertEquals(1, remaining.size)
        assertArrayEquals(second, remaining[0])
    }

    @Test
    fun emptyInputReturnsNoMessages() {
        val assembler = DnsTcpStreamAssembler()

        assertTrue(
            assembler.append(byteArrayOf()).isEmpty()
        )
    }

    @Test
    fun invalidLengthRejectsAssembler() {
        val assembler = DnsTcpStreamAssembler()

        assertThrows(IllegalArgumentException::class.java) {
            assembler.append(byteArrayOf(0, 5))
        }

        assertTrue(assembler.isFailed())

        assertThrows(IllegalStateException::class.java) {
            assembler.append(frame(message()))
        }
    }

    @Test
    fun customMaximumIsEnforced() {
        val assembler = DnsTcpStreamAssembler(
            maxMessageSize = 100
        )

        assertThrows(IllegalArgumentException::class.java) {
            assembler.append(frame(message(101)))
        }

        assertTrue(assembler.isFailed())
    }

    @Test
    fun invalidInputRangeIsRejected() {
        val assembler = DnsTcpStreamAssembler()

        assertThrows(IllegalArgumentException::class.java) {
            assembler.append(
                byteArrayOf(1, 2),
                offset = 1,
                length = 5
            )
        }
    }

    @Test
    fun maximumSizeMessageIsSupported() {
        val assembler = DnsTcpStreamAssembler()
        val dns = message(65535)

        val result = assembler.append(frame(dns))

        assertEquals(1, result.size)
        assertArrayEquals(dns, result[0])
    }
}
