package com.dnc.vpn

import android.util.Log
import java.util.concurrent.ConcurrentHashMap

/**
 * Manages TCP connection state for the VPN packet processor.
 * Tracks connections by their 4-tuple (srcIp, srcPort, dstIp, dstPort),
 * buffers payload for reassembly, and detects complete HTTP messages.
 */
class TcpConnectionManager {

    companion object {
        private const val TAG = "TcpConnectionMgr"
        private const val MAX_BUFFER_SIZE = 1024 * 1024 // 1MB max per connection
        private const val CONNECTION_TIMEOUT = 30_000L // 30 seconds
    }

    enum class TcpState {
        CLOSED,
        SYN_SENT,
        SYN_RECEIVED,
        ESTABLISHED,
        FIN_WAIT_1,
        FIN_WAIT_2,
        CLOSING,
        TIME_WAIT,
        CLOSE_WAIT,
        LAST_ACK
    }

    data class ConnectionKey(
        val srcIp: ByteArray,
        val srcPort: Int,
        val dstIp: ByteArray,
        val dstPort: Int
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is ConnectionKey) return false
            return srcIp.contentEquals(other.srcIp) &&
                    srcPort == other.srcPort &&
                    dstIp.contentEquals(other.dstIp) &&
                    dstPort == other.dstPort
        }

        override fun hashCode(): Int {
            var result = srcIp.contentHashCode()
            result = 31 * result + srcPort
            result = 31 * result + dstIp.contentHashCode()
            result = 31 * result + dstPort
            return result
        }
    }

    data class TcpConnection(
        val key: ConnectionKey,
        var state: TcpState = TcpState.CLOSED,
        val clientBuffer: ByteArrayOutputStream = ByteArrayOutputStream(),
        val serverBuffer: ByteArrayOutputStream = ByteArrayOutputStream(),
        var clientSeqNum: Long = 0,
        var serverSeqNum: Long = 0,
        var lastActivity: Long = System.currentTimeMillis(),
        var forwardSocket: java.net.Socket? = null,
        var isMitm: Boolean = false
    )

    private val connections = ConcurrentHashMap<ConnectionKey, TcpConnection>()

    fun getOrCreateConnection(key: ConnectionKey): TcpConnection {
        return connections.getOrPut(key) { TcpConnection(key) }
    }

    fun getConnection(key: ConnectionKey): TcpConnection? {
        return connections[key]
    }

    fun removeConnection(key: ConnectionKey) {
        val conn = connections.remove(key)
        try {
            conn?.forwardSocket?.close()
        } catch (e: Exception) {
            Log.w(TAG, "Error closing forward socket: ${e.message}")
        }
    }

    fun updateState(key: ConnectionKey, tcpPacket: PacketParser.TcpPacket): TcpState {
        val conn = getOrCreateConnection(key)
        conn.lastActivity = System.currentTimeMillis()

        val newState = when {
            tcpPacket.isRst -> {
                removeConnection(key)
                TcpState.CLOSED
            }
            tcpPacket.isSynAck -> {
                conn.state = TcpState.ESTABLISHED
                conn.serverSeqNum = tcpPacket.sequenceNumber
                TcpState.ESTABLISHED
            }
            tcpPacket.isSyn -> {
                conn.state = TcpState.SYN_RECEIVED
                conn.clientSeqNum = tcpPacket.sequenceNumber
                TcpState.SYN_RECEIVED
            }
            tcpPacket.isFin -> {
                when (conn.state) {
                    TcpState.ESTABLISHED -> TcpState.CLOSE_WAIT
                    TcpState.FIN_WAIT_1 -> TcpState.CLOSING
                    TcpState.FIN_WAIT_2 -> TcpState.TIME_WAIT
                    else -> conn.state
                }
            }
            tcpPacket.isAck && conn.state == TcpState.CLOSE_WAIT -> TcpState.LAST_ACK
            else -> conn.state
        }

        conn.state = newState

        // Update sequence numbers
        if (tcpPacket.hasPayload) {
            if (isClientToServer(key)) {
                conn.clientSeqNum = tcpPacket.sequenceNumber + tcpPacket.payload.size
            } else {
                conn.serverSeqNum = tcpPacket.sequenceNumber + tcpPacket.payload.size
            }
        }

        return newState
    }

    fun bufferPayload(key: ConnectionKey, payload: ByteArray, isFromClient: Boolean) {
        val conn = getConnection(key) ?: return

        try {
            val buffer = if (isFromClient) conn.clientBuffer else conn.serverBuffer
            if (buffer.size() + payload.size > MAX_BUFFER_SIZE) {
                Log.w(TAG, "Connection buffer overflow, clearing: ${key.srcPort}->${key.dstPort}")
                buffer.reset()
            }
            buffer.write(payload)
        } catch (e: Exception) {
            Log.e(TAG, "Error buffering payload: ${e.message}")
        }
    }

    /**
     * Check if we have a complete HTTP message in the buffer.
     * Detects based on Content-Length or chunked transfer encoding,
     * or the presence of two consecutive CRLFs for simple requests.
     */
    fun isCompleteHttpMessage(buffer: ByteArrayOutputStream): Boolean {
        val data = buffer.toByteArray()
        if (data.size < 4) return false

        val headerEnd = findHeaderEnd(data)
        if (headerEnd < 0) return false // Headers not complete yet

        val headerString = String(data, 0, headerEnd, Charsets.UTF_8)

        // Check for Content-Length
        val contentLengthMatch = Regex("Content-Length:\\s*(\\d+)", RegexOption.IGNORE_CASE)
            .find(headerString)
        if (contentLengthMatch != null) {
            val contentLength = contentLengthMatch.groupValues[1].toIntOrNull() ?: 0
            val totalExpected = headerEnd + 4 + contentLength // +4 for \r\n\r\n
            return data.size >= totalExpected
        }

        // Check for Transfer-Encoding: chunked
        if (headerString.contains("Transfer-Encoding: chunked", ignoreCase = true)) {
            // Check for the terminating chunk (0\r\n\r\n)
            val terminatingChunk = "0\r\n\r\n"
            return String(data, Charsets.UTF_8).contains(terminatingChunk)
        }

        // For responses without Content-Length and not chunked (connection close),
        // we rely on the connection closing or check for common patterns
        // For requests (starts with GET/POST/PUT etc.), headers only is often complete
        val firstLine = headerString.substringBefore("\r\n")
        if (firstLine.startsWith("GET ") || firstLine.startsWith("HEAD ") || firstLine.startsWith("DELETE ")) {
            return true // These methods typically don't have a body
        }

        // For POST/PUT with no Content-Length, we need more data or connection close
        return false
    }

    /**
     * Find the end of HTTP headers (position of \r\n\r\n)
     */
    private fun findHeaderEnd(data: ByteArray): Int {
        for (i in 0 until data.size - 3) {
            if (data[i] == '\r'.code.toByte() &&
                data[i + 1] == '\n'.code.toByte() &&
                data[i + 2] == '\r'.code.toByte() &&
                data[i + 3] == '\n'.code.toByte()
            ) {
                return i
            }
        }
        return -1
    }

    private fun isClientToServer(key: ConnectionKey): Boolean {
        // If source IP matches our VPN subnet (10.0.0.x), it's from client
        return key.srcIp[0] == 10.toByte() && key.srcIp[1] == 0.toByte() &&
                key.srcIp[2] == 0.toByte()
    }

    /**
     * Clean up stale connections
     */
    fun cleanupStaleConnections() {
        val now = System.currentTimeMillis()
        connections.entries.removeIf { (_, conn) ->
            val isStale = now - conn.lastActivity > CONNECTION_TIMEOUT
            if (isStale) {
                try {
                    conn.forwardSocket?.close()
                } catch (e: Exception) {
                    // Ignore
                }
            }
            isStale
        }
    }

    /**
     * Simple ByteArrayOutputStream that doesn't use synchronization
     * (we handle our own thread safety via ConcurrentHashMap)
     */
    class ByteArrayOutputStream : java.io.ByteArrayOutputStream() {
        fun reset() {
            count = 0
        }
    }

    fun connectionCount(): Int = connections.size
}

/**
 * Create a ConnectionKey from IP and TCP packet data
 */
fun createConnectionKey(
    srcIp: ByteArray,
    srcPort: Int,
    dstIp: ByteArray,
    dstPort: Int
): TcpConnectionManager.ConnectionKey {
    return TcpConnectionManager.ConnectionKey(srcIp, srcPort, dstIp, dstPort)
}
