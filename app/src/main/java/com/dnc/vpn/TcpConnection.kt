package com.dnc.vpn

import android.util.Log
import com.dnc.vpn.PacketParser.IpPacket
import com.dnc.vpn.PacketParser.TcpHeader
import com.dnc.vpn.PacketParser.TCP_FLAG_SYN
import com.dnc.vpn.PacketParser.TCP_FLAG_ACK
import com.dnc.vpn.PacketParser.TCP_FLAG_FIN
import com.dnc.vpn.PacketParser.TCP_FLAG_RST
import com.dnc.vpn.PacketParser.TCP_FLAG_PSH
import java.io.ByteArrayOutputStream
import java.net.InetAddress
import java.nio.ByteBuffer
import kotlin.math.min

/**
 * Manages the state of a single TCP connection tracked through the VPN.
 *
 * This class maintains the TCP state machine, buffers payload data for
 * reassembly, and detects complete HTTP messages (Content-Length or chunked
 * transfer encoding). It is designed for use in a local VPN proxy where the
 * service acts as a middleman between the device app and the remote server.
 */
class TcpConnection(
    val srcIp: InetAddress,
    val srcPort: Int,
    val dstIp: InetAddress,
    val dstPort: Int
) {

    companion object {
        private const val TAG = "TcpConnection"

        /** Maximum buffered payload per direction (256 KB). */
        private const val MAX_BUFFER_SIZE = 256 * 1024

        /** Maximum time (ms) a connection can sit idle before cleanup. */
        const val IDLE_TIMEOUT_MS = 30_000L

        /** Regex pattern for Content-Length header (case-insensitive). */
        private val CONTENT_LENGTH_REGEX = Regex(
            """(?i)\r\nContent-Length:\s*(\d+)\r\n"""
        )

        /** Regex pattern for Transfer-Encoding: chunked header. */
        private val CHUNKED_REGEX = Regex(
            """(?i)\r\nTransfer-Encoding:\s*chunked\r\n"""
        )

        /** HTTP header terminator. */
        private const val HEADER_END = "\r\n\r\n"

        /** Chunked transfer terminator. */
        private const val CHUNKED_END = "0\r\n\r\n"
    }

    /**
     * TCP connection states following a simplified state machine.
     */
    enum class State {
        /** Initial state — SYN received from client. */
        SYN_RECEIVED,
        /** SYN-ACK sent, waiting for ACK from client. */
        SYN_SENT,
        /** Connection fully established. */
        ESTABLISHED,
        /** Remote sent FIN, waiting for local FIN. */
        CLOSE_WAIT,
        /** Local sent FIN, waiting for remote FIN-ACK. */
        FIN_WAIT_1,
        /** FIN-ACK received, waiting for final ACK. */
        FIN_WAIT_2,
        /** Both sides closed, waiting for final ACK timeout. */
        CLOSING,
        /** Connection completely closed. */
        CLOSED
    }

    /**
     * Direction of data flow relative to the VPN.
     */
    enum class Direction {
        /** Data flowing from the device app toward the network. */
        OUTBOUND,
        /** Data flowing from the network toward the device app. */
        INBOUND
    }

    /**
     * Represents a complete HTTP message extracted from the TCP stream.
     */
    data class HttpMessage(
        val direction: Direction,
        val headerBytes: ByteArray,
        val bodyBytes: ByteArray,
        val isRequest: Boolean,
        val method: String?,
        val uri: String?,
        val statusCode: Int?,
        val statusMessage: String?
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is HttpMessage) return false
            return direction == other.direction &&
                    headerBytes.contentEquals(other.headerBytes) &&
                    bodyBytes.contentEquals(other.bodyBytes) &&
                    isRequest == other.isRequest
        }

        override fun hashCode(): Int {
            var result = direction.hashCode()
            result = 31 * result + headerBytes.contentHashCode()
            result = 31 * result + bodyBytes.contentHashCode()
            result = 31 * result + isRequest.hashCode()
            return result
        }
    }

    /** Current TCP state. */
    var state: State = State.SYN_RECEIVED
        private set

    /** Timestamp of the last activity on this connection. */
    var lastActivityMs: Long = System.currentTimeMillis()
        private set

    /** Client's initial sequence number (from SYN). */
    var clientIsn: Long = 0L
        private set

    /** Server's initial sequence number (from SYN-ACK). */
    var serverIsn: Long = 0L
        private set

    /** Client -> Server payload buffer (outbound from device). */
    private val outboundBuffer = ByteArrayOutputStream()

    /** Server -> Client payload buffer (inbound from network). */
    private val inboundBuffer = ByteArrayOutputStream()

    /** Sequence number tracking for the client (outbound) side. */
    var clientSeq: Long = 0L
        private set

    /** Sequence number tracking for the server (inbound) side. */
    var serverSeq: Long = 0L
        private set

    /** Acknowledgment number to send to client. */
    var clientAck: Long = 0L
        private set

    /** Acknowledgment number to send to server. */
    var serverAck: Long = 0L
        private set

    /** Client receive window. */
    var clientWindow: Int = 65535
        private set

    /** Server receive window. */
    var serverWindow: Int = 65535
        private set

    /**
     * Process an incoming TCP segment from the device (outbound direction).
     *
     * @param tcpHeader The parsed TCP header.
     * @param payload The TCP payload bytes.
     * @return A list of complete [HttpMessage]s if any were assembled.
     */
    fun processOutboundSegment(tcpHeader: TcpHeader, payload: ByteArray): List<HttpMessage> {
        lastActivityMs = System.currentTimeMillis()
        updateStateFlags(tcpHeader)

        if (payload.isEmpty()) return emptyList()

        clientSeq = tcpHeader.sequenceNumber
        clientAck = tcpHeader.acknowledgmentNumber
        clientWindow = tcpHeader.window

        if (outboundBuffer.size() + payload.size > MAX_BUFFER_SIZE) {
            Log.w(TAG, "Outbound buffer overflow for $flowKey, flushing")
            outboundBuffer.reset()
        }
        outboundBuffer.write(payload)

        return extractHttpMessages(outboundBuffer, Direction.OUTBOUND)
    }

    /**
     * Process an incoming TCP segment from the network (inbound direction).
     *
     * @param tcpHeader The parsed TCP header.
     * @param payload The TCP payload bytes.
     * @return A list of complete [HttpMessage]s if any were assembled.
     */
    fun processInboundSegment(tcpHeader: TcpHeader, payload: ByteArray): List<HttpMessage> {
        lastActivityMs = System.currentTimeMillis()
        updateStateFlags(tcpHeader)

        if (payload.isEmpty()) return emptyList()

        serverSeq = tcpHeader.sequenceNumber
        serverAck = tcpHeader.acknowledgmentNumber
        serverWindow = tcpHeader.window

        if (inboundBuffer.size() + payload.size > MAX_BUFFER_SIZE) {
            Log.w(TAG, "Inbound buffer overflow for $flowKey, flushing")
            inboundBuffer.reset()
        }
        inboundBuffer.write(payload)

        return extractHttpMessages(inboundBuffer, Direction.INBOUND)
    }

    /**
     * Initialize sequence numbers from the client's SYN packet.
     */
    fun initFromClientSyn(tcpHeader: TcpHeader) {
        clientIsn = tcpHeader.sequenceNumber
        clientSeq = tcpHeader.sequenceNumber
        clientWindow = tcpHeader.window
        state = State.SYN_RECEIVED
        Log.d(TAG, "SYN from client $flowKey, ISN=$clientIsn")
    }

    /**
     * Initialize server sequence number from SYN-ACK.
     */
    fun initFromServerSynAck(tcpHeader: TcpHeader) {
        serverIsn = tcpHeader.sequenceNumber
        serverSeq = tcpHeader.sequenceNumber
        serverWindow = tcpHeader.window
        state = State.ESTABLISHED
        Log.d(TAG, "SYN-ACK from server $flowKey, ISN=$serverIsn")
    }

    /**
     * Update TCP state machine based on flag transitions.
     */
    private fun updateStateFlags(tcpHeader: TcpHeader) {
        when (state) {
            State.SYN_RECEIVED -> {
                if (tcpHeader.isAck && !tcpHeader.isSyn) {
                    // Client ACK of our SYN-ACK — connection established
                    state = State.ESTABLISHED
                    Log.d(TAG, "Connection ESTABLISHED $flowKey")
                }
            }
            State.ESTABLISHED -> {
                when {
                    tcpHeader.isFin && !tcpHeader.isAck -> {
                        state = State.FIN_WAIT_1
                        Log.d(TAG, "FIN_WAIT_1 $flowKey")
                    }
                    tcpHeader.isFin && tcpHeader.isAck -> {
                        state = State.CLOSE_WAIT
                        Log.d(TAG, "CLOSE_WAIT $flowKey")
                    }
                    tcpHeader.isRst -> {
                        state = State.CLOSED
                        Log.d(TAG, "RST received, CLOSED $flowKey")
                    }
                }
            }
            State.FIN_WAIT_1 -> {
                if (tcpHeader.isFin || tcpHeader.isAck) {
                    state = State.FIN_WAIT_2
                    Log.d(TAG, "FIN_WAIT_2 $flowKey")
                }
            }
            State.FIN_WAIT_2 -> {
                if (tcpHeader.isFin) {
                    state = State.CLOSING
                    Log.d(TAG, "CLOSING $flowKey")
                }
            }
            State.CLOSE_WAIT -> {
                if (tcpHeader.isFin) {
                    state = State.CLOSING
                    Log.d(TAG, "CLOSING from CLOSE_WAIT $flowKey")
                }
            }
            State.CLOSING -> {
                if (tcpHeader.isAck) {
                    state = State.CLOSED
                    Log.d(TAG, "CLOSED $flowKey")
                }
            }
            else -> { /* No state transition */ }
        }
    }

    /**
     * Whether this connection is in a terminal or idle state and can be cleaned up.
     */
    val isClosed: Boolean
        get() = state == State.CLOSED

    /**
     * Whether this connection has been idle beyond the timeout threshold.
     */
    val isIdle: Boolean
        get() = (System.currentTimeMillis() - lastActivityMs) > IDLE_TIMEOUT_MS

    /**
     * Read all currently buffered outbound data and clear the buffer.
     */
    fun readOutbound(): ByteArray {
        val data = outboundBuffer.toByteArray()
        outboundBuffer.reset()
        return data
    }

    /**
     * Read all currently buffered inbound data and clear the buffer.
     */
    fun readInbound(): ByteArray {
        val data = inboundBuffer.toByteArray()
        inboundBuffer.reset()
        return data
    }

    /**
     * Peek at the outbound buffer without consuming it.
     */
    fun peekOutbound(): ByteArray = outboundBuffer.toByteArray()

    /**
     * Peek at the inbound buffer without consuming it.
     */
    fun peekInbound(): ByteArray = inboundBuffer.toByteArray()

    /**
     * Write data into the outbound buffer (simulating device -> network data).
     */
    fun writeOutbound(data: ByteArray) {
        if (outboundBuffer.size() + data.size > MAX_BUFFER_SIZE) {
            outboundBuffer.reset()
        }
        outboundBuffer.write(data)
        lastActivityMs = System.currentTimeMillis()
    }

    /**
     * Write data into the inbound buffer (simulating network -> device data).
     */
    fun writeInbound(data: ByteArray) {
        if (inboundBuffer.size() + data.size > MAX_BUFFER_SIZE) {
            inboundBuffer.reset()
        }
        inboundBuffer.write(data)
        lastActivityMs = System.currentTimeMillis()
    }

    /**
     * Unique flow key for this connection: "srcIp:srcPort-dstIp:dstPort"
     */
    val flowKey: String
        get() = "${srcIp.hostAddress}:$srcPort-${dstIp.hostAddress}:$dstPort"

    /**
     * Attempt to extract complete HTTP messages from a payload buffer.
     *
     * Handles both Content-Length and chunked transfer encoding.
     * Consumed bytes are removed from the buffer; partial messages remain.
     */
    private fun extractHttpMessages(
        buffer: ByteArrayOutputStream,
        direction: Direction
    ): List<HttpMessage> {
        val messages = mutableListOf<HttpMessage>()
        val data = buffer.toByteArray()

        var offset = 0
        while (offset < data.size) {
            val remaining = data.size - offset
            val slice = data.copyOfRange(offset, data.size)

            val headerEndIndex = findHeaderEnd(slice)
            if (headerEndIndex < 0) {
                // No complete headers yet — wait for more data
                break
            }

            val headerBytes = slice.copyOfRange(0, headerEndIndex)
            val headerString = String(headerBytes, Charsets.ISO_8859_1)

            // Determine body length
            val bodyLength = determineBodyLength(headerString, headerBytes.size, slice)
            if (bodyLength < 0) {
                // Body not yet complete — wait for more data
                break
            }

            val totalMessageLength = headerEndIndex + bodyLength
            if (offset + totalMessageLength > data.size) {
                // Partial body — wait for more data
                break
            }

            val bodyBytes = if (bodyLength > 0) {
                slice.copyOfRange(headerEndIndex, headerEndIndex + bodyLength)
            } else {
                ByteArray(0)
            }

            val parsed = parseHttpMeta(headerString)
            messages.add(
                HttpMessage(
                    direction = direction,
                    headerBytes = headerBytes,
                    bodyBytes = bodyBytes,
                    isRequest = parsed.isRequest,
                    method = parsed.method,
                    uri = parsed.uri,
                    statusCode = parsed.statusCode,
                    statusMessage = parsed.statusMessage
                )
            )

            offset += totalMessageLength
        }

        // Remove consumed bytes from the buffer
        if (offset > 0) {
            val leftover = data.copyOfRange(offset, data.size)
            buffer.reset()
            buffer.write(leftover)
        }

        return messages
    }

    /**
     * Find the end of HTTP headers (double CRLF) within the data.
     * Returns the byte offset just past the double CRLF, or -1 if not found.
     */
    private fun findHeaderEnd(data: ByteArray): Int {
        for (i in 0 until data.size - 3) {
            if (data[i] == '\r'.code.toByte() &&
                data[i + 1] == '\n'.code.toByte() &&
                data[i + 2] == '\r'.code.toByte() &&
                data[i + 3] == '\n'.code.toByte()
            ) {
                return i + 4
            }
        }
        return -1
    }

    /**
     * Determine the body length based on HTTP headers.
     *
     * Returns:
     * - A non-negative body length if the body is complete
     * - -1 if the body is incomplete (need more data)
     */
    private fun determineBodyLength(
        headerString: String,
        headerEndOffset: Int,
        fullSlice: ByteArray
    ): Int {
        // Check for Content-Length
        val contentLengthMatch = CONTENT_LENGTH_REGEX.find(headerString)
        if (contentLengthMatch != null) {
            val declaredLength = contentLengthMatch.groupValues[1].toIntOrNull() ?: 0
            val availableAfterHeaders = fullSlice.size - headerEndOffset
            return if (availableAfterHeaders >= declaredLength) {
                declaredLength
            } else {
                -1 // Body not yet complete
            }
        }

        // Check for chunked transfer encoding
        if (CHUNKED_REGEX.containsMatchIn(headerString)) {
            return determineChunkedBodyLength(fullSlice, headerEndOffset)
        }

        // No Content-Length and not chunked — check for 1xx, 204, 304 responses (no body)
        val firstLine = headerString.substringBefore("\r\n")
        if (firstLine.startsWith("HTTP/")) {
            val statusCode = firstLine.substringAfter(" ").substringBefore(" ").toIntOrNull() ?: 200
            if (statusCode in 100..199 || statusCode == 204 || statusCode == 304) {
                return 0
            }
        }

        // For responses without Content-Length and not chunked, the body runs until
        // connection close. We cannot determine completeness from headers alone.
        // Return current available data length as the body (best-effort for streaming).
        val availableAfterHeaders = fullSlice.size - headerEndOffset
        return if (availableAfterHeaders > 0) availableAfterHeaders else 0
    }

    /**
     * Determine the total length of a chunked transfer-encoded body.
     *
     * Scans chunk-by-chunk to find the terminating 0-length chunk.
     * Returns total body length or -1 if the chunked body is incomplete.
     */
    private fun determineChunkedBodyLength(fullSlice: ByteArray, headerEndOffset: Int): Int {
        var pos = headerEndOffset
        var totalBodyLength = 0

        while (pos < fullSlice.size) {
            // Find the end of the chunk size line
            var lineEnd = -1
            for (i in pos until fullSlice.size - 1) {
                if (fullSlice[i] == '\r'.code.toByte() && fullSlice[i + 1] == '\n'.code.toByte()) {
                    lineEnd = i
                    break
                }
            }
            if (lineEnd < 0) return -1 // Incomplete chunk size line

            // Parse the chunk size (hex, ignoring extensions after semicolon)
            val sizeLine = String(fullSlice, pos, lineEnd - pos, Charsets.ISO_8859_1)
            val chunkSizeStr = sizeLine.substringBefore(";").trim()
            val chunkSize = try {
                chunkSizeStr.toLong(16)
            } catch (e: NumberFormatException) {
                Log.w(TAG, "Invalid chunk size: '$chunkSizeStr'")
                return -1
            }

            val chunkDataStart = lineEnd + 2 // Skip \r\n after chunk size
            if (chunkSize == 0L) {
                // Terminal chunk — expect trailing \r\n (possibly with trailers)
                val trailerEnd = chunkDataStart + 2 // Minimum: empty trailer \r\n
                if (trailerEnd > fullSlice.size) return -1

                // Check for the final \r\n
                if (fullSlice.size >= trailerEnd &&
                    fullSlice[chunkDataStart] == '\r'.code.toByte() &&
                    fullSlice[chunkDataStart + 1] == '\n'.code.toByte()
                ) {
                    totalBodyLength += (chunkDataStart + 2 - headerEndOffset)
                    return totalBodyLength
                }
                // There may be trailers — look for the final \r\n\r\n
                for (i in chunkDataStart until fullSlice.size - 3) {
                    if (fullSlice[i] == '\r'.code.toByte() &&
                        fullSlice[i + 1] == '\n'.code.toByte() &&
                        fullSlice[i + 2] == '\r'.code.toByte() &&
                        fullSlice[i + 3] == '\n'.code.toByte()
                    ) {
                        totalBodyLength += (i + 4 - headerEndOffset)
                        return totalBodyLength
                    }
                }
                return -1 // Trailers not yet complete
            }

            val chunkDataEnd = chunkDataStart + chunkSize.toInt()
            val afterChunk = chunkDataEnd + 2 // \r\n after chunk data
            if (afterChunk > fullSlice.size) return -1 // Incomplete chunk

            pos = afterChunk
        }

        return -1 // Did not find terminal chunk
    }

    /**
     * Parse the first line of an HTTP message to determine if it's a request
     * or response, and extract method/URI or status code.
     */
    private fun parseHttpMeta(headerString: String): HttpMeta {
        val firstLine = headerString.substringBefore("\r\n")

        // HTTP request: "METHOD URI HTTP/1.x"
        val requestParts = firstLine.split(" ")
        if (requestParts.size >= 3 && requestParts[2].startsWith("HTTP/")) {
            return HttpMeta(
                isRequest = true,
                method = requestParts[0],
                uri = requestParts[1],
                statusCode = null,
                statusMessage = null
            )
        }

        // HTTP response: "HTTP/1.x STATUS_CODE STATUS_MESSAGE"
        if (firstLine.startsWith("HTTP/")) {
            val statusCode = requestParts.getOrNull(1)?.toIntOrNull()
            val statusMessage = requestParts.drop(2).joinToString(" ")
            return HttpMeta(
                isRequest = false,
                method = null,
                uri = null,
                statusCode = statusCode,
                statusMessage = statusMessage
            )
        }

        return HttpMeta(
            isRequest = false,
            method = null,
            uri = null,
            statusCode = null,
            statusMessage = null
        )
    }

    private data class HttpMeta(
        val isRequest: Boolean,
        val method: String?,
        val uri: String?,
        val statusCode: Int?,
        val statusMessage: String?
    )

    override fun toString(): String =
        "TcpConnection($flowKey, state=$state, lastActivity=${lastActivityMs})"
}

/**
 * Registry for tracking active TCP connections by their 4-tuple.
 */
class TcpConnectionTracker {

    companion object {
        private const val TAG = "TcpConnTracker"
    }

    /** Map of "srcIp:srcPort-dstIp:dstPort" -> active connection. */
    private val connections = mutableMapOf<String, TcpConnection>()

    /** Current number of active (non-closed) connections. */
    val activeCount: Int
        get() = connections.count { !it.value.isClosed }

    /**
     * Get or create a [TcpConnection] for the given packet.
     *
     * If the packet is a SYN and no connection exists, a new one is created.
     * If the connection already exists, it is returned.
     */
    fun getOrCreate(packet: IpPacket): TcpConnection? {
        val tcpHeader = packet.tcpHeader ?: return null

        val srcIp = packet.ipHeader.sourceIp
        val srcPort = tcpHeader.sourcePort
        val dstIp = packet.ipHeader.destinationIp
        val dstPort = tcpHeader.destinationPort

        val key = "${srcIp.hostAddress}:$srcPort-${dstIp.hostAddress}:$dstPort"
        val reverseKey = "${dstIp.hostAddress}:$dstPort-${srcIp.hostAddress}:$srcPort"

        // Check for existing connection in either direction
        connections[key]?.let { return it }
        connections[reverseKey]?.let { return it }

        // New connection — only valid on SYN
        if (tcpHeader.isSyn && !tcpHeader.isAck) {
            val conn = TcpConnection(srcIp, srcPort, dstIp, dstPort)
            conn.initFromClientSyn(tcpHeader)
            connections[key] = conn
            Log.d(TAG, "New connection: $key (total: ${connections.size})")
            return conn
        }

        // Non-SYN packet with no known connection — log and skip
        Log.w(TAG, "Unknown connection for packet: $key flags=${tcpHeader.flags}")
        return null
    }

    /**
     * Find a connection by its 4-tuple key (either direction).
     */
    fun find(srcIp: InetAddress, srcPort: Int, dstIp: InetAddress, dstPort: Int): TcpConnection? {
        val key = "${srcIp.hostAddress}:$srcPort-${dstIp.hostAddress}:$dstPort"
        val reverseKey = "${dstIp.hostAddress}:$dstPort-${srcIp.hostAddress}:$srcPort"
        return connections[key] ?: connections[reverseKey]
    }

    /**
     * Remove a connection from the tracker.
     */
    fun remove(conn: TcpConnection) {
        val key = conn.flowKey
        connections.remove(key)
        // Also try reverse
        val reverseKey = "${conn.dstIp.hostAddress}:${conn.dstPort}-${conn.srcIp.hostAddress}:${conn.srcPort}"
        connections.remove(reverseKey)
        Log.d(TAG, "Removed connection: $key (remaining: ${connections.size})")
    }

    /**
     * Clean up closed and idle connections.
     */
    fun cleanup(): Int {
        val before = connections.size
        val iter = connections.entries.iterator()
        while (iter.hasNext()) {
            val conn = iter.next().value
            if (conn.isClosed || conn.isIdle) {
                Log.d(TAG, "Cleaning up ${conn.flowKey} (closed=${conn.isClosed}, idle=${conn.isIdle})")
                iter.remove()
            }
        }
        val removed = before - connections.size
        if (removed > 0) {
            Log.d(TAG, "Cleaned up $removed connections (remaining: ${connections.size})")
        }
        return removed
    }

    /**
     * Close and remove all connections.
     */
    fun closeAll() {
        connections.clear()
        Log.d(TAG, "All connections closed")
    }
}
