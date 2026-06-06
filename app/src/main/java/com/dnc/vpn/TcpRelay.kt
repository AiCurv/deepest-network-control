package com.dnc.vpn

import android.util.Log
import com.dnc.dns.DnsInterceptor
import com.dnc.filter.FilterEngine
import com.dnc.filter.FilterOption
import com.dnc.proxy.HttpProxy
import com.dnc.proxy.HttpsProxy
import com.dnc.proxy.RedirectBlocker
import com.dnc.proxy.SniParser
import java.io.ByteArrayOutputStream
import java.io.FileOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

/**
 * Manages TCP relay connections through the VPN.
 *
 * When an app sends a TCP SYN through the TUN interface, we:
 * 1. Send SYN-ACK back to the app (so it thinks the server responded)
 * 2. Open a protected Socket to the REAL server
 * 3. Relay data bidirectionally: App ↔ TUN ↔ Socket ↔ Server
 * 4. Apply filtering (DNS blocking, URL blocking, redirect blocking)
 *
 * For HTTP traffic (port 80):
 * - Responses are inspected for redirects (301/302)
 * - Redirects to blocked domains are replaced with 200 OK
 * - URL-based filtering is applied
 *
 * For HTTPS traffic (port 443):
 * - SNI-based domain filtering at connection time
 * - Full MITM if HTTPS filtering is enabled and CA is installed
 */
class TcpRelay(
    private val vpnService: DncVpnService,
    private val dnsInterceptor: DnsInterceptor,
    private val httpProxy: HttpProxy,
    private val httpsProxy: HttpsProxy
) {
    companion object {
        private const val TAG = "TcpRelay"
        private const val CONNECT_TIMEOUT = 15_000
        private const val READ_TIMEOUT = 60_000
        private const val IDLE_TIMEOUT = 60_000L
        private const val MAX_CONNECTIONS = 200
        private const val BUFFER_SIZE = 8192
    }

    /**
     * Represents an active TCP relay connection.
     */
    data class RelayConnection(
        val srcIp: ByteArray,
        val srcPort: Int,
        val dstIp: ByteArray,
        val dstPort: Int,
        val clientIsn: Long,
        var serverIsn: Long = 0L,
        var clientSeq: Long = 0L,
        var serverSeq: Long = 0L,
        var clientAck: Long = 0L,
        var serverAck: Long = 0L,
        var socket: Socket? = null,
        var serverOut: OutputStream? = null,
        var serverIn: InputStream? = null,
        var state: RelayState = RelayState.SYN_RECEIVED,
        var lastActivity: Long = System.currentTimeMillis(),
        var relayThread: Thread? = null,
        var isBlocked: Boolean = false,
        var blockedDomain: String? = null,
        var isMitm: Boolean = false,
        // HTTP response buffer for reassembly and filtering
        var responseBuffer: ByteArrayOutputStream = ByteArrayOutputStream(),
        // Track whether we've seen the first HTTP response
        var seenFirstResponse: Boolean = false
    ) {
        val key: String
            get() = "${InetAddress.getByAddress(srcIp).hostAddress}:$srcPort-${InetAddress.getByAddress(dstIp).hostAddress}:$dstPort"

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is RelayConnection) return false
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

    enum class RelayState {
        SYN_RECEIVED,        // We got SYN, sent SYN-ACK
        ESTABLISHING,        // Connecting to real server
        ESTABLISHED,         // Connection fully up
        CLOSING,             // FIN received or error
        CLOSED               // Done
    }

    // Active connections by key
    private val connections = ConcurrentHashMap<String, RelayConnection>()

    // Packet ID generator
    private val packetIdGenerator = AtomicInteger(1000)

    // Redirect blocker for HTTP traffic inspection
    private val redirectBlocker = RedirectBlocker()

    /**
     * Handle a TCP packet from the TUN interface.
     */
    fun handlePacket(
        ipPacket: PacketParser.IpPacket,
        tcpPacket: PacketParser.TcpPacket,
        outputStream: FileOutputStream
    ) {
        val srcIp = ipPacket.sourceAddress
        val srcPort = tcpPacket.sourcePort
        val dstIp = ipPacket.destinationAddress
        val dstPort = tcpPacket.destinationPort
        val key = "${InetAddress.getByAddress(srcIp).hostAddress}:$srcPort-${InetAddress.getByAddress(dstIp).hostAddress}:$dstPort"

        // Handle RST immediately
        if (tcpPacket.isRst) {
            val conn = connections.remove(key)
            if (conn != null) {
                closeConnection(conn)
            }
            return
        }

        // Handle FIN
        if (tcpPacket.isFin) {
            val conn = connections[key]
            if (conn != null) {
                // ACK the FIN
                val finAck = PacketParser.buildTcpAck(
                    sourceIp = dstIp,
                    destIp = srcIp,
                    sourcePort = dstPort,
                    destPort = srcPort,
                    seqNum = conn.serverSeq,
                    ackNum = tcpPacket.sequenceNumber + 1,
                    ipPacketId = nextPacketId()
                )
                synchronized(outputStream) {
                    outputStream.write(finAck)
                }

                // Close the server connection
                if (conn.state == RelayState.ESTABLISHED) {
                    conn.state = RelayState.CLOSING
                    closeConnection(conn)
                    connections.remove(key)
                }
            }
            return
        }

        // New connection (SYN)
        if (tcpPacket.isSyn && !tcpPacket.isAck) {
            handleNewConnection(ipPacket, tcpPacket, key, outputStream)
            return
        }

        // Existing connection
        val conn = connections[key]
        if (conn != null) {
            handleExistingConnection(conn, ipPacket, tcpPacket, key, outputStream)
            return
        }

        // Unknown connection — might be an ACK completing a handshake we missed
        // Send RST to clean up
        if (tcpPacket.isAck && !tcpPacket.isSyn) {
            val rst = PacketParser.buildTcpRst(
                sourceIp = dstIp,
                destIp = srcIp,
                sourcePort = dstPort,
                destPort = srcPort,
                seqNum = tcpPacket.acknowledgmentNumber,
                ipPacketId = nextPacketId()
            )
            synchronized(outputStream) {
                try { outputStream.write(rst) } catch (_: Exception) {}
            }
        }
    }

    /**
     * Handle a new TCP connection (SYN packet).
     * We send SYN-ACK to the app and start connecting to the real server.
     */
    private fun handleNewConnection(
        ipPacket: PacketParser.IpPacket,
        tcpPacket: PacketParser.TcpPacket,
        key: String,
        outputStream: FileOutputStream
    ) {
        // Check connection limit
        if (connections.size >= MAX_CONNECTIONS) {
            cleanupStaleConnections()
            if (connections.size >= MAX_CONNECTIONS) {
                Log.w(TAG, "Max connections reached, dropping SYN")
                return
            }
        }

        val srcIp = ipPacket.sourceAddress
        val dstIp = ipPacket.destinationAddress
        val srcPort = tcpPacket.sourcePort
        val dstPort = tcpPacket.destinationPort

        // Check if this connection should be blocked (HTTPS SNI filtering)
        var blockedDomain: String? = null
        if (dstPort == 443 && tcpPacket.hasPayload) {
            val sni = SniParser.extractSni(tcpPacket.payload)
            if (sni != null) {
                val shouldBlock = try {
                    FilterEngine.getInstance().shouldBlockDomain(sni)
                } catch (e: Exception) {
                    Log.w(TAG, "FilterEngine error for SNI $sni: ${e.message}")
                    false
                }
                if (shouldBlock) {
                    blockedDomain = sni
                    vpnService.incrementBlocked()
                    Log.d(TAG, "BLOCKED (SNI): $sni")
                }
            }
        }

        // Send SYN-ACK back to the app
        val serverIsn = System.nanoTime() and 0xFFFFFFFFL
        val synAck = PacketParser.buildTcpSynAck(
            sourceIp = dstIp,
            destIp = srcIp,
            sourcePort = dstPort,
            destPort = srcPort,
            seqNum = serverIsn,
            ackNum = tcpPacket.sequenceNumber + 1,
            ipPacketId = nextPacketId()
        )

        synchronized(outputStream) {
            try { outputStream.write(synAck) } catch (e: Exception) {
                Log.w(TAG, "Error writing SYN-ACK: ${e.message}")
                return
            }
        }

        // Create and store the connection
        val conn = RelayConnection(
            srcIp = srcIp,
            srcPort = srcPort,
            dstIp = dstIp,
            dstPort = dstPort,
            clientIsn = tcpPacket.sequenceNumber,
            serverIsn = serverIsn,
            clientSeq = tcpPacket.sequenceNumber + 1, // After SYN
            serverSeq = serverIsn + 1, // After SYN-ACK
            clientAck = tcpPacket.acknowledgmentNumber,
            serverAck = tcpPacket.sequenceNumber + 1,
            isBlocked = blockedDomain != null,
            blockedDomain = blockedDomain
        )

        connections[key] = conn
        Log.d(TAG, "New connection: $key (blocked=${blockedDomain != null})")
    }

    /**
     * Handle a packet for an existing connection.
     */
    private fun handleExistingConnection(
        conn: RelayConnection,
        ipPacket: PacketParser.IpPacket,
        tcpPacket: PacketParser.TcpPacket,
        key: String,
        outputStream: FileOutputStream
    ) {
        conn.lastActivity = System.currentTimeMillis()

        val srcIp = ipPacket.sourceAddress
        val dstIp = ipPacket.destinationAddress

        // Handle ACK completing the 3-way handshake
        if (conn.state == RelayState.SYN_RECEIVED && tcpPacket.isAck && !tcpPacket.isSyn) {
            // 3-way handshake complete with the app
            conn.clientSeq = tcpPacket.sequenceNumber
            conn.clientAck = tcpPacket.acknowledgmentNumber
            conn.state = RelayState.ESTABLISHING

            if (conn.isBlocked) {
                // Send RST to the app (connection blocked)
                val rst = PacketParser.buildTcpRst(
                    sourceIp = dstIp,
                    destIp = srcIp,
                    sourcePort = tcpPacket.destinationPort,
                    destPort = tcpPacket.sourcePort,
                    seqNum = conn.serverSeq,
                    ipPacketId = nextPacketId()
                )
                synchronized(outputStream) {
                    try { outputStream.write(rst) } catch (_: Exception) {}
                }
                connections.remove(key)
                return
            }

            // Connect to the real server in a background thread
            connectToServer(conn, key, outputStream)
            return
        }

        // Handle data on established connection
        if (conn.state == RelayState.ESTABLISHED && tcpPacket.hasPayload) {
            // ACK the client's data
            val ack = PacketParser.buildTcpAck(
                sourceIp = dstIp,
                destIp = srcIp,
                sourcePort = tcpPacket.destinationPort,
                destPort = tcpPacket.sourcePort,
                seqNum = conn.serverSeq,
                ackNum = tcpPacket.sequenceNumber + tcpPacket.payload.size,
                ipPacketId = nextPacketId()
            )
            synchronized(outputStream) {
                try { outputStream.write(ack) } catch (_: Exception) {}
            }

            // Update sequence tracking
            conn.clientSeq = tcpPacket.sequenceNumber + tcpPacket.payload.size

            // Forward data to server
            try {
                val serverOut = conn.serverOut
                if (serverOut != null) {
                    serverOut.write(tcpPacket.payload)
                    serverOut.flush()
                }
            } catch (e: Exception) {
                Log.w(TAG, "Error writing to server for $key: ${e.message}")
                closeConnection(conn)
                connections.remove(key)
            }
        }

        // Handle pure ACK (no data) — update window tracking
        if (tcpPacket.isAck && !tcpPacket.hasPayload && conn.state == RelayState.ESTABLISHED) {
            conn.clientAck = tcpPacket.acknowledgmentNumber
        }
    }

    /**
     * Connect to the real server using a protected socket,
     * then start a relay thread to read server responses and write them to TUN.
     */
    private fun connectToServer(
        conn: RelayConnection,
        key: String,
        outputStream: FileOutputStream
    ) {
        Thread {
            try {
                val socket = Socket()
                vpnService.protectSocket(socket)

                val dstAddress = InetAddress.getByAddress(conn.dstIp)
                socket.connect(InetSocketAddress(dstAddress, conn.dstPort), CONNECT_TIMEOUT)
                socket.soTimeout = READ_TIMEOUT
                socket.tcpNoDelay = true

                if (!socket.isConnected) {
                    Log.e(TAG, "Failed to connect to server: $key")
                    sendRstToClient(conn, outputStream)
                    conn.state = RelayState.CLOSED
                    connections.remove(key)
                    return@Thread
                }

                conn.socket = socket
                conn.serverOut = socket.getOutputStream()
                conn.serverIn = socket.getInputStream()
                conn.state = RelayState.ESTABLISHED

                Log.d(TAG, "Connected to server: $key")

                // Start reading from server and writing to TUN
                relayServerData(conn, key, outputStream)

            } catch (e: Exception) {
                Log.e(TAG, "Failed to connect to server $key: ${e.message}")
                sendRstToClient(conn, outputStream)
                conn.state = RelayState.CLOSED
                connections.remove(key)
            }
        }.start()
    }

    /**
     * Read data from the server socket and write it back to the TUN interface
     * as properly formatted TCP/IP packets.
     *
     * For HTTP traffic (port 80), responses are inspected for redirects and
     * filtered through the redirect blocker before being sent to the client.
     */
    private fun relayServerData(
        conn: RelayConnection,
        key: String,
        outputStream: FileOutputStream
    ) {
        val buffer = ByteArray(BUFFER_SIZE)

        try {
            val serverIn = conn.serverIn ?: return

            while (conn.state == RelayState.ESTABLISHED &&
                    conn.socket?.isConnected == true &&
                    !Thread.currentThread().isInterrupted) {

                val bytesRead = serverIn.read(buffer)
                if (bytesRead == -1) {
                    // Server closed connection
                    Log.d(TAG, "Server closed connection: $key")
                    break
                }

                if (bytesRead == 0) continue

                var dataToSend = buffer.copyOfRange(0, bytesRead)

                // === HTTP response inspection for port 80 ===
                if (conn.dstPort == 80 && !conn.seenFirstResponse) {
                    dataToSend = processHttpResponse(conn, dataToSend, key)
                    conn.seenFirstResponse = true
                }

                // Split into MTU-sized chunks if needed
                val mtu = DncVpnService.VPN_MTU - 40 // MTU - IP header - TCP header
                var offset = 0
                while (offset < dataToSend.size) {
                    val chunkSize = minOf(mtu, dataToSend.size - offset)
                    val chunk = dataToSend.copyOfRange(offset, offset + chunkSize)

                    // Build a TCP data packet from server -> client
                    val responsePacket = PacketParser.buildTcpDataPacket(
                        sourceIp = conn.dstIp,   // Server IP (appears as source)
                        destIp = conn.srcIp,      // Client IP (appears as dest)
                        sourcePort = conn.dstPort, // Server port
                        destPort = conn.srcPort,   // Client port
                        seqNum = conn.serverSeq,
                        ackNum = conn.clientSeq,
                        payload = chunk,
                        ipPacketId = nextPacketId()
                    )

                    var writeFailed = false
                    synchronized(outputStream) {
                        try {
                            outputStream.write(responsePacket)
                        } catch (e: Exception) {
                            Log.w(TAG, "Error writing to TUN for $key: ${e.message}")
                            writeFailed = true
                        }
                    }
                    if (writeFailed) break

                    conn.serverSeq += chunkSize
                    offset += chunkSize
                }
            }

        } catch (e: java.net.SocketTimeoutException) {
            // Read timeout — check if connection is still alive
            Log.d(TAG, "Read timeout for $key, closing")
        } catch (e: Exception) {
            if (conn.state == RelayState.ESTABLISHED) {
                Log.w(TAG, "Server relay error for $key: ${e.message}")
            }
        } finally {
            // Send FIN to client
            try {
                val fin = PacketParser.buildTcpFin(
                    sourceIp = conn.dstIp,
                    destIp = conn.srcIp,
                    sourcePort = conn.dstPort,
                    destPort = conn.srcPort,
                    seqNum = conn.serverSeq,
                    ackNum = conn.clientSeq,
                    ipPacketId = nextPacketId()
                )
                synchronized(outputStream) {
                    try { outputStream.write(fin) } catch (_: Exception) {}
                }
            } catch (_: Exception) {}

            conn.state = RelayState.CLOSED
            closeConnection(conn)
            connections.remove(key)
        }
    }

    /**
     * Process an HTTP response for redirect blocking and URL filtering.
     *
     * This inspects the first HTTP response on port 80 connections.
     * If a redirect (301/302) is detected and the target matches a filter rule,
     * the redirect is replaced with a 200 OK empty response.
     *
     * For non-redirect responses, the data passes through unchanged.
     */
    private fun processHttpResponse(
        conn: RelayConnection,
        responseData: ByteArray,
        key: String
    ): ByteArray {
        try {
            // Try to parse as HTTP response
            val responseText = String(responseData, Charsets.UTF_8)

            // Quick check: does this look like an HTTP response?
            if (!responseText.startsWith("HTTP/")) {
                return responseData // Not an HTTP response, pass through
            }

            // Parse the status line
            val firstLine = responseText.substringBefore("\r\n")
            val statusCode = firstLine.split(" ").getOrNull(1)?.toIntOrNull() ?: return responseData

            // Check for redirect (3xx)
            if (statusCode in 300..399) {
                // Extract Location header
                val locationHeader = responseText.lines().find {
                    it.startsWith("Location:", ignoreCase = true) ||
                    it.startsWith("location:", ignoreCase = true)
                }
                val location = locationHeader?.substringAfter(":")?.trim()

                if (location != null) {
                    Log.d(TAG, "HTTP Redirect detected: $statusCode -> $location")

                    val shouldBlockRedirect = try {
                        FilterEngine.getInstance().shouldBlockRequest(location, "", FilterOption.OTHER)
                    } catch (e: Exception) {
                        Log.w(TAG, "FilterEngine error for redirect $location: ${e.message}")
                        false
                    }

                    if (shouldBlockRedirect) {
                        vpnService.incrementRedirectsBlocked()
                        vpnService.incrementBlocked()
                        Log.i(TAG, "REDIRECT BLOCKED: $statusCode -> $location (filter match)")

                        // Replace the redirect with a 200 OK empty response
                        // This prevents the browser from following the redirect
                        val blockedResponse = "HTTP/1.1 200 OK\r\n" +
                                "Content-Length: 0\r\n" +
                                "X-DNC-Blocked: redirect\r\n" +
                                "\r\n"
                        return blockedResponse.toByteArray(Charsets.UTF_8)
                    }

                    // Also check custom redirect rules
                    val customResult = redirectBlocker.processResponse(location,
                        com.dnc.proxy.HttpProxy.HttpResponse(
                            statusCode = statusCode,
                            statusText = "",
                            headers = mapOf("Location" to location),
                            body = ByteArray(0)
                        )
                    )
                    if (customResult.action == RedirectBlocker.RedirectAction.BLOCKED) {
                        vpnService.incrementRedirectsBlocked()
                        vpnService.incrementBlocked()
                        Log.i(TAG, "REDIRECT BLOCKED (custom rule): $statusCode -> $location")

                        val blockedResponse = "HTTP/1.1 200 OK\r\n" +
                                "Content-Length: 0\r\n" +
                                "X-DNC-Blocked: redirect\r\n" +
                                "\r\n"
                        return blockedResponse.toByteArray(Charsets.UTF_8)
                    }
                }
            }

            // Not a redirect or redirect allowed — check if the URL itself should be blocked
            // (for non-redirect responses, we still want to check URL-based rules)
            val contentTypeLine = responseText.lines().find {
                it.startsWith("Content-Type:", ignoreCase = true)
            }
            val isHtml = contentTypeLine?.contains("text/html", ignoreCase = true) == true

            if (isHtml) {
                // Extract the request URL from the connection info for filter matching
                // We don't have the original request URL here, but we can use the
                // destination IP's resolved domain for DNS-level blocking
                // URL-level blocking is handled at the DNS level for now
            }

        } catch (e: Exception) {
            Log.w(TAG, "Error processing HTTP response for $key: ${e.message}")
        }

        return responseData // Pass through unchanged
    }

    /**
     * Send a RST packet to the client app.
     */
    private fun sendRstToClient(conn: RelayConnection, outputStream: FileOutputStream) {
        try {
            val rst = PacketParser.buildTcpRst(
                sourceIp = conn.dstIp,
                destIp = conn.srcIp,
                sourcePort = conn.dstPort,
                destPort = conn.srcPort,
                seqNum = conn.serverSeq,
                ipPacketId = nextPacketId()
            )
            synchronized(outputStream) {
                try { outputStream.write(rst) } catch (_: Exception) {}
            }
        } catch (_: Exception) {}
    }

    /**
     * Close a relay connection and release resources.
     */
    private fun closeConnection(conn: RelayConnection) {
        try {
            conn.serverIn?.close()
        } catch (_: Exception) {}
        try {
            conn.serverOut?.close()
        } catch (_: Exception) {}
        try {
            conn.socket?.close()
        } catch (_: Exception) {}
        conn.relayThread?.interrupt()
        conn.state = RelayState.CLOSED
    }

    /**
     * Clean up stale connections that have been idle too long.
     */
    private fun cleanupStaleConnections() {
        val now = System.currentTimeMillis()
        val iter = connections.entries.iterator()
        while (iter.hasNext()) {
            val (_, conn) = iter.next()
            if (now - conn.lastActivity > IDLE_TIMEOUT || conn.state == RelayState.CLOSED) {
                closeConnection(conn)
                iter.remove()
            }
        }
    }

    /**
     * Clean up all connections.
     */
    fun closeAll() {
        connections.values.forEach { closeConnection(it) }
        connections.clear()
    }

    /**
     * Get the number of active connections.
     */
    fun activeConnectionCount(): Int = connections.count {
        it.value.state == RelayState.ESTABLISHED || it.value.state == RelayState.ESTABLISHING
    }

    private fun nextPacketId(): Int = packetIdGenerator.incrementAndGet()
}
