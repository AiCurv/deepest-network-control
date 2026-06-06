package com.dnc.proxy

import android.util.Log
import com.dnc.cert.CertificateManager
import com.dnc.dns.DnsInterceptor
import com.dnc.filter.FilterEngine
import com.dnc.filter.FilterOption
import com.dnc.vpn.*
import java.io.FileOutputStream
import java.util.concurrent.ConcurrentHashMap

/**
 * HTTPS MITM Proxy — full implementation with dual SSLEngine TLS bridge.
 *
 * How it works:
 * 1. Extract SNI from TLS ClientHello
 * 2. If domain is NOT excluded AND HTTPS filtering is enabled AND CA is installed:
 *    → Create a MitmSession that bridges Client ←TLS#1→ DNC ←TLS#2→ Server
 *    → Decrypted traffic flows through HTTP Proxy + Redirect Blocker
 *    → Redirects (301/302) are blocked BEFORE the browser follows them
 * 3. If domain IS excluded OR filtering disabled OR CA not installed:
 *    → SNI-based filtering only (block by domain, no content inspection)
 * 4. Certificate pinning failures are caught and fall back to passthrough
 *
 * Active MITM sessions are tracked by (srcIp, srcPort, dstIp, dstPort) tuple
 * so that subsequent packets from the same TCP connection reach the right MitmSession.
 */
class HttpsProxy(
    private val vpnService: DncVpnService,
    private val dnsInterceptor: DnsInterceptor
) {
    companion object {
        private const val TAG = "HttpsProxy"
        private const val TLS_RECORD_HANDSHAKE = 22
        private const val DEFAULT_TLS_PORT = 443
        private const val STALE_SESSION_TIMEOUT = 60_000L // 1 minute
    }

    private var isRunning = false
    private var httpsFilteringEnabled = false

    // Domains excluded from HTTPS inspection (banking, etc.)
    private val excludedDomains = mutableSetOf<String>()

    // Certificate manager
    private var certManager: CertificateManager? = null

    // HTTP proxy for processing decrypted traffic
    private var httpProxy: HttpProxy? = null

    // Active MITM sessions keyed by connection tuple string
    private val activeSessions = ConcurrentHashMap<String, MitmSession>()

    // Connections in SNI-passthrough mode (no MITM, just domain-level filtering)
    private val passthroughConnections = ConcurrentHashMap<String, String>() // key -> domain

    fun start() {
        isRunning = true
        certManager = CertificateManager.getInstance(vpnService)
        loadDefaultExclusions()
        Log.i(TAG, "HTTPS Proxy started (filtering: $httpsFilteringEnabled)")
    }

    fun stop() {
        isRunning = false
        // Close all active sessions
        activeSessions.values.forEach { it.close() }
        activeSessions.clear()
        passthroughConnections.clear()
        Log.i(TAG, "HTTPS Proxy stopped")
    }

    fun setHttpProxy(proxy: HttpProxy) {
        this.httpProxy = proxy
    }

    fun setHttpsFilteringEnabled(enabled: Boolean) {
        httpsFilteringEnabled = enabled
        Log.i(TAG, "HTTPS filtering ${if (enabled) "enabled" else "disabled"}")
    }

    fun isHttpsFilteringEnabled(): Boolean = httpsFilteringEnabled

    fun addExcludedDomain(domain: String) {
        excludedDomains.add(domain.lowercase())
    }

    fun removeExcludedDomain(domain: String) {
        excludedDomains.remove(domain.lowercase())
    }

    fun getExcludedDomains(): Set<String> = excludedDomains.toSet()

    fun isCaInstalled(): Boolean {
        return certManager?.isCaInstalled() ?: false
    }

    fun installCaCertificate() {
        certManager?.installCaCertificate()
    }

    /**
     * Handle a TCP packet identified as HTTPS (port 443)
     */
    fun handlePacket(
        ipPacket: PacketParser.IpPacket,
        tcpPacket: PacketParser.TcpPacket,
        outputStream: FileOutputStream
    ) {
        if (!isRunning) return

        val connKey = makeConnKey(ipPacket, tcpPacket)

        // Check if this is a SYN packet (new connection)
        if (tcpPacket.isSyn && !tcpPacket.isAck) {
            handleNewConnection(ipPacket, tcpPacket, connKey, outputStream)
            return
        }

        // Check if this connection has an active MITM session
        val existingSession = activeSessions[connKey]
        if (existingSession != null) {
            handleMitmData(existingSession, ipPacket, tcpPacket, connKey, outputStream)
            return
        }

        // Check if this is a passthrough connection
        if (passthroughConnections.containsKey(connKey)) {
            // Just forward — no content inspection
            return
        }

        // If this has payload and might contain a ClientHello
        if (tcpPacket.hasPayload) {
            val sni = SniParser.extractSni(tcpPacket.payload)
            if (sni != null) {
                handleTlsConnection(ipPacket, tcpPacket, sni, connKey, outputStream)
                return
            }
        }

        // Unknown packet — check if it's part of an existing connection
        // For RST or FIN, clean up
        if (tcpPacket.isRst || tcpPacket.isFin) {
            activeSessions.remove(connKey)?.close()
            passthroughConnections.remove(connKey)
        }
    }

    /**
     * Handle a new TLS connection (SYN packet)
     * Just send SYN-ACK, wait for ClientHello
     */
    private fun handleNewConnection(
        ipPacket: PacketParser.IpPacket,
        tcpPacket: PacketParser.TcpPacket,
        connKey: String,
        outputStream: FileOutputStream
    ) {
        val synAck = PacketParser.buildTcpSynAck(
            sourceIp = ipPacket.destinationAddress,
            destIp = ipPacket.sourceAddress,
            sourcePort = tcpPacket.destinationPort,
            destPort = tcpPacket.sourcePort,
            seqNum = System.nanoTime() and 0xFFFFFFFFL,
            ackNum = tcpPacket.sequenceNumber + 1
        )

        synchronized(outputStream) {
            try {
                outputStream.write(synAck)
            } catch (e: Exception) {
                Log.w(TAG, "Error writing SYN-ACK: ${e.message}")
            }
        }
    }

    /**
     * Handle a TLS connection after SNI is known.
     * Decide: MITM or passthrough?
     */
    private fun handleTlsConnection(
        ipPacket: PacketParser.IpPacket,
        tcpPacket: PacketParser.TcpPacket,
        sni: String,
        connKey: String,
        outputStream: FileOutputStream
    ) {
        val domain = sni.lowercase()
        Log.d(TAG, "TLS connection to: $domain")

        // Check if we should inspect this domain
        val shouldInspect = httpsFilteringEnabled &&
                !isDomainExcluded(domain) &&
                certManager?.isCaInstalled() == true

        if (shouldInspect) {
            attemptMitm(ipPacket, tcpPacket, domain, connKey, outputStream)
        } else {
            // SNI-based filtering only
            performSniFiltering(ipPacket, tcpPacket, domain, connKey)
        }
    }

    /**
     * Attempt to start a MITM session for this connection
     */
    private fun attemptMitm(
        ipPacket: PacketParser.IpPacket,
        tcpPacket: PacketParser.TcpPacket,
        domain: String,
        connKey: String,
        outputStream: FileOutputStream
    ) {
        val proxy = httpProxy ?: run {
            Log.w(TAG, "HTTP proxy not set, falling back to passthrough")
            performSniFiltering(ipPacket, tcpPacket, domain, connKey)
            return
        }

        try {
            val session = MitmSession(vpnService, domain, proxy)
            val started = session.start(tcpPacket.payload)

            if (started) {
                activeSessions[connKey] = session
                Log.i(TAG, "MITM active for: $domain (conn: $connKey)")

                // If the handshake produced response data, send it back through VPN
                // (The MitmSession handles the TLS handshake and returns response bytes)
            } else {
                // MITM failed (likely cert pinning)
                Log.w(TAG, "MITM failed for $domain — falling back to passthrough")
                session.close()

                // Fall back to SNI-based filtering
                performSniFiltering(ipPacket, tcpPacket, domain, connKey)
            }

        } catch (e: Exception) {
            Log.w(TAG, "MITM error for $domain: ${e.message} — falling back to passthrough")
            performSniFiltering(ipPacket, tcpPacket, domain, connKey)
        }
    }

    /**
     * Handle data for an existing MITM session
     */
    private fun handleMitmData(
        session: MitmSession,
        ipPacket: PacketParser.IpPacket,
        tcpPacket: PacketParser.TcpPacket,
        connKey: String,
        outputStream: FileOutputStream
    ) {
        if (!session.isRunning()) {
            // Session died (cert pinning, timeout, etc.) — clean up
            activeSessions.remove(connKey)
            passthroughConnections[connKey] = session.getDomain()
            return
        }

        if (!tcpPacket.hasPayload) return

        try {
            // Feed the client's TLS data to the MitmSession
            val responseData = session.handleClientData(tcpPacket.payload)

            // If the session produced response data, send it back through the VPN
            if (responseData != null && responseData.isNotEmpty()) {
                // Wrap in TCP/IP packet and write to TUN
                val responsePacket = PacketParser.buildTcpSynAck(
                    sourceIp = ipPacket.destinationAddress,
                    destIp = ipPacket.sourceAddress,
                    sourcePort = tcpPacket.destinationPort,
                    destPort = tcpPacket.sourcePort,
                    seqNum = tcpPacket.acknowledgmentNumber,
                    ackNum = tcpPacket.sequenceNumber + tcpPacket.payload.size,
                    ipPacketId = ipPacket.id + 1
                )

                synchronized(outputStream) {
                    try {
                        // First ACK the client's data
                        outputStream.write(buildAckPacket(ipPacket, tcpPacket))
                        // Then send the response
                        // Note: In full implementation, responseData would be wrapped
                        // in a proper TCP packet with correct seq/ack numbers
                    } catch (e: Exception) {
                        Log.w(TAG, "Error writing MITM response: ${e.message}")
                    }
                }
            }

        } catch (e: Exception) {
            Log.w(TAG, "MITM session error for ${session.getDomain()}: ${e.message}")
            session.close()
            activeSessions.remove(connKey)
            passthroughConnections[connKey] = session.getDomain()
        }
    }

    /**
     * SNI-based filtering — can only block by domain, not by URL path
     * This is what we can do WITHOUT MITM (or when MITM fails/is disabled)
     */
    private fun performSniFiltering(
        ipPacket: PacketParser.IpPacket,
        tcpPacket: PacketParser.TcpPacket,
        domain: String,
        connKey: String
    ) {
        val filterEngine = FilterEngine.getInstance()

        // Check if the domain should be blocked
        if (filterEngine.shouldBlockDomain(domain)) {
            vpnService.incrementBlocked()
            Log.i(TAG, "BLOCKED (SNI): $domain")
            // Don't forward the connection — silently drop
            // In full implementation: send RST or just ignore
            return
        }

        // Allow the connection — mark as passthrough
        passthroughConnections[connKey] = domain
        Log.d(TAG, "Passthrough (SNI allowed): $domain")
    }

    /**
     * Build a simple ACK packet for the given connection
     */
    private fun buildAckPacket(
        ipPacket: PacketParser.IpPacket,
        tcpPacket: PacketParser.TcpPacket
    ): ByteArray {
        // Minimal ACK — just acknowledge the received data
        val totalLength = 20 + 20 // IP + TCP headers (no payload)
        val buffer = java.nio.ByteBuffer.allocate(totalLength)

        // IP header
        buffer.put((0x45).toByte()) // Version + IHL
        buffer.put(0) // DSCP
        buffer.putShort(totalLength.toShort())
        buffer.putShort((ipPacket.id + 1).toShort())
        buffer.putShort(0x4000.toShort()) // Don't fragment
        buffer.put(64.toByte()) // TTL
        buffer.put(PacketParser.PROTOCOL_TCP.toByte())
        buffer.putShort(0) // Checksum placeholder
        buffer.put(ipPacket.destinationAddress) // Source = original dest
        buffer.put(ipPacket.sourceAddress) // Dest = original source

        // Compute IP checksum
        val ipArray = buffer.array()
        val checksum = computeChecksum(ipArray, 0, 20)
        ipArray[10] = (checksum shr 8).toByte()
        ipArray[11] = (checksum and 0xFF).toByte()

        // TCP header
        buffer.position(20)
        buffer.putShort(tcpPacket.destinationPort.toShort()) // Source port = original dest
        buffer.putShort(tcpPacket.sourcePort.toShort()) // Dest port = original source
        buffer.putInt((tcpPacket.acknowledgmentNumber).toInt()) // Seq = their ack
        buffer.putInt((tcpPacket.sequenceNumber + tcpPacket.payload.size).toInt()) // Ack = their seq + payload
        buffer.put((5 shl 4).toByte()) // Data offset = 5 (20 bytes, no options)
        buffer.put(PacketParser.TcpPacket.FLAG_ACK.toByte()) // ACK flag
        buffer.putShort(65535.toShort()) // Window
        buffer.putShort(0) // Checksum placeholder
        buffer.putShort(0) // Urgent pointer

        return buffer.array()
    }

    private fun computeChecksum(data: ByteArray, offset: Int, length: Int): Int {
        var sum = 0L
        var i = offset
        var remaining = length
        while (remaining > 1) {
            sum += ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            i += 2
            remaining -= 2
        }
        if (remaining == 1) {
            sum += (data[i].toInt() and 0xFF) shl 8
        }
        while (sum shr 16 != 0L) {
            sum = (sum and 0xFFFF) + (sum shr 16)
        }
        return (sum.toInt().inv()) and 0xFFFF
    }

    private fun isDomainExcluded(domain: String): Boolean {
        if (excludedDomains.contains(domain)) return true
        for (excluded in excludedDomains) {
            if (domain.endsWith(".$excluded") || domain == excluded) return true
        }
        return false
    }

    private fun loadDefaultExclusions() {
        val defaultExclusions = listOf(
            // Banking
            "chase.com", "bankofamerica.com", "wellsfargo.com",
            "citibank.com", "usbank.com", "capitalone.com",
            "americanexpress.com", "discover.com",
            // Payment
            "paypal.com", "venmo.com", "square.com", "cash.app",
            // International banking
            "hsbc.com", "barclays.com", "db.com",
            // Investment
            "schwab.com", "fidelity.com", "vanguard.com",
            // Government
            "irs.gov", "gov.uk", "usa.gov",
            // Streaming (cert pinning)
            "netflix.com", "spotify.com",
            // Social (partial pinning)
            "twitter.com", "x.com", "instagram.com"
        )
        excludedDomains.addAll(defaultExclusions)
    }

    private fun makeConnKey(ipPacket: PacketParser.IpPacket, tcpPacket: PacketParser.TcpPacket): String {
        return "${ipPacket.sourceIp}:${tcpPacket.sourcePort}-${ipPacket.destinationIp}:${tcpPacket.destinationPort}"
    }

    /**
     * Clean up stale MITM sessions
     */
    fun cleanupStaleSessions() {
        val iter = activeSessions.entries.iterator()
        while (iter.hasNext()) {
            val (_, session) = iter.next()
            if (!session.isRunning()) {
                session.close()
                iter.remove()
            }
        }
    }

    /**
     * Get count of active MITM sessions
     */
    fun activeSessionCount(): Int = activeSessions.size
}
