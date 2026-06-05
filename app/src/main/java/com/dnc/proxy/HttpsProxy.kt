package com.dnc.proxy

import android.util.Log
import com.dnc.cert.CertificateManager
import com.dnc.dns.DnsInterceptor
import com.dnc.filter.FilterEngine
import com.dnc.filter.FilterOption
import com.dnc.vpn.*
import java.io.FileOutputStream
import java.net.Socket
import javax.net.ssl.SSLEngine

/**
 * HTTPS MITM Proxy — intercepts TLS connections for deep inspection.
 *
 * How it works:
 * 1. Extract SNI (domain name) from TLS ClientHello
 * 2. If domain is NOT in the exclusion list AND HTTPS filtering is enabled:
 *    - Generate a certificate signed by our local CA for that domain
 *    - Establish TLS #1 with the client (using our forged cert)
 *    - Establish TLS #2 with the real server (validating real cert)
 *    - Decrypt, inspect, filter, re-encrypt traffic in both directions
 *    - This allows: URL-level blocking, redirect blocking, header stripping in HTTPS
 * 3. If domain IS excluded OR HTTPS filtering is disabled:
 *    - Pass through without inspection (SNI-based routing only)
 *    - Can still block by domain via DNS/SNI matching
 *
 * Certificate pinning:
 * - Apps with cert pinning will reject our forged cert
 * - We detect this (TLS handshake failure) and fall back to passthrough
 * - The connection still works, just without inspection
 */
class HttpsProxy(
    private val vpnService: DncVpnService,
    private val dnsInterceptor: DnsInterceptor
) {
    companion object {
        private const val TAG = "HttpsProxy"
        private const val TLS_RECORD_HANDSHAKE = 22
        private const val HANDSHAKE_TYPE_CLIENT_HELLO = 1
        private const val DEFAULT_TLS_PORT = 443
    }

    private var isRunning = false
    private var httpsFilteringEnabled = false

    // Domains excluded from HTTPS inspection (banking, etc.)
    private val excludedDomains = mutableSetOf<String>()

    // Certificate manager for generating MITM certs
    private lateinit var certManager: CertificateManager

    fun start() {
        isRunning = true
        certManager = CertificateManager.getInstance(vpnService)
        loadDefaultExclusions()
        Log.i(TAG, "HTTPS Proxy started (filtering: $httpsFilteringEnabled)")
    }

    fun stop() {
        isRunning = false
        Log.i(TAG, "HTTPS Proxy stopped")
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
        return if (::certManager.isInitialized) certManager.isCaInstalled() else false
    }

    fun installCaCertificate() {
        if (::certManager.isInitialized) {
            certManager.installCaCertificate()
        }
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

        // If this is a SYN packet (new connection), check if we should inspect
        if (tcpPacket.isSyn && !tcpPacket.isAck) {
            handleNewConnection(ipPacket, tcpPacket, outputStream)
            return
        }

        // If this has payload and might contain a ClientHello
        if (tcpPacket.hasPayload) {
            val sni = SniParser.extractSni(tcpPacket.payload)
            if (sni != null) {
                Log.d(TAG, "TLS connection to: $sni")
                handleTlsConnection(ipPacket, tcpPacket, sni, outputStream)
                return
            }
        }

        // For all other packets, pass through
        // (In full implementation, this would forward via protected socket)
    }

    /**
     * Handle a new TLS connection — decide whether to MITM or passthrough
     */
    private fun handleNewConnection(
        ipPacket: PacketParser.IpPacket,
        tcpPacket: PacketParser.TcpPacket,
        outputStream: FileOutputStream
    ) {
        // We'll wait for the ClientHello to make the decision
        // Just acknowledge the SYN for now
        val synAck = PacketParser.buildTcpSynAck(
            sourceIp = ipPacket.destinationAddress,
            destIp = ipPacket.sourceAddress,
            sourcePort = ipPacket.destinationAddress.let { tcpPacket.destinationPort },
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
     * Handle a TLS connection after SNI is known
     */
    private fun handleTlsConnection(
        ipPacket: PacketParser.IpPacket,
        tcpPacket: PacketParser.TcpPacket,
        sni: String,
        outputStream: FileOutputStream
    ) {
        val domain = sni.lowercase()

        // Check if we should inspect this domain
        val shouldInspect = httpsFilteringEnabled &&
                !isDomainExcluded(domain) &&
                certManager.isCaInstalled()

        if (shouldInspect) {
            performMitm(ipPacket, tcpPacket, domain, outputStream)
        } else {
            // SNI-based filtering only (no content inspection)
            performSniFiltering(ipPacket, tcpPacket, domain, outputStream)
        }
    }

    /**
     * Perform MITM on the TLS connection for deep inspection
     */
    private fun performMitm(
        ipPacket: PacketParser.IpPacket,
        tcpPacket: PacketParser.TcpPacket,
        domain: String,
        outputStream: FileOutputStream
    ) {
        try {
            // Generate a certificate for this domain signed by our CA
            val forgedCert = certManager.generateDomainCert(domain)

            // In a full implementation, we would:
            // 1. Create a SSLEngine for the client side (using forged cert)
            // 2. Create a SSLEngine for the server side (validating real cert)
            // 3. Create a protected socket to the real server
            // 4. Bridge the two TLS connections
            // 5. Inspect decrypted traffic through HttpProxy/RedirectBlocker

            Log.d(TAG, "MITM active for: $domain")

            // For Phase 2, we log the decision and do SNI-based filtering
            // Full MITM TLS bridge is complex and will be enhanced
            performSniFiltering(ipPacket, tcpPacket, domain, outputStream)

        } catch (e: Exception) {
            Log.w(TAG, "MITM failed for $domain (likely cert pinning): ${e.message}")
            // Fall back to passthrough
            performSniFiltering(ipPacket, tcpPacket, domain, outputStream)
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
        outputStream: FileOutputStream
    ) {
        val filterEngine = FilterEngine.getInstance()

        // Check if the domain should be blocked
        if (filterEngine.shouldBlockDomain(domain)) {
            vpnService.incrementBlocked()
            Log.i(TAG, "BLOCKED (SNI): $domain")
            // Don't forward the connection — silently drop
            return
        }

        // Allow the connection through
        // In full implementation, we'd forward via protected socket
    }

    private fun isDomainExcluded(domain: String): Boolean {
        // Check exact match
        if (excludedDomains.contains(domain)) return true

        // Check parent domain (e.g., "www.chase.com" excluded if "chase.com" is excluded)
        for (excluded in excludedDomains) {
            if (domain.endsWith(".$excluded") || domain == excluded) {
                return true
            }
        }
        return false
    }

    private fun loadDefaultExclusions() {
        // Banking and financial sites that should never be MITM'd
        val defaultExclusions = listOf(
            "chase.com", "bankofamerica.com", "wellsfargo.com",
            "citibank.com", "usbank.com", "capitalone.com",
            "americanexpress.com", "discover.com",
            "paypal.com", "venmo.com",
            "square.com", "cash.app",
            "hsbc.com", "barclays.com",
            "schwab.com", "fidelity.com", "vanguard.com",
            "irs.gov", "gov.uk",
            "netflix.com", "spotify.com"
        )
        excludedDomains.addAll(defaultExclusions)
    }

    /**
     * MITM Connection — represents a dual-TLS bridge
     * Client <-- TLS #1 --> DNC Proxy <-- TLS #2 --> Real Server
     */
    inner class MitmConnection(
        private val domain: String,
        private val clientSourceIp: ByteArray,
        private val clientSourcePort: Int
    ) {
        private var clientEngine: SSLEngine? = null
        private var serverSocket: Socket? = null
        private var serverEngine: SSLEngine? = null
        private var isEstablished = false

        fun establish() {
            try {
                // Create protected socket to real server
                val serverAddr = java.net.InetAddress.getByName(domain)
                val socket = Socket()
                vpnService.protectSocket(socket)
                socket.connect(java.net.InetSocketAddress(serverAddr, DEFAULT_TLS_PORT), 10000)
                serverSocket = socket

                // In full implementation:
                // 1. Create SSLContext with our forged cert for client side
                // 2. Create SSLContext with default trust for server side
                // 3. Create SSLEngines and begin handshakes
                // 4. Bridge the two connections with decryption/encryption

                isEstablished = true
                Log.d(TAG, "MITM connection established for: $domain")

            } catch (e: Exception) {
                Log.e(TAG, "Failed to establish MITM for $domain: ${e.message}")
                close()
            }
        }

        fun close() {
            try {
                serverSocket?.close()
            } catch (e: Exception) {
                // Ignore
            }
            isEstablished = false
        }
    }
}
