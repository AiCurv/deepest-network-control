package com.dnc.dns

import android.util.Log
import com.dnc.vpn.DncVpnService
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.nio.ByteBuffer
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

/**
 * Intercepts DNS queries from the VPN tunnel, filters them against
 * the blocklist, and either returns a blocked response or forwards
 * to the upstream DNS server ASYNCHRONOUSLY.
 *
 * CRITICAL FIXES:
 * - Protected socket return value is checked
 * - Error handling ensures the callback is ALWAYS called
 * - DNS queries to ANY destination IP are handled (not just 10.0.0.1)
 * - Fallback DNS servers if primary fails
 */
class DnsInterceptor(private val vpnService: DncVpnService) {

    companion object {
        private const val TAG = "DnsInterceptor"
        private const val DNS_PORT = 53
        private const val MAX_DNS_PACKET_SIZE = 1024
        private const val DEFAULT_CACHE_SIZE = 1000
        private const val CACHE_TTL_OVERRIDE = 0 // 0 = use original TTL
        private const val DNS_TIMEOUT_MS = 8000L
        private const val MAX_RETRIES = 2

        // Fallback DNS servers to try if primary fails
        private val FALLBACK_DNS = listOf(
            "1.1.1.1" to 53,   // Cloudflare
            "8.8.8.8" to 53,   // Google
            "9.9.9.9" to 53    // Quad9
        )
    }

    // DNS record types
    object RecordType {
        const val A = 1
        const val NS = 2
        const val CNAME = 5
        const val SOA = 6
        const val PTR = 12
        const val MX = 15
        const val TXT = 16
        const val AAAA = 28
        const val SRV = 33
    }

    // DNS response codes
    object ResponseCode {
        const val NOERROR = 0
        const val FORMERR = 1
        const val SERVFAIL = 2
        const val NXDOMAIN = 3
        const val REFUSED = 5
    }

    data class DnsCacheEntry(
        val response: ByteArray,
        val expiryTime: Long
    )

    private var isRunning = false

    // Current upstream DNS config
    var upstreamDns: DnsConfig = DnsConfig.default()

    // DNS response cache
    private val cache = ConcurrentHashMap<String, DnsCacheEntry>()

    // Statistics
    private val _stats = DnsStats()
    val stats: DnsStats get() = _stats.copy()

    // Packet ID generator for responses
    private val packetIdGenerator = AtomicInteger(1000)

    data class DnsStats(
        var totalQueries: Int = 0,
        var blocked: Int = 0,
        var cached: Int = 0,
        var forwarded: Int = 0,
        var failed: Int = 0
    )

    fun start() {
        isRunning = true
        Log.i(TAG, "DNS Interceptor started with upstream: ${upstreamDns.serverIp}")
    }

    fun stop() {
        isRunning = false
        cache.clear()
        Log.i(TAG, "DNS Interceptor stopped")
    }

    /**
     * Handle an incoming DNS query from the VPN tunnel ASYNCHRONOUSLY.
     * Returns the DNS response bytes synchronously if cached/blocked,
     * or null if the query needs async forwarding (caller should not wait).
     *
     * IMPORTANT: The onAsyncResponse callback is ALWAYS called (even on error)
     * so the caller knows when the operation is complete.
     */
    fun handleQueryAsync(
        queryData: ByteArray,
        destIp: ByteArray,
        sourceIp: ByteArray,
        sourcePort: Int,
        onAsyncResponse: (ByteArray?) -> Unit
    ): ByteArray? {
        if (!isRunning) {
            Log.w(TAG, "DNS interceptor not running, returning null")
            return null
        }

        val query = parseDnsQuery(queryData)
        if (query == null) {
            Log.w(TAG, "Failed to parse DNS query, forwarding raw")
            forwardQueryAsync(queryData, onAsyncResponse)
            return null
        }

        _stats.totalQueries += 1
        vpnService.incrementDnsQuery()

        val domain = query.questions.firstOrNull()?.domainName ?: run {
            // No domain in query — forward async
            forwardQueryAsync(queryData, onAsyncResponse)
            return null
        }

        // Check cache first
        val cacheKey = "${domain}:${query.questions.firstOrNull()?.type ?: RecordType.A}"
        val cached = cache[cacheKey]
        if (cached != null && cached.expiryTime > System.currentTimeMillis()) {
            _stats.cached += 1
            // Replace the transaction ID in the cached response with the query's ID
            val response = cached.response.copyOf()
            response[0] = (query.header.id shr 8).toByte()
            response[1] = (query.header.id and 0xFF).toByte()
            Log.d(TAG, "CACHE HIT: $domain")
            return response
        }

        // Check against filter engine
        val shouldBlock = shouldBlockDomain(domain)

        if (shouldBlock) {
            _stats.blocked += 1
            vpnService.incrementBlocked()
            Log.d(TAG, "BLOCKED DNS query: $domain")
            return buildBlockedResponse(query)
        }

        // Forward to upstream ASYNCHRONOUSLY — don't block the packet loop
        _stats.forwarded += 1
        Log.d(TAG, "FORWARDING DNS query: $domain -> ${upstreamDns.serverIp}")
        forwardQueryAsync(queryData) { responseBytes ->
            if (responseBytes != null) {
                // Cache the response
                cacheResponse(cacheKey, responseBytes)
                Log.d(TAG, "DNS response received for: $domain")
            } else {
                Log.w(TAG, "DNS forward failed for: $domain")
            }
            // ALWAYS call the callback so the caller knows we're done
            onAsyncResponse(responseBytes)
        }

        return null // Response will come via callback
    }

    private fun shouldBlockDomain(domain: String): Boolean {
        val filterEngine = com.dnc.filter.FilterEngine.getInstance()
        return filterEngine.shouldBlockDomain(domain)
    }

    /**
     * Forward the DNS query to the upstream DNS server ASYNCHRONOUSLY.
     * Tries fallback servers if the primary fails.
     * ALWAYS calls the callback (even on failure, with null).
     */
    private fun forwardQueryAsync(
        queryData: ByteArray,
        callback: (ByteArray?) -> Unit
    ) {
        Thread {
            var result: ByteArray? = null

            // Try primary upstream first
            result = tryForward(queryData, upstreamDns.serverIp, upstreamDns.serverPort)

            // If primary failed, try fallback DNS servers
            if (result == null) {
                Log.w(TAG, "Primary DNS (${upstreamDns.serverIp}) failed, trying fallbacks")
                for ((ip, port) in FALLBACK_DNS) {
                    if (ip == upstreamDns.serverIp) continue // Skip if same as primary
                    result = tryForward(queryData, ip, port)
                    if (result != null) {
                        Log.i(TAG, "Fallback DNS ($ip) succeeded")
                        break
                    }
                }
            }

            if (result == null) {
                _stats.failed += 1
            }

            callback(result)
        }.start()
    }

    /**
     * Try to forward a DNS query to a specific server.
     * Returns the response bytes on success, null on failure.
     */
    private fun tryForward(queryData: ByteArray, serverIp: String, serverPort: Int): ByteArray? {
        var socket: DatagramSocket? = null
        try {
            socket = DatagramSocket()
            val protected = vpnService.protectSocket(socket)
            if (!protected) {
                Log.e(TAG, "Failed to protect DNS socket for $serverIp — skipping")
                return null
            }
            socket.soTimeout = DNS_TIMEOUT_MS.toInt()

            val serverAddress = InetAddress.getByName(serverIp)
            val sendPacket = DatagramPacket(
                queryData, queryData.size,
                serverAddress, serverPort
            )
            socket.send(sendPacket)

            val receiveBuffer = ByteArray(MAX_DNS_PACKET_SIZE)
            val receivePacket = DatagramPacket(receiveBuffer, receiveBuffer.size)
            socket.receive(receivePacket)

            return receiveBuffer.copyOf(receivePacket.length)
        } catch (e: Exception) {
            Log.e(TAG, "DNS forward to $serverIp:$serverPort failed: ${e.message}")
            return null
        } finally {
            try { socket?.close() } catch (_: Exception) {}
        }
    }

    /**
     * Build a DNS response that indicates the domain is blocked
     */
    private fun buildBlockedResponse(query: DnsPacket): ByteArray {
        val builder = DnsPacketBuilder()

        return when (upstreamDns.blockResponseType) {
            BlockResponseType.ADDRESS_0_0_0_0 -> {
                builder.buildBlockedResponse(
                    queryId = query.header.id,
                    questions = query.questions,
                    blockIp = "0.0.0.0"
                )
            }
            BlockResponseType.NXDOMAIN -> {
                builder.buildNxDomainResponse(
                    queryId = query.header.id,
                    questions = query.questions
                )
            }
            BlockResponseType.REFUSED -> {
                builder.buildRefusedResponse(
                    queryId = query.header.id,
                    questions = query.questions
                )
            }
        }
    }

    private fun cacheResponse(key: String, response: ByteArray) {
        if (cache.size >= DEFAULT_CACHE_SIZE) {
            val sortedKeys = cache.entries.sortedBy { it.value.expiryTime }.map { it.key }
            val toRemove = sortedKeys.take(sortedKeys.size / 2)
            toRemove.forEach { cache.remove(it) }
        }

        val ttl = parseTtlFromResponse(response)
        val expiryTime = System.currentTimeMillis() + (ttl * 1000)

        cache[key] = DnsCacheEntry(response.copyOf(), expiryTime)
    }

    private fun parseTtlFromResponse(response: ByteArray): Long {
        try {
            val answerCount = ((response[6].toInt() and 0xFF) shl 8) or (response[7].toInt() and 0xFF)
            if (answerCount == 0) return 300L

            var offset = 12
            val questionCount = ((response[4].toInt() and 0xFF) shl 8) or (response[5].toInt() and 0xFF)
            for (i in 0 until questionCount) {
                offset = skipName(response, offset)
                offset += 4
            }

            if (offset < response.size - 10) {
                offset = skipName(response, offset)
                offset += 8
                if (offset + 4 <= response.size) {
                    val ttl = ((response[offset].toInt() and 0xFF) shl 24) or
                            ((response[offset + 1].toInt() and 0xFF) shl 16) or
                            ((response[offset + 2].toInt() and 0xFF) shl 8) or
                            (response[offset + 3].toInt() and 0xFF)
                    return ttl.toLong().coerceIn(60, 86400)
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "Failed to parse TTL: ${e.message}")
        }
        return 300L
    }

    private fun skipName(data: ByteArray, offset: Int): Int {
        var pos = offset
        while (pos < data.size) {
            val len = data[pos].toInt() and 0xFF
            if (len == 0) return pos + 1
            if ((len and 0xC0) == 0xC0) return pos + 2
            pos += len + 1
        }
        return pos
    }

    // ========== DNS Packet Parsing ==========

    data class DnsHeader(
        val id: Int,
        val flags: Int,
        val questionCount: Int,
        val answerCount: Int,
        val authorityCount: Int,
        val additionalCount: Int
    )

    data class DnsQuestion(
        val domainName: String,
        val type: Int,
        val clazz: Int
    )

    data class DnsPacket(
        val header: DnsHeader,
        val questions: List<DnsQuestion>
    )

    fun parseDnsQuery(data: ByteArray): DnsPacket? {
        if (data.size < 12) return null

        val id = ((data[0].toInt() and 0xFF) shl 8) or (data[1].toInt() and 0xFF)
        val flags = ((data[2].toInt() and 0xFF) shl 8) or (data[3].toInt() and 0xFF)
        val questionCount = ((data[4].toInt() and 0xFF) shl 8) or (data[5].toInt() and 0xFF)
        val answerCount = ((data[6].toInt() and 0xFF) shl 8) or (data[7].toInt() and 0xFF)
        val authorityCount = ((data[8].toInt() and 0xFF) shl 8) or (data[9].toInt() and 0xFF)
        val additionalCount = ((data[10].toInt() and 0xFF) shl 8) or (data[11].toInt() and 0xFF)

        val header = DnsHeader(id, flags, questionCount, answerCount, authorityCount, additionalCount)

        val questions = mutableListOf<DnsQuestion>()
        var offset = 12

        for (i in 0 until questionCount) {
            if (offset >= data.size) break

            val domainName = StringBuilder()
            var pos = offset
            while (pos < data.size) {
                val labelLength = data[pos].toInt() and 0xFF
                if (labelLength == 0) {
                    pos++
                    break
                }
                if (pos + 1 + labelLength > data.size) break
                if (domainName.isNotEmpty()) domainName.append('.')
                for (j in 1..labelLength) {
                    domainName.append((data[pos + j].toInt() and 0xFF).toChar())
                }
                pos += labelLength + 1
            }
            offset = pos

            if (offset + 4 > data.size) break
            val type = ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)
            val clazz = ((data[offset + 2].toInt() and 0xFF) shl 8) or (data[offset + 3].toInt() and 0xFF)
            offset += 4

            questions.add(DnsQuestion(domainName.toString(), type, clazz))
        }

        return DnsPacket(header, questions)
    }

    // ========== DNS Packet Builder ==========

    class DnsPacketBuilder {

        fun buildBlockedResponse(queryId: Int, questions: List<DnsQuestion>, blockIp: String): ByteArray {
            val buffer = ByteBuffer.allocate(MAX_DNS_PACKET_SIZE)

            buffer.putShort(queryId.toShort())
            buffer.putShort(0x8180.toShort())
            buffer.putShort(questions.size.toShort())
            buffer.putShort(questions.size.toShort())
            buffer.putShort(0)
            buffer.putShort(0)

            for (q in questions) {
                writeDomainName(buffer, q.domainName)
                buffer.putShort(q.type.toShort())
                buffer.putShort(q.clazz.toShort())
            }

            val blockBytes = InetAddress.getByName(blockIp).address
            for (q in questions) {
                if (q.type == RecordType.A) {
                    writeDomainName(buffer, q.domainName)
                    buffer.putShort(RecordType.A.toShort())
                    buffer.putShort(1)
                    buffer.putInt(300)
                    buffer.putShort(4)
                    buffer.put(blockBytes)
                }
            }

            val result = ByteArray(buffer.position())
            buffer.flip()
            buffer.get(result)
            return result
        }

        fun buildNxDomainResponse(queryId: Int, questions: List<DnsQuestion>): ByteArray {
            val buffer = ByteBuffer.allocate(MAX_DNS_PACKET_SIZE)

            buffer.putShort(queryId.toShort())
            buffer.putShort(0x8183.toShort())
            buffer.putShort(questions.size.toShort())
            buffer.putShort(0)
            buffer.putShort(0)
            buffer.putShort(0)

            for (q in questions) {
                writeDomainName(buffer, q.domainName)
                buffer.putShort(q.type.toShort())
                buffer.putShort(q.clazz.toShort())
            }

            val result = ByteArray(buffer.position())
            buffer.flip()
            buffer.get(result)
            return result
        }

        fun buildRefusedResponse(queryId: Int, questions: List<DnsQuestion>): ByteArray {
            val buffer = ByteBuffer.allocate(MAX_DNS_PACKET_SIZE)

            buffer.putShort(queryId.toShort())
            buffer.putShort(0x8185.toShort())
            buffer.putShort(questions.size.toShort())
            buffer.putShort(0)
            buffer.putShort(0)
            buffer.putShort(0)

            for (q in questions) {
                writeDomainName(buffer, q.domainName)
                buffer.putShort(q.type.toShort())
                buffer.putShort(q.clazz.toShort())
            }

            val result = ByteArray(buffer.position())
            buffer.flip()
            buffer.get(result)
            return result
        }

        private fun writeDomainName(buffer: ByteBuffer, domain: String) {
            if (domain.isEmpty()) {
                buffer.put(0)
                return
            }
            val labels = domain.split(".")
            for (label in labels) {
                val bytes = label.toByteArray(Charsets.US_ASCII)
                buffer.put(bytes.size.toByte())
                buffer.put(bytes)
            }
            buffer.put(0)
        }
    }
}
