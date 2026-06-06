package com.dnc.dns

import android.util.Log
import com.dnc.vpn.DncVpnService
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.nio.ByteBuffer
import java.util.concurrent.ConcurrentHashMap

/**
 * Intercepts DNS queries from the VPN tunnel, filters them against
 * the blocklist, and either returns a blocked response or forwards
 * to the upstream DNS server.
 */
class DnsInterceptor(private val vpnService: DncVpnService) {

    companion object {
        private const val TAG = "DnsInterceptor"
        private const val DNS_PORT = 53
        private const val MAX_DNS_PACKET_SIZE = 1024
        private const val DEFAULT_CACHE_SIZE = 1000
        private const val CACHE_TTL_OVERRIDE = 0 // 0 = use original TTL
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
    private var forwardSocket: DatagramSocket? = null

    // Current upstream DNS config
    var upstreamDns: DnsConfig = DnsConfig.default()

    // DNS response cache
    private val cache = ConcurrentHashMap<String, DnsCacheEntry>()

    // Statistics
    private val _stats = DnsStats()
    val stats: DnsStats get() = _stats.copy()

    data class DnsStats(
        var totalQueries: Int = 0,
        var blocked: Int = 0,
        var cached: Int = 0,
        var forwarded: Int = 0
    )

    fun start() {
        isRunning = true
        forwardSocket = DatagramSocket().also {
            vpnService.protectSocket(it)
        }
        Log.i(TAG, "DNS Interceptor started with upstream: ${upstreamDns.serverIp}")
    }

    fun stop() {
        isRunning = false
        try {
            forwardSocket?.close()
        } catch (e: Exception) {
            Log.w(TAG, "Error closing DNS forward socket: ${e.message}")
        }
        forwardSocket = null
        cache.clear()
        Log.i(TAG, "DNS Interceptor stopped")
    }

    /**
     * Handle an incoming DNS query from the VPN tunnel.
     * Returns the DNS response bytes, or null if we can't handle it.
     */
    fun handleQuery(queryData: ByteArray, destIp: ByteArray): ByteArray? {
        if (!isRunning) return null

        val query = parseDnsQuery(queryData) ?: return null

        _stats.totalQueries += 1

        val domain = query.questions.firstOrNull()?.domainName ?: return forwardQuery(queryData)

        // Check cache first
        val cacheKey = "${domain}:${query.questions.firstOrNull()?.type ?: RecordType.A}"
        val cached = cache[cacheKey]
        if (cached != null && cached.expiryTime > System.currentTimeMillis()) {
            _stats.cached += 1
            // Replace the transaction ID in the cached response with the query's ID
            val response = cached.response.copyOf()
            response[0] = (query.header.id shr 8).toByte()
            response[1] = (query.header.id and 0xFF).toByte()
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

        // Forward to upstream
        _stats.forwarded += 1
        val response = forwardQuery(queryData) ?: return null

        // Cache the response
        cacheResponse(cacheKey, response)

        return response
    }

    private fun shouldBlockDomain(domain: String): Boolean {
        // Will integrate with FilterEngine when it's ready
        // For now, check against a basic blocklist
        val filterEngine = com.dnc.filter.FilterEngine.getInstance()
        return filterEngine.shouldBlockDomain(domain)
    }

    /**
     * Forward the DNS query to the upstream DNS server
     */
    private fun forwardQuery(queryData: ByteArray): ByteArray? {
        val socket = forwardSocket ?: return null

        return try {
            val serverAddress = InetAddress.getByName(upstreamDns.serverIp)
            val sendPacket = DatagramPacket(
                queryData, queryData.size,
                serverAddress, upstreamDns.serverPort
            )
            socket.send(sendPacket)

            val receiveBuffer = ByteArray(MAX_DNS_PACKET_SIZE)
            val receivePacket = DatagramPacket(receiveBuffer, receiveBuffer.size)
            socket.soTimeout = 5000 // 5 second timeout
            socket.receive(receivePacket)

            receiveBuffer.copyOf(receivePacket.length)

        } catch (e: Exception) {
            Log.e(TAG, "DNS forward failed: ${e.message}")
            null
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
            // Remove oldest entries
            val sortedKeys = cache.entries.sortedBy { it.value.expiryTime }.map { it.key }
            val toRemove = sortedKeys.take(sortedKeys.size / 2)
            toRemove.forEach { cache.remove(it) }
        }

        // Parse TTL from the response
        val ttl = parseTtlFromResponse(response)
        val expiryTime = System.currentTimeMillis() + (ttl * 1000)

        cache[key] = DnsCacheEntry(response.copyOf(), expiryTime)
    }

    private fun parseTtlFromResponse(response: ByteArray): Long {
        // Simple TTL extraction from first answer record
        // DNS header = 12 bytes, then questions, then answers
        try {
            val answerCount = ((response[6].toInt() and 0xFF) shl 8) or (response[7].toInt() and 0xFF)
            if (answerCount == 0) return 300L // Default 5 min

            // Skip header and questions
            var offset = 12
            val questionCount = ((response[4].toInt() and 0xFF) shl 8) or (response[5].toInt() and 0xFF)
            for (i in 0 until questionCount) {
                offset = skipName(response, offset)
                offset += 4 // QTYPE + QCLASS
            }

            // Read first answer TTL
            if (offset < response.size - 10) {
                offset = skipName(response, offset)
                offset += 8 // TYPE + CLASS + TTL first 2 bytes
                if (offset + 2 <= response.size) {
                    val ttl = ((response[offset].toInt() and 0xFF) shl 24) or
                            ((response[offset + 1].toInt() and 0xFF) shl 16) or
                            ((response[offset + 2].toInt() and 0xFF) shl 8) or
                            (response[offset + 3].toInt() and 0xFF)
                    return ttl.toLong().coerceIn(60, 86400) // Between 1 min and 1 day
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
            if ((len and 0xC0) == 0xC0) return pos + 2 // Compressed pointer
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

            // Header
            buffer.putShort(queryId.toShort())
            buffer.putShort(0x8180.toShort()) // Response, recursion desired + available
            buffer.putShort(questions.size.toShort()) // QDCOUNT
            buffer.putShort(questions.size.toShort()) // ANCOUNT = same as questions
            buffer.putShort(0) // NSCOUNT
            buffer.putShort(0) // ARCOUNT

            // Questions
            for (q in questions) {
                writeDomainName(buffer, q.domainName)
                buffer.putShort(q.type.toShort())
                buffer.putShort(q.clazz.toShort())
            }

            // Answers
            val blockBytes = InetAddress.getByName(blockIp).address
            for (q in questions) {
                if (q.type == RecordType.A) {
                    writeDomainName(buffer, q.domainName)
                    buffer.putShort(RecordType.A.toShort()) // TYPE A
                    buffer.putShort(1) // CLASS IN
                    buffer.putInt(300) // TTL = 5 minutes
                    buffer.putShort(4) // RDLENGTH
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

            // Header
            buffer.putShort(queryId.toShort())
            buffer.putShort(0x8183.toShort()) // Response + NXDOMAIN
            buffer.putShort(questions.size.toShort())
            buffer.putShort(0) // No answers
            buffer.putShort(0)
            buffer.putShort(0)

            // Questions (echoed back)
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

            // Header
            buffer.putShort(queryId.toShort())
            buffer.putShort(0x8185.toShort()) // Response + REFUSED
            buffer.putShort(questions.size.toShort())
            buffer.putShort(0)
            buffer.putShort(0)
            buffer.putShort(0)

            // Questions
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
            buffer.put(0) // Root label
        }
    }
}
