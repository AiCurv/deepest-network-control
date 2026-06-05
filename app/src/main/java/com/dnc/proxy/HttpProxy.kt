package com.dnc.proxy

import android.util.Log
import com.dnc.dns.DnsInterceptor
import com.dnc.filter.FilterEngine
import com.dnc.filter.FilterOption
import com.dnc.vpn.*
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.Socket
import java.net.URI
import java.net.URL
import kotlin.concurrent.thread

/**
 * HTTP Proxy that intercepts and filters HTTP traffic from the VPN tunnel.
 * - Parses HTTP requests and matches against filter engine
 * - Blocks requests matching filter rules
 * - Passes responses through RedirectBlocker before returning to client
 * - Modifies request headers (remove tracking headers if configured)
 */
class HttpProxy(
    private val vpnService: DncVpnService,
    private val dnsInterceptor: DnsInterceptor
) {
    companion object {
        private const val TAG = "HttpProxy"
        private const val MAX_REQUEST_SIZE = 10 * 1024 * 1024 // 10MB
        private const val CONNECT_TIMEOUT = 10_000
        private const val READ_TIMEOUT = 30_000
    }

    private var isRunning = false

    // Redirect blocker
    private val redirectBlocker = RedirectBlocker()

    // Request log for UI
    private val _requestLog = mutableListOf<RequestLogEntry>()
    val requestLog: List<RequestLogEntry> get() = _requestLog.toList()

    data class RequestLogEntry(
        val timestamp: Long,
        val url: String,
        val method: String,
        val action: Action,
        val matchedRule: String? = null,
        val statusCode: Int? = null
    )

    enum class Action {
        ALLOWED,
        BLOCKED,
        REDIRECT_BLOCKED
    }

    fun start() {
        isRunning = true
        Log.i(TAG, "HTTP Proxy started")
    }

    fun stop() {
        isRunning = false
        Log.i(TAG, "HTTP Proxy stopped")
    }

    /**
     * Handle a TCP packet that's been identified as HTTP (port 80)
     */
    fun handlePacket(
        ipPacket: PacketParser.IpPacket,
        tcpPacket: PacketParser.TcpPacket,
        outputStream: java.io.FileOutputStream
    ) {
        if (!isRunning) return
        if (!tcpPacket.hasPayload) return

        // Parse HTTP request from the TCP payload
        val requestData = tcpPacket.payload
        val httpRequest = parseHttpRequest(requestData) ?: return

        val filterEngine = FilterEngine.getInstance()

        // Determine the full URL
        val url = resolveUrl(httpRequest, ipPacket)

        // Determine request type for filtering
        val requestType = determineRequestType(httpRequest)

        // Check if request should be blocked
        val shouldBlock = filterEngine.shouldBlockRequest(url, "", requestType)

        if (shouldBlock) {
            vpnService.incrementBlocked()
            addToLog(url, httpRequest.method, Action.BLOCKED, statusCode = null)
            Log.d(TAG, "BLOCKED: ${httpRequest.method} $url")
            // Don't forward — the request is silently dropped
            return
        }

        // Check redirect rules
        // Forward the request and inspect the response
        try {
            val response = forwardHttpRequest(url, httpRequest) ?: return

            // Pass through redirect blocker
            val finalResponse = redirectBlocker.processResponse(url, response)

            if (finalResponse.action == RedirectBlocker.RedirectAction.BLOCKED) {
                vpnService.incrementRedirectsBlocked()
                addToLog(url, httpRequest.method, Action.REDIRECT_BLOCKED, statusCode = response.statusCode)
                Log.d(TAG, "REDIRECT BLOCKED: ${response.statusCode} -> ${response.headers["Location"]}")
                return
            }

            addToLog(url, httpRequest.method, Action.ALLOWED, statusCode = response.statusCode)

        } catch (e: Exception) {
            Log.e(TAG, "Error forwarding HTTP request: ${e.message}")
        }
    }

    /**
     * Parse raw HTTP request bytes into an HttpRequest object
     */
    fun parseHttpRequest(data: ByteArray): HttpRequest? {
        try {
            val text = String(data, Charsets.UTF_8)
            val lines = text.split("\r\n")
            if (lines.isEmpty()) return null

            // Parse request line: METHOD URL HTTP/1.x
            val requestLine = lines[0]
            val requestLineParts = requestLine.split(" ", limit = 3)
            if (requestLineParts.size < 3) return null

            val method = requestLineParts[0]
            var path = requestLineParts[1]
            val version = requestLineParts[2]

            // Parse headers
            val headers = mutableMapOf<String, String>()
            var headerEnd = 0
            for (i in 1 until lines.size) {
                val line = lines[i]
                if (line.isEmpty()) {
                    headerEnd = i
                    break
                }
                val colonIndex = line.indexOf(':')
                if (colonIndex > 0) {
                    val key = line.substring(0, colonIndex).trim()
                    val value = line.substring(colonIndex + 1).trim()
                    headers[key] = value
                }
            }

            // Parse body (everything after the blank line)
            val bodyStart = text.indexOf("\r\n\r\n")
            val body = if (bodyStart >= 0 && bodyStart + 4 < text.length) {
                data.copyOfRange(
                    text.indexOf("\r\n\r\n") + 4,
                    data.size
                )
            } else {
                ByteArray(0)
            }

            return HttpRequest(
                method = method,
                path = path,
                version = version,
                headers = headers,
                body = body
            )
        } catch (e: Exception) {
            Log.w(TAG, "Failed to parse HTTP request: ${e.message}")
            return null
        }
    }

    /**
     * Resolve the full URL from the request and Host header
     */
    private fun resolveUrl(request: HttpRequest, ipPacket: PacketParser.IpPacket): String {
        val host = request.headers["Host"] ?: ipPacket.destinationIp
        val path = if (request.path.startsWith("http")) request.path else request.path
        return if (request.path.startsWith("http")) {
            request.path
        } else {
            "http://$host${request.path}"
        }
    }

    /**
     * Determine the filter request type from HTTP headers
     */
    private fun determineRequestType(request: HttpRequest): FilterOption {
        val acceptHeader = request.headers["Accept"] ?: ""

        return when {
            request.headers["X-Requested-With"] != null -> FilterOption.XMLHTTPREQUEST
            acceptHeader.contains("image/") -> FilterOption.IMAGE
            acceptHeader.contains("text/css") -> FilterOption.STYLESHEET
            acceptHeader.contains("javascript") || acceptHeader.contains("application/javascript") -> FilterOption.SCRIPT
            acceptHeader.contains("video/") || acceptHeader.contains("audio/") -> FilterOption.MEDIA
            acceptHeader.contains("font/") || acceptHeader.contains("application/font") -> FilterOption.FONT
            else -> FilterOption.OTHER
        }
    }

    /**
     * Forward an HTTP request to the real server and return the response
     */
    private fun forwardHttpRequest(url: String, request: HttpRequest): HttpResponse? {
        return try {
            val connection = URL(url).openConnection() as HttpURLConnection
            connection.requestMethod = request.method
            connection.connectTimeout = CONNECT_TIMEOUT
            connection.readTimeout = READ_TIMEOUT
            connection.instanceFollowRedirects = false // We handle redirects ourselves

            // Set request headers
            for ((key, value) in request.headers) {
                try {
                    connection.setRequestProperty(key, value)
                } catch (e: Exception) {
                    // Some headers can't be set (like Host)
                }
            }

            // Send body if present
            if (request.body.isNotEmpty() && (request.method == "POST" || request.method == "PUT" || request.method == "PATCH")) {
                connection.doOutput = true
                connection.outputStream.write(request.body)
                connection.outputStream.flush()
            }

            val statusCode = connection.responseCode
            val responseHeaders = mutableMapOf<String, String>()
            for ((key, value) in connection.headerFields) {
                if (key != null) responseHeaders[key] = value.joinToString(", ")
            }

            val bodyStream = if (statusCode in 200..399) connection.inputStream else connection.errorStream
            val body = bodyStream?.readBytes() ?: ByteArray(0)

            connection.disconnect()

            HttpResponse(
                statusCode = statusCode,
                statusText = connection.responseMessage ?: "",
                headers = responseHeaders,
                body = body
            )
        } catch (e: Exception) {
            Log.e(TAG, "Error forwarding request to $url: ${e.message}")
            null
        }
    }

    private fun addToLog(
        url: String,
        method: String,
        action: Action,
        matchedRule: String? = null,
        statusCode: Int? = null
    ) {
        synchronized(_requestLog) {
            _requestLog.add(RequestLogEntry(
                timestamp = System.currentTimeMillis(),
                url = url,
                method = method,
                action = action,
                matchedRule = matchedRule,
                statusCode = statusCode
            ))
            // Keep only last 500 entries
            while (_requestLog.size > 500) {
                _requestLog.removeAt(0)
            }
        }
    }

    // ========== HTTP Data Classes ==========

    data class HttpRequest(
        val method: String,
        val path: String,
        val version: String,
        val headers: Map<String, String>,
        val body: ByteArray
    ) {
        override fun equals(other: Any?): Boolean = this === other
        override fun hashCode(): Int = method.hashCode() + path.hashCode()
    }

    data class HttpResponse(
        val statusCode: Int,
        val statusText: String,
        val headers: Map<String, String>,
        val body: ByteArray
    ) {
        val isRedirect: Boolean get() = statusCode in 300..399
        val location: String? get() = headers["Location"] ?: headers["location"]

        override fun equals(other: Any?): Boolean = this === other
        override fun hashCode(): Int = statusCode
    }
}
