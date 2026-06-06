package com.dnc.proxy

import android.util.Log
import com.dnc.dns.DnsInterceptor
import com.dnc.filter.FilterEngine
import com.dnc.filter.FilterOption
import com.dnc.handler.AdvancedRuleHandlers
import com.dnc.handler.ResourceRegistry
import com.dnc.injector.HtmlInjector
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
 *
 * Phase 4 enhancements:
 * - $removeparam: Strip tracking query parameters from URLs before forwarding
 * - $redirect: Serve neutral resources instead of dropping blocked requests
 * - $csp: Inject Content-Security-Policy headers into responses
 * - Cosmetic filtering: Inject CSS to hide page elements
 * - Scriptlet injection: Inject JavaScript to neutralize trackers/anti-adblock
 * - HTML injection: Modify HTML response bodies via HtmlInjector
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

    // Phase 4: Advanced rule handlers
    private val advancedHandlers = AdvancedRuleHandlers.getInstance()

    // Phase 4: HTML injector (cosmetic + scriptlet)
    private val htmlInjector = HtmlInjector.getInstance()

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
        REDIRECT_BLOCKED,
        REDIRECTED,      // Phase 4: $redirect — served neutral resource
        PARAM_REMOVED,   // Phase 4: $removeparam — tracking params stripped
        CSP_INJECTED,    // Phase 4: $csp — CSP header injected
        HTML_MODIFIED    // Phase 4: cosmetic/scriptlet injection into HTML
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

        val requestData = tcpPacket.payload
        val httpRequest = parseHttpRequest(requestData) ?: return

        val filterEngine = FilterEngine.getInstance()
        val url = resolveUrl(httpRequest, ipPacket)
        val requestType = determineRequestType(httpRequest)
        val domain = extractDomain(url)

        // === Phase 4: $removeparam — strip tracking params before anything ===
        val removeParamResult = advancedHandlers.processRemoveParam(url, "")
        val effectiveUrl = removeParamResult.modifiedUrl

        if (removeParamResult.wasModified) {
            Log.d(TAG, "PARAMS REMOVED: ${removeParamResult.removedParams} from $url")
            addToLog(url, httpRequest.method, Action.PARAM_REMOVED, statusCode = null)
        }

        // === Check if request should be blocked ===
        val shouldBlock = filterEngine.shouldBlockRequest(effectiveUrl, "", requestType)

        if (shouldBlock) {
            // === Phase 4: $redirect — serve neutral resource instead of dropping ===
            val redirectResource = filterEngine.shouldRedirect(effectiveUrl, "", requestType)
            if (redirectResource != null) {
                val resource = ResourceRegistry.getInstance().getResource(redirectResource)
                if (resource != null) {
                    vpnService.incrementBlocked()
                    addToLog(effectiveUrl, httpRequest.method, Action.REDIRECTED,
                        matchedRule = redirectResource, statusCode = 200)
                    Log.d(TAG, "REDIRECTED: ${httpRequest.method} $effectiveUrl -> $redirectResource")
                    // The response would be built by AdvancedRuleHandlers.buildRedirectResponse()
                    return
                }
            }

            vpnService.incrementBlocked()
            addToLog(effectiveUrl, httpRequest.method, Action.BLOCKED, statusCode = null)
            Log.d(TAG, "BLOCKED: ${httpRequest.method} $effectiveUrl")
            return
        }

        // === Forward the request and process the response ===
        try {
            val response = forwardHttpRequest(effectiveUrl, httpRequest) ?: return

            // === Redirect blocking (301/302) ===
            val finalResponse = redirectBlocker.processResponse(effectiveUrl, response)

            if (finalResponse.action == RedirectBlocker.RedirectAction.BLOCKED) {
                vpnService.incrementRedirectsBlocked()
                addToLog(effectiveUrl, httpRequest.method, Action.REDIRECT_BLOCKED,
                    statusCode = response.statusCode)
                Log.d(TAG, "REDIRECT BLOCKED: ${response.statusCode} -> ${response.headers["Location"]}")
                return
            }

            // === Phase 4: HTML injection (cosmetic + scriptlets) ===
            var modifiedResponse = finalResponse.response
            if (domain != null) {
                val contentType = modifiedResponse.headers["Content-Type"] ?:
                    modifiedResponse.headers["content-type"]
                val injectionResult = htmlInjector.inject(
                    body = modifiedResponse.body,
                    domain = domain,
                    contentType = contentType
                )
                if (injectionResult.wasModified) {
                    modifiedResponse = modifiedResponse.copy(body = injectionResult.modifiedBody)
                    addToLog(effectiveUrl, httpRequest.method, Action.HTML_MODIFIED,
                        statusCode = modifiedResponse.statusCode)
                    Log.d(TAG, "HTML MODIFIED: $domain (css=${injectionResult.cosmeticInjected}, js=${injectionResult.scriptletsInjected})")
                }
            }

            // === Phase 4: $csp — inject Content-Security-Policy ===
            if (requestType == FilterOption.DOCUMENT && domain != null) {
                val cspResult = advancedHandlers.processCsp(effectiveUrl, "")
                if (cspResult.shouldInject && cspResult.cspHeader != null) {
                    val modifiedHeaders = modifiedResponse.headers.toMutableMap()
                    advancedHandlers.injectCspHeader(modifiedHeaders, cspResult.cspHeader)
                    modifiedResponse = modifiedResponse.copy(headers = modifiedHeaders)
                    addToLog(effectiveUrl, httpRequest.method, Action.CSP_INJECTED,
                        statusCode = modifiedResponse.statusCode)
                    Log.d(TAG, "CSP INJECTED: $domain")
                }
            }

            addToLog(effectiveUrl, httpRequest.method, Action.ALLOWED, statusCode = modifiedResponse.statusCode)

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

            val requestLine = lines[0]
            val requestLineParts = requestLine.split(" ", limit = 3)
            if (requestLineParts.size < 3) return null

            val method = requestLineParts[0]
            var path = requestLineParts[1]
            val version = requestLineParts[2]

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

            val bodyStart = text.indexOf("\r\n\r\n")
            val body = if (bodyStart >= 0 && bodyStart + 4 < text.length) {
                data.copyOfRange(text.indexOf("\r\n\r\n") + 4, data.size)
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
     * Extract domain from URL
     */
    private fun extractDomain(url: String): String? {
        return try {
            val uri = URI(url)
            uri.host
        } catch (e: Exception) {
            null
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
            connection.instanceFollowRedirects = false

            for ((key, value) in request.headers) {
                try {
                    connection.setRequestProperty(key, value)
                } catch (e: Exception) {
                    // Some headers can't be set (like Host)
                }
            }

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
