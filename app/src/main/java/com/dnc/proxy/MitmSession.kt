package com.dnc.proxy

import android.util.Log
import com.dnc.cert.CertificateManager
import com.dnc.filter.FilterEngine
import com.dnc.filter.FilterOption
import com.dnc.handler.AdvancedRuleHandlers
import com.dnc.handler.ResourceRegistry
import com.dnc.injector.HtmlInjector
import com.dnc.vpn.DncVpnService
import java.io.ByteArrayOutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URI
import java.nio.ByteBuffer
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLEngineResult
import javax.net.ssl.SSLException
import javax.net.ssl.SSLSession

/**
 * A full MITM TLS bridge session.
 *
 * Architecture:
 * ```
 * Client App <-- TLS #1 --> [MitmSession] <-- TLS #2 --> Real Server
 *                                |
 *                         [Decrypted Traffic]
 *                                |
 *                         [HTTP Proxy + Redirect Blocker]
 * ```
 *
 * The MitmSession maintains two SSLEngines:
 * 1. clientEngine — presents our forged cert to the client app
 * 2. serverEngine — validates the real server's cert using the system trust store
 *
 * Data flow:
 * - Client → clientEngine.decrypt() → plaintext → filter → serverEngine.encrypt() → Server
 * - Server → serverEngine.decrypt() → plaintext → filter → clientEngine.encrypt() → Client
 *
 * All decrypted traffic is passed through the HTTP proxy for:
 * - URL-based request blocking
 * - Redirect blocking (301/302)
 * - Header stripping
 * - Response body modification
 */
class MitmSession(
    private val vpnService: DncVpnService,
    private val domain: String,
    private val httpProxy: HttpProxy
) {
    companion object {
        private const val TAG = "MitmSession"
        private const val BUFFER_SIZE = 32768
        private const val CONNECT_TIMEOUT = 10_000
        private const val READ_TIMEOUT = 30_000
    }

    enum class State {
        IDLE,
        CONNECTING,
        CLIENT_HANDSHAKING,
        SERVER_HANDSHAKING,
        BRIDGING,
        CLOSING,
        CLOSED,
        FAILED
    }

    private var state = State.IDLE
    private val isRunning = AtomicBoolean(false)

    // The two TLS engines
    private var clientEngine: SSLEngine? = null
    private var serverEngine: SSLEngine? = null

    // Connection to the real server
    private var serverSocket: Socket? = null
    private var serverInputStream: java.io.InputStream? = null
    private var serverOutputStream: java.io.OutputStream? = null

    // Buffers for the client side (VPN TUN interface)
    private var clientToProxyBuffer = ByteBuffer.allocate(BUFFER_SIZE)
    private var proxyToClientBuffer = ByteBuffer.allocate(BUFFER_SIZE)

    // Buffers for the server side
    private var serverToProxyBuffer = ByteBuffer.allocate(BUFFER_SIZE)
    private var proxyToServerBuffer = ByteBuffer.allocate(BUFFER_SIZE)

    // Decrypted plaintext buffers
    private val clientPlaintext = ByteArrayOutputStream()
    private val serverPlaintext = ByteArrayOutputStream()

    // HTTP request/response reassembly
    private val requestBuffer = ByteArrayOutputStream()
    private val responseBuffer = ByteArrayOutputStream()

    /**
     * Start the MITM session:
     * 1. Create client SSLEngine (with forged cert)
     * 2. Connect to real server
     * 3. Create server SSLEngine (with real cert validation)
     * 4. Complete both TLS handshakes
     * 5. Start bridging traffic
     */
    fun start(clientHello: ByteArray? = null): Boolean {
        if (!isRunning.compareAndSet(false, true)) return false

        try {
            state = State.CONNECTING
            val certManager = CertificateManager.getInstance(vpnService)

            // 1. Create client SSLEngine (presents forged cert to the app)
            val clientSslContext = certManager.createClientSslContext(domain)
            clientEngine = clientSslContext.createSSLEngine(domain, 443)
            clientEngine?.useClientMode = false // We're the server (presenting cert to client)
            clientEngine?.enabledProtocols = arrayOf("TLSv1.2", "TLSv1.3")
            clientEngine?.enabledCipherSuites = getSupportedCipherSuites(clientEngine!!)

            // 2. Connect to the real server via protected socket
            serverSocket = Socket()
            vpnService.protectSocket(serverSocket!!)
            serverSocket?.connect(InetSocketAddress(domain, 443), CONNECT_TIMEOUT)
            serverSocket?.soTimeout = READ_TIMEOUT
            serverInputStream = serverSocket?.getInputStream()
            serverOutputStream = serverSocket?.getOutputStream()

            if (serverSocket?.isConnected != true) {
                Log.e(TAG, "Failed to connect to real server: $domain")
                state = State.FAILED
                return false
            }

            // 3. Create server SSLEngine (validates real server's cert)
            val serverSslContext = certManager.createServerSslContext()
            serverEngine = serverSslContext.createSSLEngine(domain, 443)
            serverEngine?.useClientMode = true // We're the client (connecting to real server)
            serverEngine?.enabledProtocols = arrayOf("TLSv1.2", "TLSv1.3")

            // 4. Complete server-side handshake
            state = State.SERVER_HANDSHAKING
            if (!doServerHandshake()) {
                Log.e(TAG, "Server TLS handshake failed for: $domain")
                state = State.FAILED
                return false
            }

            // 5. Complete client-side handshake
            state = State.CLIENT_HANDSHAKING
            // Client handshake happens as data comes in from the VPN TUN interface
            // We'll process it in handleClientData()

            Log.i(TAG, "MITM session started for: $domain")
            state = State.BRIDGING
            return true

        } catch (e: SSLException) {
            Log.w(TAG, "TLS error for $domain (likely cert pinning): ${e.message}")
            state = State.FAILED
            return false
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start MITM for $domain: ${e.message}")
            state = State.FAILED
            return false
        }
    }

    /**
     * Perform the server-side TLS handshake (connecting to the real server)
     */
    private fun doServerHandshake(): Boolean {
        val engine = serverEngine ?: return false
        val myNetData = ByteBuffer.allocate(engine.session.packetBufferSize)
        val myAppData = ByteBuffer.allocate(engine.session.applicationBufferSize)
        val peerNetData = ByteBuffer.allocate(engine.session.packetBufferSize)

        engine.beginHandshake()

        var handshakeStatus = engine.handshakeStatus

        while (handshakeStatus != SSLEngineResult.HandshakeStatus.FINISHED &&
               handshakeStatus != SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {

            when (handshakeStatus) {
                SSLEngineResult.HandshakeStatus.NEED_WRAP -> {
                    myNetData.clear()
                    val result = engine.wrap(ByteBuffer.allocate(0), myNetData)
                    if (result.status == SSLEngineResult.Status.OK) {
                        myNetData.flip()
                        val data = ByteArray(myNetData.remaining())
                        myNetData.get(data)
                        serverOutputStream?.write(data)
                        serverOutputStream?.flush()
                    } else {
                        Log.e(TAG, "Server handshake wrap failed: ${result.status}")
                        return false
                    }
                }

                SSLEngineResult.HandshakeStatus.NEED_UNWRAP -> {
                    peerNetData.clear()
                    val bytesRead = readFromServer(peerNetData)
                    if (bytesRead <= 0) {
                        // Need more data — read with blocking
                        val buf = ByteArray(BUFFER_SIZE)
                        val len = serverInputStream?.read(buf) ?: -1
                        if (len < 0) return false
                        peerNetData.put(buf, 0, len)
                    }
                    peerNetData.flip()

                    val result = engine.unwrap(peerNetData, myAppData)
                    if (result.status == SSLEngineResult.Status.OK ||
                        result.status == SSLEngineResult.Status.BUFFER_UNDERFLOW) {
                        // OK
                    } else {
                        Log.e(TAG, "Server handshake unwrap failed: ${result.status}")
                        return false
                    }
                }

                SSLEngineResult.HandshakeStatus.NEED_TASK -> {
                    var task = engine.delegatedTask
                    while (task != null) {
                        task.run()
                        task = engine.delegatedTask
                    }
                }

                else -> break
            }

            handshakeStatus = engine.handshakeStatus
        }

        Log.d(TAG, "Server TLS handshake completed for: $domain (protocol: ${engine.session.protocol})")
        return true
    }

    /**
     * Handle incoming data from the client (via VPN TUN interface)
     * This is encrypted TLS data that needs to be decrypted by clientEngine
     */
    fun handleClientData(data: ByteArray): ByteArray? {
        if (!isRunning.get()) return null

        val engine = clientEngine ?: return null

        try {
            // If we're still in client handshake phase
            if (state == State.CLIENT_HANDSHAKING) {
                return processClientHandshake(data, engine)
            }

            // Decrypt the client's TLS data
            val netData = ByteBuffer.wrap(data)
            val appData = ByteBuffer.allocate(engine.session.applicationBufferSize)

            val result = engine.unwrap(netData, appData)

            when (result.status) {
                SSLEngineResult.Status.OK -> {
                    appData.flip()
                    val plaintext = ByteArray(appData.remaining())
                    appData.get(plaintext)

                    if (plaintext.isNotEmpty()) {
                        // Process the decrypted HTTP request
                        return processClientPlaintext(plaintext)
                    }
                }
                SSLEngineResult.Status.BUFFER_UNDERFLOW -> {
                    // Need more data
                    return null
                }
                SSLEngineResult.Status.CLOSED -> {
                    close()
                    return null
                }
                SSLEngineResult.Status.ERROR -> {
                    Log.w(TAG, "Client TLS error for $domain — likely cert pinning")
                    state = State.FAILED
                    return null
                }
            }
        } catch (e: SSLException) {
            Log.w(TAG, "Client TLS error for $domain: ${e.message}")
            state = State.FAILED
        } catch (e: Exception) {
            Log.e(TAG, "Error handling client data for $domain: ${e.message}")
        }

        return null
    }

    /**
     * Process the client handshake (responding to ClientHello etc.)
     * Returns bytes that should be sent back to the client via the VPN TUN
     */
    private fun processClientHandshake(data: ByteArray, engine: SSLEngine): ByteArray? {
        val responseBuffer = ByteArrayOutputStream()
        val netData = ByteBuffer.wrap(data)
        val appData = ByteBuffer.allocate(engine.session.applicationBufferSize)
        val outNetData = ByteBuffer.allocate(engine.session.packetBufferSize)

        engine.beginHandshake()

        var handshakeStatus = engine.handshakeStatus

        // Feed the incoming data to the engine
        var unwrapResult = engine.unwrap(netData, appData)
        handshakeStatus = unwrapResult.handshakeStatus

        val maxIterations = 50
        var iterations = 0

        while (handshakeStatus != SSLEngineResult.HandshakeStatus.FINISHED &&
               handshakeStatus != SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING &&
               iterations < maxIterations) {

            iterations++

            when (handshakeStatus) {
                SSLEngineResult.HandshakeStatus.NEED_WRAP -> {
                    outNetData.clear()
                    val result = engine.wrap(ByteBuffer.allocate(0), outNetData)
                    if (result.status == SSLEngineResult.Status.OK) {
                        outNetData.flip()
                        val response = ByteArray(outNetData.remaining())
                        outNetData.get(response)
                        responseBuffer.write(response)
                    }
                }

                SSLEngineResult.HandshakeStatus.NEED_UNWRAP -> {
                    if (netData.hasRemaining()) {
                        val result = engine.unwrap(netData, appData)
                        handshakeStatus = result.handshakeStatus
                    }
                    // If no more data available, we need to wait for more from the client
                }

                SSLEngineResult.HandshakeStatus.NEED_TASK -> {
                    var task = engine.delegatedTask
                    while (task != null) {
                        task.run()
                        task = engine.delegatedTask
                    }
                }

                else -> break
            }

            handshakeStatus = engine.handshakeStatus
        }

        if (handshakeStatus == SSLEngineResult.HandshakeStatus.FINISHED ||
            handshakeStatus == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
            state = State.BRIDGING
            Log.d(TAG, "Client TLS handshake completed for: $domain")
        }

        return if (responseBuffer.size() > 0) responseBuffer.toByteArray() else null
    }

    /**
     * Process decrypted client plaintext (HTTP request)
     *
     * Phase 4 enhancements:
     * - $removeparam: Strip tracking params from request URL before forwarding
     * - $redirect: Serve neutral resources for blocked requests
     * - $csp: Inject CSP headers into document responses
     * - HTML injection: Cosmetic filtering + scriptlet injection into response body
     */
    private fun processClientPlaintext(plaintext: ByteArray): ByteArray? {
        // Buffer the plaintext for HTTP message reassembly
        requestBuffer.write(plaintext)

        val requestStr = requestBuffer.toString(Charsets.UTF_8)

        val httpRequest = httpProxy.parseHttpRequest(requestBuffer.toByteArray())
        if (httpRequest == null) {
            return null
        }

        requestBuffer.reset()

        var url = "https://$domain${httpRequest.path}"

        val filterEngine = FilterEngine.getInstance()
        val advancedHandlers = AdvancedRuleHandlers.getInstance()
        val requestType = determineRequestType(httpRequest)

        // === Phase 4: $removeparam — strip tracking params ===
        val removeParamResult = advancedHandlers.processRemoveParam(url, "")
        if (removeParamResult.wasModified) {
            Log.d(TAG, "MITM PARAMS REMOVED: ${removeParamResult.removedParams} from $url")
            url = removeParamResult.modifiedUrl
        }

        // Check against filter engine
        val shouldBlock = filterEngine.shouldBlockRequest(url, "", requestType)

        if (shouldBlock) {
            // === Phase 4: $redirect — serve neutral resource instead of empty block ===
            val redirectName = filterEngine.shouldRedirect(url, "", requestType)
            if (redirectName != null) {
                val resource = ResourceRegistry.getInstance().getResource(redirectName)
                if (resource != null) {
                    vpnService.incrementBlocked()
                    Log.d(TAG, "MITM REDIRECTED: $url -> $redirectName")
                    return encryptForClient(
                        advancedHandlers.buildRedirectResponse(resource)
                    )
                }
            }

            vpnService.incrementBlocked()
            Log.d(TAG, "MITM BLOCKED request: ${httpRequest.method} $url")
            return encryptForClient(
                "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX-DNC-Blocked: true\r\n\r\n".toByteArray()
            )
        }

        // Forward the request to the real server via serverEngine
        forwardToServer(requestStr.toByteArray())

        // Read the response from the real server
        val response = readServerResponse() ?: return null

        // Process the response through redirect blocker
        val httpResponse = parseHttpResponse(response) ?: return encryptForClient(response)

        if (httpResponse.isRedirect) {
            val redirectResult = redirectBlocker.processResponse(url, httpResponse)
            if (redirectResult.action == RedirectBlocker.RedirectAction.BLOCKED) {
                vpnService.incrementRedirectsBlocked()
                Log.i(TAG, "MITM REDIRECT BLOCKED: $url -> ${httpResponse.location}")
                return encryptForClient(
                    "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX-DNC-Blocked: redirect\r\n\r\n".toByteArray()
                )
            }
        }

        // === Phase 4: HTML injection (cosmetic + scriptlets) ===
        val htmlInjector = HtmlInjector.getInstance()
        val contentType = httpResponse.headers["Content-Type"] ?: httpResponse.headers["content-type"]
        val injectionResult = htmlInjector.inject(
            body = httpResponse.body,
            domain = domain,
            contentType = contentType
        )

        if (injectionResult.wasModified) {
            val modifiedResponse = buildModifiedResponse(httpResponse, injectionResult.modifiedBody)
            Log.d(TAG, "MITM HTML MODIFIED: $domain (css=${injectionResult.cosmeticInjected}, js=${injectionResult.scriptletsInjected})")
            return encryptForClient(modifiedResponse)
        }

        // === Phase 4: $csp injection ===
        if (requestType == FilterOption.DOCUMENT) {
            val cspResult = advancedHandlers.processCsp(url, "")
            if (cspResult.shouldInject && cspResult.cspHeader != null) {
                val modifiedHeaders = httpResponse.headers.toMutableMap()
                advancedHandlers.injectCspHeader(modifiedHeaders, cspResult.cspHeader)
                val cspResponse = buildResponseWithHeaders(httpResponse, modifiedHeaders)
                Log.d(TAG, "MITM CSP INJECTED: $domain")
                return encryptForClient(cspResponse)
            }
        }

        // Return the (possibly modified) response to the client
        return encryptForClient(response)
    }

    /**
     * Build a modified HTTP response with a new body, updating Content-Length
     */
    private fun buildModifiedResponse(
        original: HttpProxy.HttpResponse,
        newBody: ByteArray
    ): ByteArray {
        val headers = original.headers.toMutableMap()
        headers["Content-Length"] = newBody.size.toString()
        headers["X-DNC-Modified"] = "html-injection"

        val headerStr = buildString {
            append("HTTP/1.1 ${original.statusCode} ${original.statusText}\r\n")
            for ((key, value) in headers) {
                append("$key: $value\r\n")
            }
            append("\r\n")
        }

        return headerStr.toByteArray() + newBody
    }

    /**
     * Build a response with modified headers, keeping the original body
     */
    private fun buildResponseWithHeaders(
        original: HttpProxy.HttpResponse,
        newHeaders: Map<String, String>
    ): ByteArray {
        val headerStr = buildString {
            append("HTTP/1.1 ${original.statusCode} ${original.statusText}\r\n")
            for ((key, value) in newHeaders) {
                append("$key: $value\r\n")
            }
            append("\r\n")
        }

        return headerStr.toByteArray() + original.body
    }

    /**
     * Encrypt plaintext data with clientEngine and return the TLS-encrypted bytes
     * These go back to the client app via the VPN TUN interface
     */
    private fun encryptForClient(plaintext: ByteArray): ByteArray? {
        val engine = clientEngine ?: return null

        try {
            val appData = ByteBuffer.wrap(plaintext)
            val netData = ByteBuffer.allocate(engine.session.packetBufferSize + plaintext.size)

            val result = engine.wrap(appData, netData)

            if (result.status == SSLEngineResult.Status.OK) {
                netData.flip()
                val encrypted = ByteArray(netData.remaining())
                netData.get(encrypted)
                return encrypted
            } else {
                Log.w(TAG, "Failed to encrypt for client: ${result.status}")
                return null
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error encrypting for client: ${e.message}")
            return null
        }
    }

    /**
     * Forward plaintext data to the real server via serverEngine
     */
    private fun forwardToServer(plaintext: ByteArray) {
        val engine = serverEngine ?: return

        try {
            val appData = ByteBuffer.wrap(plaintext)
            val netData = ByteBuffer.allocate(engine.session.packetBufferSize + plaintext.size)

            val result = engine.wrap(appData, netData)

            if (result.status == SSLEngineResult.Status.OK) {
                netData.flip()
                val encrypted = ByteArray(netData.remaining())
                netData.get(encrypted)
                serverOutputStream?.write(encrypted)
                serverOutputStream?.flush()
            } else {
                Log.w(TAG, "Failed to encrypt for server: ${result.status}")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error forwarding to server: ${e.message}")
        }
    }

    /**
     * Read and decrypt the response from the real server
     */
    private fun readServerResponse(): ByteArray? {
        val engine = serverEngine ?: return null

        try {
            val netData = ByteBuffer.allocate(engine.session.packetBufferSize)
            val appData = ByteBuffer.allocate(engine.session.applicationBufferSize)
            val responseBuffer = ByteArrayOutputStream()

            // Read encrypted data from the server socket
            val buf = ByteArray(BUFFER_SIZE)
            var totalRead = 0
            val startTime = System.currentTimeMillis()

            while (System.currentTimeMillis() - startTime < READ_TIMEOUT) {
                val bytesRead = serverInputStream?.read(buf) ?: -1
                if (bytesRead == -1) break
                if (bytesRead == 0) continue

                netData.clear()
                netData.put(buf, 0, bytesRead)
                netData.flip()

                // Decrypt
                var unwrapResult = engine.unwrap(netData, appData)
                while (unwrapResult.status == SSLEngineResult.Status.OK) {
                    appData.flip()
                    val plaintext = ByteArray(appData.remaining())
                    appData.get(plaintext)
                    responseBuffer.write(plaintext)
                    appData.clear()

                    if (netData.hasRemaining()) {
                        unwrapResult = engine.unwrap(netData, appData)
                    } else {
                        break
                    }
                }

                // Check if we have a complete HTTP response
                val currentResponse = responseBuffer.toByteArray()
                if (isCompleteHttpResponse(currentResponse)) {
                    return currentResponse
                }

                // For chunked responses, check for terminating chunk
                val responseStr = currentResponse.toString(Charsets.UTF_8)
                if (responseStr.contains("0\r\n\r\n")) {
                    return currentResponse
                }
            }

            return if (responseBuffer.size() > 0) responseBuffer.toByteArray() else null

        } catch (e: Exception) {
            Log.e(TAG, "Error reading server response for $domain: ${e.message}")
            return null
        }
    }

    /**
     * Check if we have a complete HTTP response (based on Content-Length)
     */
    private fun isCompleteHttpResponse(data: ByteArray): Boolean {
        val headerEnd = indexOf(data, "\r\n\r\n".toByteArray())
        if (headerEnd < 0) return false

        val headers = String(data, 0, headerEnd, Charsets.UTF_8)

        // Check Content-Length
        val contentLengthMatch = Regex("Content-Length:\\s*(\\d+)", RegexOption.IGNORE_CASE).find(headers)
        if (contentLengthMatch != null) {
            val contentLength = contentLengthMatch.groupValues[1].toIntOrNull() ?: 0
            val bodyStart = headerEnd + 4
            return data.size >= bodyStart + contentLength
        }

        // For chunked, we check for the terminating chunk elsewhere
        // For responses without Content-Length, we rely on connection close or timeout
        return false
    }

    private fun indexOf(data: ByteArray, pattern: ByteArray): Int {
        for (i in 0..data.size - pattern.size) {
            var found = true
            for (j in pattern.indices) {
                if (data[i + j] != pattern[j]) {
                    found = false
                    break
                }
            }
            if (found) return i
        }
        return -1
    }

    /**
     * Parse an HTTP response from raw bytes
     */
    private fun parseHttpResponse(data: ByteArray): HttpProxy.HttpResponse? {
        return try {
            val text = String(data, Charsets.UTF_8)
            val lines = text.split("\r\n")
            if (lines.isEmpty()) return null

            val statusLine = lines[0]
            val statusParts = statusLine.split(" ", limit = 3)
            if (statusParts.size < 2) return null

            val statusCode = statusParts[1].toIntOrNull() ?: return null
            val statusText = statusParts.getOrElse(2) { "" }

            val headers = mutableMapOf<String, String>()
            for (i in 1 until lines.size) {
                val line = lines[i]
                if (line.isEmpty()) break
                val colonIndex = line.indexOf(':')
                if (colonIndex > 0) {
                    headers[line.substring(0, colonIndex).trim()] = line.substring(colonIndex + 1).trim()
                }
            }

            val bodyStart = text.indexOf("\r\n\r\n")
            val body = if (bodyStart >= 0 && bodyStart + 4 < data.size) {
                data.copyOfRange(bodyStart + 4, data.size)
            } else {
                ByteArray(0)
            }

            HttpProxy.HttpResponse(
                statusCode = statusCode,
                statusText = statusText,
                headers = headers,
                body = body
            )
        } catch (e: Exception) {
            null
        }
    }

    private fun determineRequestType(request: HttpProxy.HttpRequest): FilterOption {
        val acceptHeader = request.headers["Accept"] ?: ""
        return when {
            request.headers["X-Requested-With"] != null -> FilterOption.XMLHTTPREQUEST
            acceptHeader.contains("image/") -> FilterOption.IMAGE
            acceptHeader.contains("text/css") -> FilterOption.STYLESHEET
            acceptHeader.contains("javascript") -> FilterOption.SCRIPT
            acceptHeader.contains("video/") || acceptHeader.contains("audio/") -> FilterOption.MEDIA
            acceptHeader.contains("font/") -> FilterOption.FONT
            else -> FilterOption.OTHER
        }
    }

    private fun readFromServer(buffer: ByteBuffer): Int {
        // This is a non-blocking check — returns 0 if no data available
        return 0 // Actual read happens in readServerResponse()
    }

    private fun getSupportedCipherSuites(engine: SSLEngine): Array<String> {
        // Filter out weak cipher suites
        return engine.supportedCipherSuites.filter { suite ->
            !suite.contains("NULL") &&
            !suite.contains("anon") &&
            !suite.contains("EXPORT") &&
            !suite.contains("DES") &&
            !suite.contains("MD5") &&
            (suite.contains("AES") || suite.contains("CHACHA") || suite.contains("ECDHE"))
        }.toTypedArray()
    }

    /**
     * Close the MITM session and release all resources
     */
    fun close() {
        if (!isRunning.compareAndSet(true, false)) return

        state = State.CLOSING

        try {
            clientEngine?.closeInbound()
            clientEngine?.closeOutbound()
        } catch (e: Exception) {
            // Ignore
        }

        try {
            serverEngine?.closeInbound()
            serverEngine?.closeOutbound()
        } catch (e: Exception) {
            // Ignore
        }

        try {
            serverInputStream?.close()
            serverOutputStream?.close()
            serverSocket?.close()
        } catch (e: Exception) {
            // Ignore
        }

        state = State.CLOSED
        Log.d(TAG, "MITM session closed for: $domain")
    }

    fun getState(): State = state
    fun isRunning(): Boolean = isRunning.get()
    fun getDomain(): String = domain

    // Redirect blocker instance for this session
    private val redirectBlocker = RedirectBlocker()
}
