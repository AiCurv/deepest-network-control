package com.dnc.proxy

import android.util.Log
import com.dnc.filter.FilterEngine

/**
 * Blocks HTTP redirects (301/302/303/307/308) based on filter rules.
 *
 * This is the KEY feature that DNS-only blockers can't do:
 * - DNS can only block entire domains
 * - This intercepts the redirect response BEFORE the browser follows it
 * - We check the Location header and block if the target matches a filter rule
 * - The redirect NEVER fires — no data sent to tracker, no redirect chain
 */
class RedirectBlocker {

    companion object {
        private const val TAG = "RedirectBlocker"

        // Redirect status codes
        private val REDIRECT_CODES = setOf(301, 302, 303, 307, 308)
    }

    enum class RedirectAction {
        ALLOWED,         // Redirect passes through normally
        BLOCKED,         // Redirect is replaced with empty response
        REPLACED         // Redirect target is changed
    }

    data class RedirectResult(
        val action: RedirectAction,
        val response: HttpProxy.HttpResponse
    )

    data class RedirectRule(
        val pattern: String,         // Domain or URL pattern to match
        val isRegex: Boolean = false, // Whether pattern is a regex
        val action: RedirectAction = RedirectAction.BLOCKED,
        val replacementUrl: String? = null, // For REPLACED action
        val enabled: Boolean = true,
        val description: String = ""
    )

    // User-defined redirect rules
    private val customRules = mutableListOf<RedirectRule>()

    // Block all redirects from these domains
    private val blockRedirectFromDomains = mutableSetOf<String>()

    // Statistics
    private var totalRedirectsSeen = 0
    private var totalRedirectsBlocked = 0
    private var totalRedirectsReplaced = 0

    fun getStats(): Triple<Int, Int, Int> = Triple(totalRedirectsSeen, totalRedirectsBlocked, totalRedirectsReplaced)

    /**
     * Process an HTTP response and decide what to do with redirects.
     * If the response is a redirect (3xx), check the Location header
     * against filter rules. Otherwise, pass through unchanged.
     */
    fun processResponse(
        requestUrl: String,
        response: HttpProxy.HttpResponse
    ): RedirectResult {
        if (response.statusCode !in REDIRECT_CODES) {
            return RedirectResult(RedirectAction.ALLOWED, response)
        }

        totalRedirectsSeen++

        val location = response.location
        if (location == null) {
            // Malformed redirect with no Location header — let it through
            return RedirectResult(RedirectAction.ALLOWED, response)
        }

        Log.d(TAG, "Redirect detected: $requestUrl -> $location (HTTP ${response.statusCode})")

        // Check against filter engine
        val filterEngine = FilterEngine.getInstance()

        // Check if the redirect TARGET should be blocked
        if (filterEngine.shouldBlockRequest(location, requestUrl, com.dnc.filter.FilterOption.OTHER)) {
            totalRedirectsBlocked++
            Log.i(TAG, "REDIRECT BLOCKED (filter match): $requestUrl -> $location")
            return RedirectResult(
                RedirectAction.BLOCKED,
                createEmptyResponse(response)
            )
        }

        // Check if the redirect should be blocked based on redirect-specific rules
        val customRuleResult = checkCustomRules(requestUrl, location)
        if (customRuleResult != null) {
            when (customRuleResult.action) {
                RedirectAction.BLOCKED -> {
                    totalRedirectsBlocked++
                    Log.i(TAG, "REDIRECT BLOCKED (custom rule): $requestUrl -> $location [${customRuleResult.description}]")
                    return RedirectResult(RedirectAction.BLOCKED, createEmptyResponse(response))
                }
                RedirectAction.REPLACED -> {
                    totalRedirectsReplaced++
                    Log.i(TAG, "REDIRECT REPLACED: $location -> ${customRuleResult.replacementUrl}")
                    return RedirectResult(
                        RedirectAction.REPLACED,
                        createRedirectResponse(response, customRuleResult.replacementUrl ?: "about:blank")
                    )
                }
                RedirectAction.ALLOWED -> { /* Fall through */ }
            }
        }

        // Check if the SOURCE domain has all redirects blocked
        val sourceDomain = extractDomain(requestUrl)
        if (blockRedirectFromDomains.contains(sourceDomain)) {
            totalRedirectsBlocked++
            Log.i(TAG, "REDIRECT BLOCKED (source domain rule): $sourceDomain -> $location")
            return RedirectResult(RedirectAction.BLOCKED, createEmptyResponse(response))
        }

        // Allow the redirect
        return RedirectResult(RedirectAction.ALLOWED, response)
    }

    /**
     * Check user-defined custom redirect rules
     */
    private fun checkCustomRules(requestUrl: String, redirectTarget: String): RedirectRule? {
        for (rule in customRules) {
            if (!rule.enabled) continue

            val target = if (rule.isRegex) {
                try {
                    Regex(rule.pattern).containsMatchIn(redirectTarget)
                } catch (e: Exception) {
                    false
                }
            } else {
                redirectTarget.contains(rule.pattern, ignoreCase = true) ||
                        redirectTarget.endsWith(rule.pattern, ignoreCase = true)
            }

            if (target) return rule
        }
        return null
    }

    /**
     * Create an empty 200 OK response to replace a blocked redirect
     * The browser receives a 200 with no content — redirect never fires
     */
    private fun createEmptyResponse(originalResponse: HttpProxy.HttpResponse): HttpProxy.HttpResponse {
        val emptyBody = ByteArray(0)
        return HttpProxy.HttpResponse(
            statusCode = 200,
            statusText = "OK",
            headers = mapOf(
                "Content-Length" to "0",
                "X-DNC-Blocked" to "redirect"
            ),
            body = emptyBody
        )
    }

    /**
     * Create a redirect response with a modified Location header
     */
    private fun createRedirectResponse(
        originalResponse: HttpProxy.HttpResponse,
        newLocation: String
    ): HttpProxy.HttpResponse {
        val modifiedHeaders = originalResponse.headers.toMutableMap()
        modifiedHeaders["Location"] = newLocation
        return HttpProxy.HttpResponse(
            statusCode = originalResponse.statusCode,
            statusText = originalResponse.statusText,
            headers = modifiedHeaders,
            body = originalResponse.body
        )
    }

    // ========== Rule Management ==========

    fun addCustomRule(rule: RedirectRule) {
        customRules.add(rule)
        Log.d(TAG, "Added redirect rule: ${rule.pattern} -> ${rule.action}")
    }

    fun removeCustomRule(pattern: String) {
        customRules.removeAll { it.pattern == pattern }
    }

    fun getCustomRules(): List<RedirectRule> = customRules.toList()

    fun addBlockRedirectFromDomain(domain: String) {
        blockRedirectFromDomains.add(domain)
        Log.d(TAG, "Blocking all redirects from: $domain")
    }

    fun removeBlockRedirectFromDomain(domain: String) {
        blockRedirectFromDomains.remove(domain)
    }

    fun getBlockRedirectFromDomains(): Set<String> = blockRedirectFromDomains.toSet()

    private fun extractDomain(url: String): String {
        return try {
            val uri = java.net.URI(url)
            uri.host ?: url
        } catch (e: Exception) {
            url.substringBefore("/").substringBefore(":")
        }
    }
}
