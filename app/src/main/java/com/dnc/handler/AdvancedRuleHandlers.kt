package com.dnc.handler

import android.util.Log
import com.dnc.filter.FilterEngine
import com.dnc.filter.FilterOption
import com.dnc.filter.FilterRule
import com.dnc.filter.FilterRuleType
import java.net.URI

/**
 * Advanced rule handlers for $removeparam, $csp, and $redirect directives.
 *
 * These rule types go beyond simple blocking — they modify requests and responses
 * in sophisticated ways matching uBlock Origin:
 *
 * $removeparam — Strip tracking query parameters from URLs before forwarding
 * $csp — Inject or modify Content-Security-Policy headers
 * $redirect — Redirect blocked requests to neutral resources instead of dropping
 */
class AdvancedRuleHandlers {

    companion object {
        private const val TAG = "AdvancedRuleHandlers"

        @Volatile
        private var instance: AdvancedRuleHandlers? = null

        fun getInstance(): AdvancedRuleHandlers {
            return instance ?: synchronized(this) {
                instance ?: AdvancedRuleHandlers().also { instance = it }
            }
        }
    }

    // ========== $removeparam ==========

    data class RemoveParamResult(
        val modifiedUrl: String,
        val wasModified: Boolean,
        val removedParams: List<String>
    )

    /**
     * Process a URL and remove tracking parameters based on $removeparam rules.
     */
    fun processRemoveParam(url: String, originUrl: String): RemoveParamResult {
        val filterEngine = FilterEngine.getInstance()
        val rules = findRemoveParamRules(url, originUrl)

        if (rules.isEmpty()) {
            return RemoveParamResult(url, false, emptyList())
        }

        var currentUrl = url
        val allRemoved = mutableListOf<String>()

        for (rule in rules) {
            val paramSpec = rule.removeParams ?: continue
            val result = removeParams(currentUrl, paramSpec)
            if (result.wasModified) {
                currentUrl = result.modifiedUrl
                allRemoved.addAll(result.removedParams)
            }
        }

        return RemoveParamResult(currentUrl, allRemoved.isNotEmpty(), allRemoved)
    }

    private fun removeParams(url: String, paramSpec: String): RemoveParamResult {
        try {
            val uri = URI(url)
            val query = uri.query ?: return RemoveParamResult(url, false, emptyList())

            val params = query.split("&").mapNotNull { param ->
                val eqIndex = param.indexOf('=')
                if (eqIndex >= 0) param.substring(0, eqIndex) to param.substring(eqIndex + 1)
                else param to ""
            }

            val removed = mutableListOf<String>()
            val kept = mutableListOf<Pair<String, String>>()

            for ((name, value) in params) {
                if (shouldRemoveParam(name, paramSpec)) {
                    removed.add(name)
                } else {
                    kept.add(name to value)
                }
            }

            if (removed.isEmpty()) return RemoveParamResult(url, false, emptyList())

            val newQuery = kept.joinToString("&") { (n, v) ->
                if (v.isEmpty()) n else "$n=$v"
            }

            val newUrl = buildString {
                append(uri.scheme).append("://").append(uri.authority).append(uri.path)
                if (newQuery.isNotEmpty()) append("?").append(newQuery)
                if (uri.fragment != null) append("#").append(uri.fragment)
            }

            Log.d(TAG, "Removed params: $removed from $url")
            return RemoveParamResult(newUrl, true, removed)

        } catch (e: Exception) {
            Log.w(TAG, "Error processing removeparam: ${e.message}")
            return RemoveParamResult(url, false, emptyList())
        }
    }

    private fun shouldRemoveParam(paramName: String, spec: String): Boolean {
        val specs = spec.split("|")
        var shouldRemove = false

        for (s in specs) {
            val trimmed = s.trim()
            if (trimmed.isEmpty()) continue
            if (trimmed.startsWith("~")) {
                if (matchParamPattern(paramName, trimmed.removePrefix("~"))) return false
                continue
            }
            if (matchParamPattern(paramName, trimmed)) shouldRemove = true
        }
        return shouldRemove
    }

    private fun matchParamPattern(paramName: String, pattern: String): Boolean {
        return when {
            pattern.startsWith("/") && pattern.endsWith("/") && pattern.length > 2 -> {
                try {
                    Regex(pattern.removeSurrounding("/"), RegexOption.IGNORE_CASE).containsMatchIn(paramName)
                } catch (_: Exception) { false }
            }
            pattern.contains("*") -> {
                try {
                    Regex("^${pattern.replace("*", ".*")}$", RegexOption.IGNORE_CASE).matches(paramName)
                } catch (_: Exception) { false }
            }
            else -> paramName.equals(pattern, ignoreCase = true)
        }
    }

    private fun findRemoveParamRules(url: String, originUrl: String): List<FilterRule> {
        val filterEngine = FilterEngine.getInstance()
        return filterEngine.getCustomRules().filter { rule ->
            rule.enabled && FilterOption.REMOVEPARAM in rule.options &&
            rule.removeParams != null && rule.matchRequest(url, originUrl, FilterOption.OTHER)
        }
    }

    // ========== $csp ==========

    data class CspResult(val cspHeader: String?, val shouldInject: Boolean)

    /**
     * Process CSP rules and generate a Content-Security-Policy header value.
     */
    fun processCsp(url: String, originUrl: String): CspResult {
        val rules = findCspRules(url, originUrl)
        if (rules.isEmpty()) return CspResult(null, false)

        val directives = mutableSetOf<String>()
        for (rule in rules) {
            rule.cspDirective?.split(";")?.map { it.trim() }?.filter { it.isNotEmpty() }?.forEach {
                directives.add(it)
            }
        }

        if (directives.isEmpty()) return CspResult(null, false)

        val cspHeader = directives.joinToString("; ")
        Log.d(TAG, "Injecting CSP: $cspHeader for $url")
        return CspResult(cspHeader, true)
    }

    fun injectCspHeader(headers: MutableMap<String, String>, cspValue: String) {
        val existingCsp = headers["Content-Security-Policy"] ?: headers["content-security-policy"]
        headers["Content-Security-Policy"] = if (existingCsp != null) "$existingCsp; $cspValue" else cspValue
    }

    private fun findCspRules(url: String, originUrl: String): List<FilterRule> {
        val filterEngine = FilterEngine.getInstance()
        return filterEngine.getCustomRules().filter { rule ->
            rule.enabled && FilterOption.CSP in rule.options &&
            rule.cspDirective != null && rule.matchRequest(url, originUrl, FilterOption.DOCUMENT)
        }
    }

    // ========== $redirect ==========

    data class RedirectResult(
        val shouldRedirect: Boolean,
        val resource: ResourceRegistry.RedirectResource?,
        val matchedRule: FilterRule?
    )

    /**
     * Process $redirect rules — instead of dropping blocked requests, serve neutral resources.
     */
    fun processRedirect(url: String, originUrl: String, requestType: FilterOption): RedirectResult {
        val rules = findRedirectRules(url, originUrl, requestType)
        if (rules.isEmpty()) return RedirectResult(false, null, null)

        val rule = rules.last()
        val resourceName = rule.redirectResource ?: return RedirectResult(false, null, null)
        val resource = ResourceRegistry.getInstance().getResource(resourceName)
            ?: return RedirectResult(false, null, null)

        Log.d(TAG, "Redirecting $url to resource: $resourceName")
        return RedirectResult(true, resource, rule)
    }

    fun buildRedirectResponse(resource: ResourceRegistry.RedirectResource): ByteArray {
        val headers = buildString {
            append("HTTP/1.1 200 OK\r\n")
            append("Content-Type: ${resource.contentType}\r\n")
            append("Content-Length: ${resource.data.size}\r\n")
            append("Cache-Control: public, max-age=31536000\r\n")
            append("X-DNC-Redirect: ${resource.name}\r\n")
            append("\r\n")
        }
        return headers.toByteArray() + resource.data
    }

    private fun findRedirectRules(url: String, originUrl: String, requestType: FilterOption): List<FilterRule> {
        val filterEngine = FilterEngine.getInstance()
        return filterEngine.getCustomRules().filter { rule ->
            rule.enabled && FilterOption.REDIRECT in rule.options &&
            rule.redirectResource != null && rule.matchRequest(url, originUrl, requestType)
        }
    }

    // ========== Combined Processing ==========

    data class AdvancedProcessResult(
        val modifiedUrl: String,
        val urlWasModified: Boolean,
        val redirectResource: ResourceRegistry.RedirectResource?,
        val cspHeader: String?,
        val removedParams: List<String>
    )

    fun processRequest(url: String, originUrl: String, requestType: FilterOption): AdvancedProcessResult {
        val removeParamResult = processRemoveParam(url, originUrl)
        val redirectResult = processRedirect(removeParamResult.modifiedUrl, originUrl, requestType)
        val cspResult = if (requestType == FilterOption.DOCUMENT) {
            processCsp(removeParamResult.modifiedUrl, originUrl)
        } else {
            CspResult(null, false)
        }

        return AdvancedProcessResult(
            modifiedUrl = removeParamResult.modifiedUrl,
            urlWasModified = removeParamResult.wasModified,
            redirectResource = redirectResult.resource,
            cspHeader = cspResult.cspHeader,
            removedParams = removeParamResult.removedParams
        )
    }
}
