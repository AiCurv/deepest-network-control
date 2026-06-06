package com.dnc.filter

/**
 * Filter rule data class — represents a single uBlock Origin / ABP filter rule.
 *
 * Supports the full ABP/uBO/AdGuard filter syntax:
 * - Basic blocking: ||ads.example.com^
 * - Exception rules: @@||example.com^
 * - Domain restrictions: $domain=example.com
 * - Type options: $script, $image, $stylesheet, etc.
 * - Redirect: $redirect=resource
 * - Remove params: $removeparam=param
 * - CSP: $csp=policy
 * - Cosmetic filters: ##selector
 * - Scriptlet injection: ##+js(scriptlet-name, arg1)
 */
data class FilterRule(
    val rawText: String,
    val type: FilterRuleType,
    val pattern: String,
    val isRegex: Boolean = false,
    val regex: Regex? = null,
    val options: Set<FilterOption> = emptySet(),
    val domains: Set<String>? = null,     // null = all domains, set = restricted
    val excludedDomains: Set<String> = emptySet(),
    val redirectResource: String? = null,
    val removeParams: String? = null,
    val cspDirective: String? = null,
    val cosmeticSelector: String? = null,
    val scriptletName: String? = null,
    val scriptletArgs: List<String>? = null,
    val enabled: Boolean = true,
    val listId: String? = null
) {
    /**
     * Check if this rule matches a given request
     */
    fun matchRequest(url: String, originUrl: String, requestType: FilterOption): Boolean {
        if (!enabled) return false
        if (type != FilterRuleType.BLOCK && type != FilterRuleType.EXCEPTION) return false

        // Check type options
        if (options.isNotEmpty()) {
            val typeOptions = options.filter { it.isRequestType }
            if (typeOptions.isNotEmpty() && requestType !in typeOptions) {
                return false
            }
        }

        // Check domain restrictions
        if (domains != null) {
            val originDomain = extractDomain(originUrl)
            if (originDomain != null) {
                if (originDomain in excludedDomains) return false
                if (domains.isNotEmpty() && originDomain !in domains && !domains.any { originDomain.endsWith(".$it") }) {
                    return false
                }
            }
        }

        // Check third-party / first-party
        if (FilterOption.THIRD_PARTY in options) {
            val urlDomain = extractDomain(url)
            val originDomain = extractDomain(originUrl)
            if (urlDomain == originDomain) return false
        }
        if (FilterOption.FIRST_PARTY in options) {
            val urlDomain = extractDomain(url)
            val originDomain = extractDomain(originUrl)
            if (urlDomain != originDomain) return false
        }

        // Match URL against pattern
        return matchUrl(url)
    }

    /**
     * Check if this rule matches a domain (for DNS-level blocking)
     */
    fun matchDomain(domain: String): Boolean {
        if (!enabled) return false
        if (type != FilterRuleType.BLOCK && type != FilterRuleType.EXCEPTION) return false

        // For DNS, we can only match domain-level patterns
        return when {
            isRegex -> regex?.containsMatchIn(domain) ?: false
            pattern.startsWith("||") && pattern.endsWith("^") -> {
                val domainPattern = pattern.removePrefix("||").removeSuffix("^")
                domain == domainPattern || domain.endsWith(".$domainPattern")
            }
            pattern.startsWith("||") -> {
                val domainPattern = pattern.removePrefix("||")
                domain == domainPattern || domain.endsWith(".$domainPattern")
            }
            pattern.contains("/") -> false // Path-based rules can't match DNS
            else -> domain.contains(pattern, ignoreCase = true)
        }
    }

    /**
     * Check if the URL matches this rule's pattern
     */
    private fun matchUrl(url: String): Boolean {
        val urlLower = url.lowercase()
        val patternLower = pattern.lowercase()

        return when {
            isRegex -> regex?.containsMatchIn(url) ?: false

            // Domain anchor: ||example.com^
            patternLower.startsWith("||") -> {
                val stripped = patternLower.removePrefix("||")
                val urlDomain = extractDomain(urlLower) ?: ""
                val urlFull = urlLower.substringAfter("://", urlLower)

                if (stripped.endsWith("^")) {
                    val domain = stripped.removeSuffix("^")
                    // ^ matches separator: /, ?, :, =, &, or end
                    urlDomain == domain ||
                            urlDomain.endsWith(".$domain") ||
                            urlFull.startsWith(domain) && isSeparator(urlFull.getOrNull(domain.length))
                } else {
                    urlDomain == stripped ||
                            urlDomain.endsWith(".$stripped") ||
                            urlFull.contains(stripped)
                }
            }

            // Start anchor: |https://
            patternLower.startsWith("|") -> {
                val stripped = patternLower.removePrefix("|")
                urlLower.startsWith(stripped)
            }

            // End anchor: |
            patternLower.endsWith("|") -> {
                val stripped = patternLower.removeSuffix("|")
                urlLower.endsWith(stripped)
            }

            // Contains wildcard: *
            patternLower.contains("*") -> {
                wildcardMatch(patternLower, urlLower)
            }

            // Simple contains match
            else -> urlLower.contains(patternLower)
        }
    }

    /**
     * Simple wildcard matching — * matches any string
     */
    private fun wildcardMatch(pattern: String, url: String): Boolean {
        val parts = pattern.split("*")
        if (parts.isEmpty()) return true

        var currentIndex = 0
        for ((index, part) in parts.withIndex()) {
            if (part.isEmpty()) continue

            val foundIndex = url.indexOf(part, currentIndex)
            if (foundIndex < 0) return false

            if (index == 0 && pattern.startsWith(part) && foundIndex != 0) {
                return false // First part must match at start (if no leading *)
            }

            currentIndex = foundIndex + part.length
        }

        if (pattern.endsWith("*")) return true
        return url.endsWith(parts.last())
    }

    private fun isSeparator(char: Char?): Boolean {
        return char == null || char in setOf('/', '?', ':', '=', '&')
    }

    private fun extractDomain(url: String): String? {
        return try {
            val noProtocol = url.substringAfter("://", url)
            val beforePath = noProtocol.substringBefore("/", noProtocol)
            val beforePort = beforePath.substringBefore(":", beforePath)
            val beforeAuth = beforePort.substringAfter("@", beforePort)
            beforeAuth.ifEmpty { null }
        } catch (e: Exception) {
            null
        }
    }
}

enum class FilterRuleType {
    BLOCK,           // Standard blocking rule
    EXCEPTION,       // @@exception rule (whitelist)
    COSMETIC,        // ##selector (element hiding)
    COSMETIC_EXCEPTION, // #@#selector
    SCRIPTLET,       // ##+js(scriptlet)
    REDIRECT,        // $redirect=resource
    HEADER,          // ##^responseheader
    HTML_FILTER,     // ##^tag:has-text(...)
    COMMENT          // ! comment line
}

enum class FilterOption(val isRequestType: Boolean = false) {
    SCRIPT(true),
    IMAGE(true),
    STYLESHEET(true),
    SUBDOCUMENT(true),
    XMLHTTPREQUEST(true),
    DOCUMENT(true),
    POPUP(true),
    MEDIA(true),
    FONT(true),
    WEBSOCKET(true),
    PING(true),
    OTHER(true),
    THIRD_PARTY(false),
    FIRST_PARTY(false),
    MATCH_CASE(false),
    IMPORTANT(false),
    BADFILTER(false),
    REDIRECT(false),
    REMOVEPARAM(false),
    CSP(false)
}
