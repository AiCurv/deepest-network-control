package com.dnc.filter

import android.util.Log
import java.util.concurrent.ConcurrentHashMap

/**
 * URL pattern matching engine implementing the ABP/uBO matching algorithm.
 *
 * Handles all pattern types:
 * - Domain anchor (||): matches domain and subdomains
 * - Start anchor (|): matches start of URL
 * - End anchor (|): matches end of URL
 * - Separator wildcard (^): matches ://, /, ?, =, &, or end of URL
 * - Wildcard (*): matches any string
 * - Regex patterns (/regex/)
 * - Plain text matching
 */
object UrlMatcher {

    private const val TAG = "UrlMatcher"

    // LRU cache for match results
    private val matchCache = ConcurrentHashMap<String, Boolean>()
    private const val MAX_CACHE_SIZE = 5000

    /**
     * Check if a URL matches a given pattern
     */
    fun matches(pattern: String, url: String): Boolean {
        val cacheKey = "$pattern|$url"
        matchCache[cacheKey]?.let { return it }

        val result = doMatch(pattern, url.lowercase())

        // Cache the result
        if (matchCache.size > MAX_CACHE_SIZE) {
            matchCache.clear()
        }
        matchCache[cacheKey] = result

        return result
    }

    private fun doMatch(pattern: String, url: String): Boolean {
        val patternLower = pattern.lowercase()

        return when {
            // Regex pattern: /regex/
            patternLower.startsWith("/") && patternLower.endsWith("/") && patternLower.length > 2 -> {
                try {
                    val regexStr = patternLower.removeSurrounding("/")
                    Regex(regexStr).containsMatchIn(url)
                } catch (e: Exception) {
                    Log.w(TAG, "Invalid regex: $patternLower")
                    false
                }
            }

            // Domain anchor: ||example.com
            patternLower.startsWith("||") -> matchDomainAnchor(patternLower, url)

            // Start anchor: |https://
            patternLower.startsWith("|") -> matchStartAnchor(patternLower, url)

            // End anchor: pattern|
            patternLower.endsWith("|") -> matchEndAnchor(patternLower, url)

            // Both start and end anchors: |pattern|
            patternLower.startsWith("|") && patternLower.endsWith("|") && patternLower.length > 2 -> {
                url == patternLower.removeSurrounding("|")
            }

            // Contains wildcard
            patternLower.contains("*") -> matchWildcard(patternLower, url)

            // Plain text contains
            else -> url.contains(patternLower)
        }
    }

    /**
     * Match domain anchor pattern: ||example.com^
     * Matches: http://example.com/..., http://sub.example.com/..., https://example.com?...
     * Does NOT match: http://notexample.com/...
     */
    private fun matchDomainAnchor(pattern: String, url: String): Boolean {
        var stripped = pattern.removePrefix("||")

        // Handle separator wildcard at end
        val hasTrailingSeparator = stripped.endsWith("^")
        if (hasTrailingSeparator) {
            stripped = stripped.removeSuffix("^")
        }

        // Handle wildcards within the pattern
        if (stripped.contains("*")) {
            return matchDomainWildcard(stripped, url, hasTrailingSeparator)
        }

        // Extract the URL's domain and path for matching
        val urlAfterProtocol = url.substringAfter("://", url)
        val urlDomain = urlAfterProtocol.substringBefore("/")
        val urlPath = urlAfterProtocol.substringAfter("/", "")

        // Check if URL domain matches the pattern domain
        val domainMatches = urlDomain == stripped || urlDomain.endsWith(".$stripped")

        if (!domainMatches) return false

        // If there's a path component in the pattern, check it too
        val patternPath = stripped.substringAfter("/", "")
        if (patternPath.isEmpty()) {
            // Just domain matching with optional separator check
            return if (hasTrailingSeparator) {
                // ^ must be followed by separator or end
                val afterDomain = urlAfterProtocol.substringAfter(stripped, "")
                afterDomain.isEmpty() || afterDomain.first() in setOf('/', '?', ':', '=', '&')
            } else {
                true
            }
        }

        // Domain + path matching
        val fullPath = "/$urlPath"
        return if (hasTrailingSeparator) {
            val fullPattern = "$stripped^"
            urlAfterProtocol.startsWith(fullPattern) ||
                    urlAfterProtocol.contains(stripped) && isSeparatorAfter(urlAfterProtocol, stripped)
        } else {
            urlAfterProtocol.contains(stripped)
        }
    }

    /**
     * Match start anchor: |https://example.com
     * URL must start with the pattern
     */
    private fun matchStartAnchor(pattern: String, url: String): Boolean {
        val stripped = pattern.removePrefix("|")
        return url.startsWith(stripped)
    }

    /**
     * Match end anchor: pattern|
     * URL must end with the pattern
     */
    private fun matchEndAnchor(pattern: String, url: String): Boolean {
        val stripped = pattern.removeSuffix("|")
        return url.endsWith(stripped)
    }

    /**
     * Match wildcard pattern: ad*tracker
     * * matches any string (including empty)
     */
    private fun matchWildcard(pattern: String, url: String): Boolean {
        val parts = pattern.split("*")
        if (parts.isEmpty() || parts.all { it.isEmpty() }) return true

        var currentIndex = 0

        for ((index, part) in parts.withIndex()) {
            if (part.isEmpty()) continue

            val foundIndex = url.indexOf(part, currentIndex)
            if (foundIndex < 0) return false

            // First part must match at start if pattern doesn't start with *
            if (index == 0 && !pattern.startsWith("*") && foundIndex != 0) {
                return false
            }

            currentIndex = foundIndex + part.length
        }

        // Last part must match at end if pattern doesn't end with *
        if (!pattern.endsWith("*") && parts.isNotEmpty()) {
            val lastPart = parts.last()
            if (lastPart.isNotEmpty() && !url.endsWith(lastPart)) {
                return false
            }
        }

        return true
    }

    /**
     * Match domain pattern with wildcards: *.example.com or ad*.tracker.com
     */
    private fun matchDomainWildcard(pattern: String, url: String, trailingSep: Boolean): Boolean {
        val urlAfterProtocol = url.substringAfter("://", url)
        return matchWildcard(pattern, urlAfterProtocol) ||
                matchWildcard(pattern, urlAfterProtocol.substringBefore("/"))
    }

    /**
     * Check if the character after a pattern match is a separator
     * Separator = one of: / ? : = &, or end of string
     */
    private fun isSeparatorAfter(text: String, pattern: String): Boolean {
        val index = text.indexOf(pattern)
        if (index < 0) return false
        val afterIndex = index + pattern.length
        if (afterIndex >= text.length) return true
        return text[afterIndex] in setOf('/', '?', ':', '=', '&')
    }

    /**
     * Clear the match cache
     */
    fun clearCache() {
        matchCache.clear()
    }
}
