package com.dnc.cosmetic

import android.util.Log
import com.dnc.filter.FilterEngine
import com.dnc.filter.FilterRule
import com.dnc.filter.FilterRuleType
import java.util.concurrent.ConcurrentHashMap

/**
 * Cosmetic filtering engine — the uBlock Origin ##selector system for network-level element hiding.
 *
 * In a browser extension, cosmetic filters inject CSS rules like:
 *   .ad-banner { display: none !important; }
 *
 * At the network level, we achieve the same effect by modifying HTML response bodies
 * to inject a <style> tag containing the CSS rules before the page reaches the browser.
 *
 * Supported syntax:
 * - ##selector                  → Generic element hiding (applies to all sites)
 * - domain##selector            → Specific element hiding (only on domain)
 * - domain1,domain2##selector   → Multi-domain element hiding
 * - #@#selector                 → Cosmetic exception (disable a generic rule on a domain)
 * - ##selector :has-text(...)   → Procedural cosmetic filter (limited support)
 *
 * Implementation:
 * 1. FilterEngine.findCosmeticFilters(domain) returns matching rules
 * 2. CosmeticFilter.generateCss(domain) builds the CSS <style> content
 * 3. HtmlInjector inserts it into the HTML <head> or before </body>
 */
class CosmeticFilter {

    companion object {
        private const val TAG = "CosmeticFilter"

        @Volatile
        private var instance: CosmeticFilter? = null

        fun getInstance(): CosmeticFilter {
            return instance ?: synchronized(this) {
                instance ?: CosmeticFilter().also { instance = it }
            }
        }
    }

    // Cache: domain → generated CSS
    private val domainCssCache = ConcurrentHashMap<String, String>()
    private val cacheTimestamp = ConcurrentHashMap<String, Long>()
    private val CACHE_TTL = 5 * 60 * 1000L // 5 minutes

    // Generic cosmetic rules (no domain restriction) — applied to ALL sites
    // These are built during rule loading
    private val genericCosmeticSelectors = mutableListOf<String>()
    private val genericExceptionSelectors = ConcurrentHashMap<String, MutableSet<String>>()

    /**
     * Generate the CSS content to inject for a given domain.
     *
     * Combines:
     * - Generic cosmetic selectors (##selector with no domain)
     * - Domain-specific cosmetic selectors (domain##selector)
     * - Excludes any selectors that are excepted (domain#@#selector)
     */
    fun generateCss(domain: String): String? {
        val cacheKey = domain.lowercase()
        val cachedTime = cacheTimestamp[cacheKey]
        if (cachedTime != null && System.currentTimeMillis() - cachedTime < CACHE_TTL) {
            domainCssCache[cacheKey]?.let { cached ->
                return if (cached.isEmpty()) null else cached
            }
        }

        val filterEngine = FilterEngine.getInstance()
        val rules = filterEngine.findCosmeticFilters(domain)

        if (rules.isEmpty() && genericCosmeticSelectors.isEmpty()) {
            domainCssCache[cacheKey] = ""
            cacheTimestamp[cacheKey] = System.currentTimeMillis()
            return null
        }

        val selectors = mutableSetOf<String>()
        val exceptions = mutableSetOf<String>()

        // Add generic selectors (those with no domain restriction)
        selectors.addAll(genericCosmeticSelectors)

        // Process domain-specific rules
        for (rule in rules) {
            val selector = rule.cosmeticSelector ?: continue

            when (rule.type) {
                FilterRuleType.COSMETIC -> {
                    // Check if this domain is in excludedDomains
                    val domainLower = domain.lowercase()
                    val isExcluded = rule.excludedDomains.isNotEmpty() &&
                            rule.excludedDomains.any { domainLower == it || domainLower.endsWith(".$it") }
                    if (!isExcluded) {
                        selectors.add(selector)
                    }
                }
                FilterRuleType.COSMETIC_EXCEPTION -> {
                    exceptions.add(selector)
                }
                else -> { /* skip */ }
            }
        }

        // Remove domain-specific exceptions from generic selectors
        val domainExceptions = genericExceptionSelectors[cacheKey] ?: emptySet()
        exceptions.addAll(domainExceptions)

        // Remove all exceptions
        selectors.removeAll(exceptions)

        if (selectors.isEmpty()) {
            domainCssCache[cacheKey] = ""
            cacheTimestamp[cacheKey] = System.currentTimeMillis()
            return null
        }

        // Build CSS: each selector gets display:none !important
        val css = buildString {
            appendLine("/* DNC Cosmetic Filter — deepest-network-control */")
            for ((index, batch) in selectors.chunked(50).withIndex()) {
                append(batch.joinToString(","))
                appendLine(" { display: none !important; }")
            }
        }

        domainCssCache[cacheKey] = css
        cacheTimestamp[cacheKey] = System.currentTimeMillis()
        return css
    }

    /**
     * Check if a domain has any cosmetic filters to inject
     */
    fun hasCosmeticFilters(domain: String): Boolean {
        val filterEngine = FilterEngine.getInstance()
        return filterEngine.findCosmeticFilters(domain).isNotEmpty() ||
                genericCosmeticSelectors.isNotEmpty()
    }

    /**
     * Add a generic cosmetic selector (no domain restriction)
     */
    fun addGenericSelector(selector: String) {
        genericCosmeticSelectors.add(selector)
    }

    /**
     * Add a generic cosmetic exception for a domain
     */
    fun addGenericException(domain: String, selector: String) {
        genericExceptionSelectors.getOrPut(domain.lowercase()) { mutableSetOf() }.add(selector)
    }

    /**
     * Clear all generic selectors (called on rule rebuild)
     */
    fun clearGenericSelectors() {
        genericCosmeticSelectors.clear()
        genericExceptionSelectors.clear()
    }

    /**
     * Invalidate cache (after rule updates)
     */
    fun invalidateCache() {
        domainCssCache.clear()
        cacheTimestamp.clear()
    }

    /**
     * Rebuild generic cosmetic rules from the filter engine
     * Called after rules are loaded/updated
     */
    fun rebuildGenericRules() {
        clearGenericSelectors()
        val filterEngine = FilterEngine.getInstance()
        // The filter engine's cosmetic rules indexed by "" are generic
        val genericRules = filterEngine.findCosmeticFilters("")
        for (rule in genericRules) {
            val selector = rule.cosmeticSelector ?: continue
            when (rule.type) {
                FilterRuleType.COSMETIC -> addGenericSelector(selector)
                FilterRuleType.COSMETIC_EXCEPTION -> {
                    // Generic exceptions apply to specific domains via domain field
                    rule.domains?.forEach { domain ->
                        addGenericException(domain, selector)
                    }
                }
                else -> {}
            }
        }
        invalidateCache()
    }

    data class CosmeticStats(
        val genericSelectorCount: Int,
        val domainCacheSize: Int,
        val exceptionDomainCount: Int
    )

    fun getStats(): CosmeticStats = CosmeticStats(
        genericSelectorCount = genericCosmeticSelectors.size,
        domainCacheSize = domainCssCache.size,
        exceptionDomainCount = genericExceptionSelectors.size
    )
}
