package com.dnc.filter

import android.content.Context
import android.util.Log
import kotlinx.coroutines.*
import java.net.URL
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList

/**
 * The main filter engine that matches URLs and domains against loaded filter rules.
 *
 * Features:
 * - Loads and manages multiple filter lists
 * - Fast matching using optimized data structures
 * - Supports ABP/uBO/AdGuard filter syntax
 * - Custom user rules
 * - Statistics tracking
 * - Thread-safe rule access
 */
class FilterEngine private constructor(private val context: Context) {

    companion object {
        private const val TAG = "FilterEngine"
        private const val PREFS_NAME = "dnc_filter_prefs"
        private const val KEY_CUSTOM_RULES = "custom_rules"

        @Volatile
        private var instance: FilterEngine? = null

        fun getInstance(): FilterEngine {
            return instance ?: throw IllegalStateException("FilterEngine not initialized. Call init(context) first.")
        }

        fun init(context: Context): FilterEngine {
            return instance ?: synchronized(this) {
                instance ?: FilterEngine(context.applicationContext).also { instance = it }
            }
        }
    }

    // All loaded filter rules, indexed for fast access
    private val allRules = CopyOnWriteArrayList<FilterRule>()

    // Index: domain-based rules (||domain^) — fastest lookup
    private val domainRules = ConcurrentHashMap<String, MutableList<FilterRule>>()

    // Index: exception rules (@@||domain^)
    private val exceptionRules = CopyOnWriteArrayList<FilterRule>()

    // Index: regex rules
    private val regexRules = CopyOnWriteArrayList<FilterRule>()

    // Index: cosmetic rules by domain
    private val cosmeticRules = ConcurrentHashMap<String, MutableList<FilterRule>>()

    // Index: scriptlet rules by domain
    private val scriptletRules = ConcurrentHashMap<String, MutableList<FilterRule>>()

    // Custom user rules
    private val customRules = CopyOnWriteArrayList<FilterRule>()

    // Filter list metadata
    private val filterLists = ConcurrentHashMap<String, FilterListInfo>()

    // Statistics
    private var totalRulesLoaded = 0
    private var blockedRequests = 0L
    private var evaluatedRequests = 0L

    // URL matcher for efficient pattern matching
    private val urlMatcher = UrlMatcher

    private val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    init {
        loadCustomRules()
        loadDefaultLists()
        // Auto-download EasyList on first launch so blocking works out of the box
        autoDownloadDefaultLists()
    }

    // ========== Filter List Management ==========

    data class FilterListInfo(
        val id: String,
        val name: String,
        val url: String,
        var ruleCount: Int = 0,
        var lastUpdated: Long = 0,
        var enabled: Boolean = true
    )

    /**
     * Add a filter list by URL — downloads and parses it
     */
    suspend fun addFilterList(listId: String, name: String, url: String): Result<Int> {
        return withContext(Dispatchers.IO) {
            try {
                Log.i(TAG, "Downloading filter list: $name from $url")
                val rawText = URL(url).readText()
                val rules = FilterListParser.parseList(rawText, listId)

                // Remove old rules from this list if re-adding
                removeFilterListRules(listId)

                // Add new rules
                addRules(rules)

                // Update metadata
                filterLists[listId] = FilterListInfo(
                    id = listId,
                    name = name,
                    url = url,
                    ruleCount = rules.size,
                    lastUpdated = System.currentTimeMillis()
                )

                totalRulesLoaded = allRules.size
                Log.i(TAG, "Loaded ${rules.size} rules from: $name")

                Result.success(rules.size)
            } catch (e: Exception) {
                Log.e(TAG, "Failed to load filter list $name: ${e.message}")
                Result.failure(e)
            }
        }
    }

    /**
     * Remove a filter list and all its rules
     */
    fun removeFilterList(listId: String) {
        removeFilterListRules(listId)
        filterLists.remove(listId)
        totalRulesLoaded = allRules.size
    }

    private fun removeFilterListRules(listId: String) {
        val toRemove = allRules.filter { it.listId == listId }
        allRules.removeAll(toRemove)
        rebuildIndexes()
    }

    /**
     * Update all filter lists
     */
    suspend fun updateFilterLists(): Map<String, Result<Int>> {
        val results = mutableMapOf<String, Result<Int>>()
        for ((id, info) in filterLists) {
            if (info.enabled) {
                results[id] = addFilterList(id, info.name, info.url)
            }
        }
        return results
    }

    /**
     * Get all filter list info
     */
    fun getFilterLists(): List<FilterListInfo> = filterLists.values.toList()

    // ========== Request Matching ==========

    /**
     * Check if a request should be blocked
     * Returns true if blocked, false if allowed
     */
    fun shouldBlockRequest(url: String, originUrl: String, type: FilterOption = FilterOption.OTHER): Boolean {
        evaluatedRequests++

        // Check exception rules FIRST (they override blocking)
        for (rule in exceptionRules) {
            if (rule.matchRequest(url, originUrl, type)) {
                return false // Exception rule allows this request
            }
        }

        // Check important rules (they override exceptions)
        val importantRules = allRules.filter {
            it.enabled && FilterOption.IMPORTANT in it.options &&
                    (it.type == FilterRuleType.BLOCK)
        }
        for (rule in importantRules) {
            if (rule.matchRequest(url, originUrl, type)) {
                blockedRequests++
                return true
            }
        }

        // Check domain-indexed rules (fast path)
        val domain = extractDomain(url)
        if (domain != null) {
            val domainParts = generateDomainParts(domain)
            for (part in domainParts) {
                domainRules[part]?.let { rules ->
                    for (rule in rules) {
                        if (rule.matchRequest(url, originUrl, type)) {
                            blockedRequests++
                            return true
                        }
                    }
                }
            }
        }

        // Check regex rules (slow path)
        for (rule in regexRules) {
            if (rule.matchRequest(url, originUrl, type)) {
                blockedRequests++
                return true
            }
        }

        return false
    }

    /**
     * Check if a domain should be blocked (for DNS-level filtering)
     */
    fun shouldBlockDomain(domain: String): Boolean {
        val domainLower = domain.lowercase()

        // Check exception rules first
        for (rule in exceptionRules) {
            if (rule.matchDomain(domainLower)) {
                return false
            }
        }

        // Check domain-indexed rules
        val domainParts = generateDomainParts(domainLower)
        for (part in domainParts) {
            domainRules[part]?.let { rules ->
                for (rule in rules) {
                    if (rule.type == FilterRuleType.BLOCK && rule.matchDomain(domainLower)) {
                        return true
                    }
                }
            }
        }

        // Check custom rules
        for (rule in customRules) {
            if (rule.type == FilterRuleType.BLOCK && rule.matchDomain(domainLower)) {
                return true
            }
        }

        return false
    }

    /**
     * Check if a redirect should be blocked
     */
    fun shouldBlockRedirect(fromUrl: String, toUrl: String): Boolean {
        // Check if the redirect target should be blocked as a regular request
        return shouldBlockRequest(toUrl, fromUrl, FilterOption.OTHER)
    }

    /**
     * Find cosmetic filters for a domain
     */
    fun findCosmeticFilters(domain: String): List<FilterRule> {
        val results = mutableListOf<FilterRule>()
        val domainLower = domain.lowercase()

        // Global cosmetic rules (no domain restriction)
        cosmeticRules[""]?.let { results.addAll(it) }

        // Domain-specific rules
        val domainParts = generateDomainParts(domainLower)
        for (part in domainParts) {
            cosmeticRules[part]?.let { results.addAll(it) }
        }

        return results
    }

    /**
     * Find scriptlets for a domain
     */
    fun findScriptlets(domain: String): List<FilterRule> {
        val results = mutableListOf<FilterRule>()
        val domainLower = domain.lowercase()

        val domainParts = generateDomainParts(domainLower)
        for (part in domainParts) {
            scriptletRules[part]?.let { results.addAll(it) }
        }

        // Also include generic scriptlets (no domain restriction)
        scriptletRules[""]?.let { results.addAll(it) }

        return results
    }

    /**
     * Find all rules with $removeparam option matching a URL
     */
    fun findRemoveParamRules(url: String, originUrl: String): List<FilterRule> {
        return allRules.filter { rule ->
            rule.enabled &&
            FilterOption.REMOVEPARAM in rule.options &&
            rule.removeParams != null &&
            rule.matchRequest(url, originUrl, FilterOption.OTHER)
        }
    }

    /**
     * Find all rules with $csp option matching a URL
     */
    fun findCspRules(url: String, originUrl: String): List<FilterRule> {
        return allRules.filter { rule ->
            rule.enabled &&
            FilterOption.CSP in rule.options &&
            rule.cspDirective != null &&
            rule.matchRequest(url, originUrl, FilterOption.DOCUMENT)
        }
    }

    /**
     * Find all rules with $redirect option matching a URL
     */
    fun findRedirectRules(url: String, originUrl: String, requestType: FilterOption): List<FilterRule> {
        return allRules.filter { rule ->
            rule.enabled &&
            FilterOption.REDIRECT in rule.options &&
            rule.redirectResource != null &&
            rule.matchRequest(url, originUrl, requestType)
        }
    }

    /**
     * Check if a request should be redirected (instead of blocked)
     * Returns the redirect resource name, or null
     */
    fun shouldRedirect(url: String, originUrl: String, requestType: FilterOption): String? {
        val rules = findRedirectRules(url, originUrl, requestType)
        // First check exception rules
        for (rule in rules) {
            if (rule.type == FilterRuleType.EXCEPTION) return null
        }
        // Last matching redirect rule wins (uBO behavior)
        return rules.lastOrNull()?.redirectResource
    }

    /**
     * Rebuild all indexes — public API for when rules are bulk-updated
     */
    fun rebuildAllIndexes() {
        rebuildIndexes()
    }

    // ========== Custom Rules ==========

    fun addCustomRule(ruleText: String): FilterRule? {
        val rule = FilterListParser.parseRule(ruleText, "custom") ?: return null
        customRules.add(rule)
        addRules(listOf(rule))
        saveCustomRules()
        return rule
    }

    fun removeCustomRule(ruleText: String) {
        customRules.removeAll { it.rawText == ruleText }
        allRules.removeAll { it.rawText == ruleText && it.listId == "custom" }
        rebuildIndexes()
        saveCustomRules()
    }

    fun getCustomRules(): List<FilterRule> = customRules.toList()

    // ========== Statistics ==========

    data class FilterStats(
        val totalRules: Int,
        val blockedRequests: Long,
        val evaluatedRequests: Long,
        val customRules: Int,
        val enabledLists: Int
    )

    fun getStats(): FilterStats = FilterStats(
        totalRules = allRules.size,
        blockedRequests = blockedRequests,
        evaluatedRequests = evaluatedRequests,
        customRules = customRules.size,
        enabledLists = filterLists.values.count { it.enabled }
    )

    // ========== Internal ==========

    private fun addRules(rules: List<FilterRule>) {
        allRules.addAll(rules)
        indexRules(rules)
    }

    private fun indexRules(rules: List<FilterRule>) {
        for (rule in rules) {
            when {
                rule.type == FilterRuleType.EXCEPTION -> exceptionRules.add(rule)
                rule.type == FilterRuleType.BLOCK -> {
                    if (rule.isRegex) {
                        regexRules.add(rule)
                    } else if (rule.pattern.startsWith("||")) {
                        val domain = rule.pattern
                            .removePrefix("||")
                            .removeSuffix("^")
                            .substringBefore("/")
                            .lowercase()
                        domainRules.getOrPut(domain) { mutableListOf() }.add(rule)
                    } else {
                        regexRules.add(rule) // Treat complex patterns as regex-like
                    }
                }
                rule.type == FilterRuleType.COSMETIC || rule.type == FilterRuleType.COSMETIC_EXCEPTION -> {
                    val domain = rule.domains?.firstOrNull()?.lowercase() ?: ""
                    cosmeticRules.getOrPut(domain) { mutableListOf() }.add(rule)
                }
                rule.type == FilterRuleType.SCRIPTLET -> {
                    val domain = rule.domains?.firstOrNull()?.lowercase() ?: ""
                    scriptletRules.getOrPut(domain) { mutableListOf() }.add(rule)
                }
            }
        }
    }

    private fun rebuildIndexes() {
        domainRules.clear()
        exceptionRules.clear()
        regexRules.clear()
        cosmeticRules.clear()
        scriptletRules.clear()
        indexRules(allRules.toList())
    }

    private fun generateDomainParts(domain: String): List<String> {
        val parts = mutableListOf(domain)
        val segments = domain.split(".")
        for (i in 1 until segments.size - 1) {
            parts.add(segments.drop(i).joinToString("."))
        }
        return parts
    }

    private fun extractDomain(url: String): String? {
        return try {
            val noProtocol = url.substringAfter("://", url)
            noProtocol.substringBefore("/").substringBefore(":").substringAfter("@").ifEmpty { null }
        } catch (e: Exception) {
            null
        }
    }

    private fun loadDefaultLists() {
        // Pre-configure the default list metadata — enabled by default
        val defaults = listOf(
            Triple("easylist", "EasyList", "https://easylist.to/easylist/easylist.txt"),
            Triple("easyprivacy", "EasyPrivacy", "https://easylist.to/easylist/easyprivacy.txt"),
            Triple("ublock-filters", "uBlock Filters", "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters.txt"),
            Triple("peter-lowe", "Peter Lowe's List", "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=adblockplus&showtype=0&mimetype=plaintext"),
            Triple("adguard-mobile", "AdGuard Mobile Ads", "https://filters.adtidy.org/extension/ublock/filters/11.txt")
        )

        for ((id, name, url) in defaults) {
            if (!filterLists.containsKey(id)) {
                filterLists[id] = FilterListInfo(
                    id = id,
                    name = name,
                    url = url,
                    enabled = true // Enabled by default — auto-download on startup
                )
            }
        }
    }

    /**
     * Auto-download enabled filter lists in the background.
     * This ensures blocking works as soon as the app starts.
     */
    private fun autoDownloadDefaultLists() {
        scope.launch {
            for ((id, info) in filterLists) {
                if (info.enabled && info.ruleCount == 0) {
                    try {
                        Log.i(TAG, "Auto-downloading filter list: ${info.name}")
                        val result = addFilterList(id, info.name, info.url)
                        result.onSuccess { count ->
                            Log.i(TAG, "Auto-loaded $count rules from ${info.name}")
                        }.onFailure { error ->
                            Log.e(TAG, "Auto-download failed for ${info.name}: ${error.message}")
                        }
                    } catch (e: Exception) {
                        Log.e(TAG, "Auto-download error for ${info.name}: ${e.message}")
                    }
                }
            }
        }
    }

    private fun loadCustomRules() {
        val saved = prefs.getStringSet(KEY_CUSTOM_RULES, emptySet()) ?: emptySet()
        for (ruleText in saved) {
            val rule = FilterListParser.parseRule(ruleText, "custom")
            if (rule != null) {
                customRules.add(rule)
                allRules.add(rule)
            }
        }
        if (customRules.isNotEmpty()) {
            indexRules(customRules.toList())
            Log.i(TAG, "Loaded ${customRules.size} custom rules")
        }
    }

    private fun saveCustomRules() {
        val ruleTexts = customRules.map { it.rawText }.toSet()
        prefs.edit().putStringSet(KEY_CUSTOM_RULES, ruleTexts).apply()
    }
}
