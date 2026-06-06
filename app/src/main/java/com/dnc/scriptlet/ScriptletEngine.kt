package com.dnc.scriptlet

import android.util.Log
import com.dnc.filter.FilterEngine
import com.dnc.filter.FilterRuleType
import java.util.concurrent.ConcurrentHashMap

/**
 * Scriptlet injection engine — the uBlock Origin ##+js() system for network-level filtering.
 *
 * At the browser extension level, uBO injects JavaScript into pages via content scripts.
 * At the network level, we achieve the same effect by modifying HTML response bodies
 * to inject <script> tags before the page reaches the browser.
 *
 * Flow:
 * 1. FilterEngine finds scriptlet rules matching a domain
 * 2. ScriptletEngine resolves scriptlet names to JS code
 * 3. HtmlInjector inserts the generated <script> into the HTML response
 *
 * Supported syntax:
 * - domain##+js(scriptlet-name)
 * - domain##+js(scriptlet-name, arg1)
 * - domain##+js(scriptlet-name, arg1, arg2)
 * - domain#@#+js(scriptlet-name)  ← exception (disable scriptlet)
 */
class ScriptletEngine {

    companion object {
        private const val TAG = "ScriptletEngine"

        @Volatile
        private var instance: ScriptletEngine? = null

        fun getInstance(): ScriptletEngine {
            return instance ?: synchronized(this) {
                instance ?: ScriptletEngine().also { instance = it }
            }
        }

        fun init(): ScriptletEngine = getInstance()
    }

    // Registry: name → scriptlet definition
    private val scriptletRegistry = ConcurrentHashMap<String, ScriptletDef>()

    // Cache: domain → generated JS code
    private val domainScriptCache = ConcurrentHashMap<String, String>()
    private val cacheTimestamp = ConcurrentHashMap<String, Long>()
    private val CACHE_TTL = 5 * 60 * 1000L // 5 minutes

    init {
        ScriptletLibrary.registerAll(this)
    }

    /**
     * A scriptlet definition — template + metadata for a ##+js() scriptlet
     */
    data class ScriptletDef(
        val name: String,
        val description: String,
        val minArgs: Int = 0,
        val maxArgs: Int = 10,
        val requiresTrust: Boolean = false,
        val generator: (args: List<String>) -> String
    )

    fun registerScriptlet(def: ScriptletDef) {
        scriptletRegistry[def.name] = def
        ScriptletLibrary.getAliases(def.name).forEach { alias ->
            scriptletRegistry[alias] = def
        }
    }

    fun getScriptlet(name: String): ScriptletDef? = scriptletRegistry[name]

    fun getRegisteredScriptlets(): List<String> = scriptletRegistry.keys.sorted()

    /**
     * Generate JavaScript to inject for a given domain.
     * Finds matching scriptlet rules, filters exceptions, generates JS.
     */
    fun generateInjectionScript(domain: String): String? {
        val cacheKey = domain.lowercase()
        val cachedTime = cacheTimestamp[cacheKey]
        if (cachedTime != null && System.currentTimeMillis() - cachedTime < CACHE_TTL) {
            domainScriptCache[cacheKey]?.let { cached ->
                return if (cached.isEmpty()) null else cached
            }
        }

        val filterEngine = FilterEngine.getInstance()
        val scriptletRules = filterEngine.findScriptlets(domain)

        if (scriptletRules.isEmpty()) {
            domainScriptCache[cacheKey] = ""
            cacheTimestamp[cacheKey] = System.currentTimeMillis()
            return null
        }

        // Exception scriptlets (domain#@#+js(name))
        val exceptionNames = mutableSetOf<String>()
        for (rule in scriptletRules) {
            if (rule.type == FilterRuleType.EXCEPTION && rule.scriptletName != null) {
                exceptionNames.add(rule.scriptletName)
            }
        }

        val jsParts = mutableListOf<String>()
        for (rule in scriptletRules) {
            if (rule.type == FilterRuleType.EXCEPTION) continue
            if (rule.scriptletName == null) continue
            if (rule.scriptletName in exceptionNames) continue

            val def = scriptletRegistry[rule.scriptletName]
            if (def != null) {
                try {
                    val args = rule.scriptletArgs ?: emptyList()
                    if (args.size < def.minArgs) {
                        Log.w(TAG, "Scriptlet ${rule.scriptletName}: needs ${def.minArgs} args, got ${args.size}")
                        continue
                    }
                    val js = def.generator(args)
                    if (js.isNotBlank()) jsParts.add(js)
                } catch (e: Exception) {
                    Log.e(TAG, "Scriptlet gen error ${rule.scriptletName}: ${e.message}")
                }
            } else {
                Log.w(TAG, "Unknown scriptlet: ${rule.scriptletName}")
            }
        }

        if (jsParts.isEmpty()) {
            domainScriptCache[cacheKey] = ""
            cacheTimestamp[cacheKey] = System.currentTimeMillis()
            return null
        }

        val combined = buildString {
            appendLine("// DNC Scriptlet Injection — deepest-network-control")
            appendLine("(function() {")
            appendLine("  'use strict';")
            for (js in jsParts) {
                appendLine("  try {")
                appendLine("    $js")
                appendLine("  } catch(e) { /* DNC scriptlet error */ }")
            }
            appendLine("})();")
        }

        domainScriptCache[cacheKey] = combined
        cacheTimestamp[cacheKey] = System.currentTimeMillis()
        return combined
    }

    fun invalidateCache() {
        domainScriptCache.clear()
        cacheTimestamp.clear()
    }

    fun hasScriptlets(domain: String): Boolean {
        val filterEngine = FilterEngine.getInstance()
        val rules = filterEngine.findScriptlets(domain)
        val hasBlock = rules.any { it.type == FilterRuleType.SCRIPTLET && it.scriptletName != null }
        if (!hasBlock) return false
        val exceptionNames = rules
            .filter { it.type == FilterRuleType.EXCEPTION && it.scriptletName != null }
            .map { it.scriptletName!! }.toSet()
        return rules.any { it.type == FilterRuleType.SCRIPTLET && it.scriptletName !in exceptionNames }
    }

    data class ScriptletStats(
        val registeredCount: Int,
        val cacheSize: Int
    )

    fun getStats(): ScriptletStats = ScriptletStats(
        registeredCount = scriptletRegistry.size,
        cacheSize = domainScriptCache.size
    )
}
