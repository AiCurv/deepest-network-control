package com.dnc.filter

import android.util.Log

/**
 * Parses ABP/uBlock Origin filter list format.
 *
 * Supports:
 * - Basic blocking: ||ads.example.com^
 * - Exception rules: @@||example.com^
 * - Domain anchors: ||domain.com and |https://
 * - Path wildcards: /ads/*
 * - Separator wildcard: ^
 * - Regex filters: /regex/
 * - Domain restrictions: $domain=example.com|~foo.example.com
 * - Type options: $script, $image, $stylesheet, etc.
 * - Redirect: $redirect=resource
 * - Remove params: $removeparam=param
 * - CSP: $csp=policy
 * - Cosmetic filters: ##selector
 * - Cosmetic exceptions: #@#selector
 * - Scriptlet injection: ##+js(scriptlet-name, arg1, arg2)
 * - Comments: ! comment
 * - Metadata: ! Title:, ! Last modified:
 */
object FilterListParser {

    private const val TAG = "FilterListParser"

    /**
     * Parse a complete filter list text into a list of FilterRule objects
     */
    fun parseList(rawText: String, listId: String): List<FilterRule> {
        val rules = mutableListOf<FilterRule>()
        val lines = rawText.lines()

        for (line in lines) {
            val trimmed = line.trim()
            if (trimmed.isEmpty()) continue

            val rule = parseRule(trimmed, listId)
            if (rule != null && rule.type != FilterRuleType.COMMENT) {
                rules.add(rule)
            }
        }

        Log.d(TAG, "Parsed ${rules.size} rules from list: $listId")
        return rules
    }

    /**
     * Parse a single filter rule line
     */
    fun parseRule(line: String, listId: String? = null): FilterRule? {
        try {
            // Skip comments
            if (line.startsWith("!") || line.startsWith("#") && !line.contains("##") && !line.contains("#@#")) {
                return FilterRule(
                    rawText = line,
                    type = FilterRuleType.COMMENT,
                    pattern = "",
                    listId = listId
                )
            }

            // Skip metadata lines
            if (line.startsWith("! ") || line.startsWith("[Adblock")) {
                return FilterRule(
                    rawText = line,
                    type = FilterRuleType.COMMENT,
                    pattern = "",
                    listId = listId
                )
            }

            // Scriptlet injection: ##+js(scriptlet, args...)
            if (line.contains("##+js(") || line.contains("#@#+js(")) {
                return parseScriptletRule(line, listId)
            }

            // Cosmetic filters: ##selector or #@#selector
            if (line.contains("##") || line.contains("#@#")) {
                return parseCosmeticRule(line, listId)
            }

            // HTML filtering: ##^tag
            if (line.contains("##^")) {
                return parseHtmlFilterRule(line, listId)
            }

            // Response header filtering: ##^responseheader
            if (line.contains("##^responseheader")) {
                return parseHeaderFilterRule(line, listId)
            }

            // Network filtering rules (blocking/exception)
            return parseNetworkRule(line, listId)

        } catch (e: Exception) {
            Log.w(TAG, "Failed to parse rule: $line — ${e.message}")
            return null
        }
    }

    /**
     * Parse a network filtering rule (blocking or exception)
     */
    private fun parseNetworkRule(line: String, listId: String?): FilterRule? {
        var ruleText = line
        var isException = false

        // Check for exception rule
        if (ruleText.startsWith("@@")) {
            isException = true
            ruleText = ruleText.removePrefix("@@")
        }

        // Split pattern and options
        val optionsStart = findOptionsStart(ruleText)
        val (pattern, optionsText) = if (optionsStart >= 0) {
            ruleText.substring(0, optionsStart) to ruleText.substring(optionsStart + 1)
        } else {
            ruleText to null
        }

        if (pattern.isEmpty()) return null

        // Parse options
        val options = mutableSetOf<FilterOption>()
        var domains: Set<String>? = null
        var excludedDomains = mutableSetOf<String>()
        var redirectResource: String? = null
        var removeParams: String? = null
        var cspDirective: String? = null
        var isImportant = false
        var isBadfilter = false

        if (optionsText != null) {
            val optionParts = optionsText.split(",")
            for (opt in optionParts) {
                val trimmedOpt = opt.trim()
                when {
                    trimmedOpt.startsWith("domain=") -> {
                        val domainList = trimmedOpt.removePrefix("domain=")
                        val (included, excluded) = parseDomainRestrictions(domainList)
                        domains = included
                        excludedDomains = excluded
                    }
                    trimmedOpt.startsWith("redirect=") -> {
                        redirectResource = trimmedOpt.removePrefix("redirect=")
                        options.add(FilterOption.REDIRECT)
                    }
                    trimmedOpt.startsWith("redirect-rule=") -> {
                        redirectResource = trimmedOpt.removePrefix("redirect-rule=")
                        options.add(FilterOption.REDIRECT)
                    }
                    trimmedOpt.startsWith("removeparam=") -> {
                        removeParams = trimmedOpt.removePrefix("removeparam=")
                        options.add(FilterOption.REMOVEPARAM)
                    }
                    trimmedOpt.startsWith("csp=") -> {
                        cspDirective = trimmedOpt.removePrefix("csp=")
                        options.add(FilterOption.CSP)
                    }
                    trimmedOpt == "important" -> isImportant = true
                    trimmedOpt == "badfilter" -> isBadfilter = true
                    trimmedOpt == "third-party" || trimmedOpt == "3p" -> options.add(FilterOption.THIRD_PARTY)
                    trimmedOpt == "~third-party" || trimmedOpt == "1p" -> options.add(FilterOption.FIRST_PARTY)
                    trimmedOpt == "first-party" -> options.add(FilterOption.FIRST_PARTY)
                    trimmedOpt == "match-case" -> options.add(FilterOption.MATCH_CASE)
                    trimmedOpt == "script" || trimmedOpt == "1p-script" || trimmedOpt == "3p-script" -> options.add(FilterOption.SCRIPT)
                    trimmedOpt == "image" -> options.add(FilterOption.IMAGE)
                    trimmedOpt == "stylesheet" || trimmedOpt == "css" -> options.add(FilterOption.STYLESHEET)
                    trimmedOpt == "subdocument" || trimmedOpt == "frame" -> options.add(FilterOption.SUBDOCUMENT)
                    trimmedOpt == "xmlhttprequest" || trimmedOpt == "xhr" -> options.add(FilterOption.XMLHTTPREQUEST)
                    trimmedOpt == "document" || trimmedOpt == "doc" -> options.add(FilterOption.DOCUMENT)
                    trimmedOpt == "popup" || trimmedOpt == "popunder" -> options.add(FilterOption.POPUP)
                    trimmedOpt == "media" -> options.add(FilterOption.MEDIA)
                    trimmedOpt == "font" -> options.add(FilterOption.FONT)
                    trimmedOpt == "websocket" -> options.add(FilterOption.WEBSOCKET)
                    trimmedOpt == "ping" -> options.add(FilterOption.PING)
                    trimmedOpt == "other" -> options.add(FilterOption.OTHER)
                    trimmedOpt == "all" -> {
                        // "all" = script + image + stylesheet + subdocument + xmlhttprequest + popup + media + font + websocket + ping + other
                        options.addAll(listOf(
                            FilterOption.SCRIPT, FilterOption.IMAGE, FilterOption.STYLESHEET,
                            FilterOption.SUBDOCUMENT, FilterOption.XMLHTTPREQUEST, FilterOption.POPUP,
                            FilterOption.MEDIA, FilterOption.FONT, FilterOption.WEBSOCKET,
                            FilterOption.PING, FilterOption.OTHER
                        ))
                    }
                    // Negated options
                    trimmedOpt.startsWith("~") -> {
                        // ~script means "not script" — we don't fully support this
                        // but don't crash on it
                    }
                }
            }
        }

        if (isImportant) options.add(FilterOption.IMPORTANT)
        if (isBadfilter) options.add(FilterOption.BADFILTER)

        // Determine if pattern is a regex
        val isRegex = pattern.startsWith("/") && pattern.endsWith("/") && pattern.length > 2
        val regex = if (isRegex) {
            try {
                val regexStr = pattern.removeSurrounding("/")
                Regex(regexStr, RegexOption.IGNORE_CASE)
            } catch (e: Exception) {
                Log.w(TAG, "Invalid regex pattern: $pattern")
                null
            }
        } else null

        return FilterRule(
            rawText = line,
            type = if (isException) FilterRuleType.EXCEPTION else FilterRuleType.BLOCK,
            pattern = pattern,
            isRegex = isRegex,
            regex = regex,
            options = options,
            domains = domains,
            excludedDomains = excludedDomains,
            redirectResource = redirectResource,
            removeParams = removeParams,
            cspDirective = cspDirective,
            enabled = !isBadfilter,
            listId = listId
        )
    }

    /**
     * Parse a cosmetic filter rule: domain##selector or domain#@#selector
     */
    private fun parseCosmeticRule(line: String, listId: String?): FilterRule? {
        val isException = line.contains("#@#")
        val separator = if (isException) "#@#" else "##"

        val parts = line.split(separator, limit = 2)
        if (parts.size < 2) return null

        val domainPart = parts[0].trim()
        val selector = parts[1].trim()

        if (selector.isEmpty()) return null

        val (domains, excluded) = if (domainPart.isNotEmpty()) {
            parseDomainRestrictions(domainPart.replace(",", "|"))
        } else {
            null to emptySet()
        }

        return FilterRule(
            rawText = line,
            type = if (isException) FilterRuleType.COSMETIC_EXCEPTION else FilterRuleType.COSMETIC,
            pattern = "",
            domains = domains,
            excludedDomains = excluded,
            cosmeticSelector = selector,
            listId = listId
        )
    }

    /**
     * Parse a scriptlet injection rule: domain##+js(scriptlet, arg1, arg2)
     */
    private fun parseScriptletRule(line: String, listId: String?): FilterRule? {
        val isException = line.contains("#@#+js(")
        val separator = if (isException) "#@#+js(" else "##+js("

        val parts = line.split(separator, limit = 2)
        if (parts.size < 2) return null

        val domainPart = parts[0].trim()
        val scriptletPart = parts[1].removeSuffix(")").trim()

        // Parse scriptlet name and args
        val scriptletPieces = scriptletPart.split(",").map { it.trim().removeSurrounding("\"") }
        val scriptletName = scriptletPieces.firstOrNull() ?: return null
        val scriptletArgs = scriptletPieces.drop(1)

        val (domains, excluded) = if (domainPart.isNotEmpty()) {
            parseDomainRestrictions(domainPart.replace(",", "|"))
        } else {
            null to emptySet()
        }

        return FilterRule(
            rawText = line,
            type = if (isException) FilterRuleType.EXCEPTION else FilterRuleType.SCRIPTLET,
            pattern = "",
            domains = domains,
            excludedDomains = excluded,
            scriptletName = scriptletName,
            scriptletArgs = scriptletArgs.ifEmpty { null },
            listId = listId
        )
    }

    /**
     * Parse an HTML filter rule: domain##^tag:has-text(...)
     */
    private fun parseHtmlFilterRule(line: String, listId: String?): FilterRule? {
        val separator = "##^"
        val parts = line.split(separator, limit = 2)
        if (parts.size < 2) return null

        val domainPart = parts[0].trim()
        val filterPart = parts[1].trim()

        val (domains, excluded) = if (domainPart.isNotEmpty()) {
            parseDomainRestrictions(domainPart.replace(",", "|"))
        } else {
            null to emptySet()
        }

        return FilterRule(
            rawText = line,
            type = FilterRuleType.HTML_FILTER,
            pattern = filterPart,
            domains = domains,
            excludedDomains = excluded,
            listId = listId
        )
    }

    /**
     * Parse a response header filter rule: domain##^responseheader(name:)
     */
    private fun parseHeaderFilterRule(line: String, listId: String?): FilterRule? {
        val separator = "##^responseheader("
        val parts = line.split(separator, limit = 2)
        if (parts.size < 2) return null

        val domainPart = parts[0].trim()
        val headerName = parts[1].removeSuffix(")").trim()

        val (domains, excluded) = if (domainPart.isNotEmpty()) {
            parseDomainRestrictions(domainPart.replace(",", "|"))
        } else {
            null to emptySet()
        }

        return FilterRule(
            rawText = line,
            type = FilterRuleType.HEADER,
            pattern = headerName,
            domains = domains,
            excludedDomains = excluded,
            listId = listId
        )
    }

    /**
     * Find where options start in a rule (the $ that's not inside a domain anchor)
     */
    private fun findOptionsStart(rule: String): Int {
        var i = 0
        while (i < rule.length) {
            if (rule[i] == '$') {
                // Make sure it's not part of $$ (regex anchor) or inside a regex
                if (i > 0 && rule[i - 1] == '\\') {
                    i++
                    continue
                }
                return i
            }
            i++
        }
        return -1
    }

    /**
     * Parse domain restrictions: domain1.com|~domain2.com
     * ~ prefix means excluded
     */
    fun parseDomainRestrictions(domainsText: String): Pair<Set<String>, Set<String>> {
        val included = mutableSetOf<String>()
        val excluded = mutableSetOf<String>()

        val parts = domainsText.split("|")
        for (part in parts) {
            val trimmed = part.trim()
            if (trimmed.isEmpty()) continue

            if (trimmed.startsWith("~")) {
                excluded.add(trimmed.removePrefix("~").lowercase())
            } else {
                included.add(trimmed.lowercase())
            }
        }

        return included to excluded
    }
}
