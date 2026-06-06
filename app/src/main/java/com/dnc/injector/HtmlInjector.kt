package com.dnc.injector

import android.util.Log
import com.dnc.cosmetic.CosmeticFilter
import com.dnc.scriptlet.ScriptletEngine
import java.nio.charset.Charset

/**
 * HTML response body injection engine.
 *
 * This is the bridge between our filter engines and the actual HTTP response
 * modification. When an HTML response passes through our proxy (HTTP or HTTPS via MITM),
 * HtmlInjector modifies the response body to inject:
 *
 * 1. <style> tags for cosmetic filtering (element hiding via CSS)
 * 2. <script> tags for scriptlet injection (JavaScript overrides)
 *
 * Injection strategy:
 * - For <style>: Inject right after <head> or at the very beginning of the document
 * - For <script>: Inject right after <style> tags, before any other scripts
 * - This ensures our CSS/JS executes BEFORE the page's own content loads
 *
 * Encoding handling:
 * - Detects charset from Content-Type header and <meta> tags
 * - Preserves original encoding in the modified response
 * - Falls back to UTF-8 if charset cannot be determined
 */
class HtmlInjector {

    companion object {
        private const val TAG = "HtmlInjector"
        private const val MAX_HTML_SIZE = 5 * 1024 * 1024 // 5MB
        private const val DNC_MARKER = "data-dnc-injected"

        @Volatile
        private var instance: HtmlInjector? = null

        fun getInstance(): HtmlInjector {
            return instance ?: synchronized(this) {
                instance ?: HtmlInjector().also { instance = it }
            }
        }
    }

    data class InjectionResult(
        val modifiedBody: ByteArray,
        val wasModified: Boolean,
        val cosmeticInjected: Boolean,
        val scriptletsInjected: Boolean
    )

    /**
     * Process an HTML response body and inject cosmetic filters + scriptlets.
     */
    fun inject(
        body: ByteArray,
        domain: String,
        contentType: String?,
        contentEncoding: String? = null
    ): InjectionResult {
        if (body.size > MAX_HTML_SIZE) {
            return InjectionResult(body, false, false, false)
        }

        if (!isHtmlContent(contentType, body)) {
            return InjectionResult(body, false, false, false)
        }

        val bodyStr = body.toString(Charsets.UTF_8)
        if (bodyStr.contains(DNC_MARKER)) {
            return InjectionResult(body, false, false, false)
        }

        val charset = detectCharset(contentType, bodyStr)
        var html = bodyStr

        val cosmeticFilter = CosmeticFilter.getInstance()
        val css = cosmeticFilter.generateCss(domain)
        var cosmeticInjected = false

        val scriptletEngine = ScriptletEngine.getInstance()
        val js = scriptletEngine.generateInjectionScript(domain)
        var scriptletsInjected = false

        if (css == null && js == null) {
            return InjectionResult(body, false, false, false)
        }

        val injectionBlock = buildString {
            if (css != null) {
                appendLine("<style $DNC_MARKER type=\"text/css\">")
                appendLine(css)
                appendLine("</style>")
                cosmeticInjected = true
            }
            if (js != null) {
                appendLine("<script $DNC_MARKER type=\"text/javascript\">")
                appendLine(js)
                appendLine("</script>")
                scriptletsInjected = true
            }
        }

        val modifiedHtml = injectIntoHtml(html, injectionBlock)
        val modifiedBody = modifiedHtml.toByteArray(charset)

        Log.d(TAG, "Injected into $domain: css=$cosmeticInjected js=$scriptletsInjected")

        return InjectionResult(
            modifiedBody = modifiedBody,
            wasModified = true,
            cosmeticInjected = cosmeticInjected,
            scriptletsInjected = scriptletsInjected
        )
    }

    /**
     * Inject the block into the HTML at the optimal position.
     * Strategy: after <head> > after <html> > at the beginning
     */
    private fun injectIntoHtml(html: String, injectionBlock: String): String {
        // After <head...>
        val headIndex = html.indexOf("<head", ignoreCase = true)
        if (headIndex >= 0) {
            val afterHead = findTagEnd(html, headIndex)
            if (afterHead > headIndex) {
                return html.substring(0, afterHead) + "\n" + injectionBlock + html.substring(afterHead)
            }
        }

        // After <html...>
        val htmlIndex = html.indexOf("<html", ignoreCase = true)
        if (htmlIndex >= 0) {
            val afterHtmlTag = findTagEnd(html, htmlIndex)
            if (afterHtmlTag > htmlIndex) {
                return html.substring(0, afterHtmlTag) + "\n<head>" + injectionBlock + "</head>" + html.substring(afterHtmlTag)
            }
        }

        // Fallback: at the beginning
        return injectionBlock + html
    }

    private fun findTagEnd(html: String, startIndex: Int): Int {
        var i = startIndex
        var inQuote = false
        var quoteChar = '"'

        while (i < html.length) {
            val c = html[i]
            if (inQuote) {
                if (c == quoteChar) inQuote = false
            } else {
                when (c) {
                    '"', '\'' -> { inQuote = true; quoteChar = c }
                    '>' -> return i + 1
                }
            }
            i++
        }
        return -1
    }

    private fun isHtmlContent(contentType: String?, body: ByteArray): Boolean {
        if (contentType != null) {
            val ctLower = contentType.lowercase()
            if (ctLower.contains("text/html")) return true
            if (ctLower.contains("application/xhtml")) return true
            if (ctLower.contains("application/json")) return false
            if (ctLower.contains("application/javascript")) return false
            if (ctLower.contains("image/")) return false
            if (ctLower.contains("video/")) return false
            if (ctLower.contains("audio/")) return false
        }

        if (body.size < 20) return false
        val start = String(body, 0, minOf(500, body.size), Charsets.UTF_8).trimStart()
        return start.startsWith("<!DOCTYPE", ignoreCase = true) ||
                start.startsWith("<html", ignoreCase = true) ||
                start.startsWith("<head", ignoreCase = true) ||
                (start.startsWith("<") && start.contains("<body", ignoreCase = true))
    }

    private fun detectCharset(contentType: String?, bodyStr: String): Charset {
        if (contentType != null) {
            val charsetMatch = Regex("charset=([^;\\s]+)", RegexOption.IGNORE_CASE).find(contentType)
            if (charsetMatch != null) {
                try { return Charset.forName(charsetMatch.groupValues[1]) } catch (_: Exception) { }
            }
        }

        val prefix = bodyStr.substring(0, minOf(2000, bodyStr.length))

        val metaCharset = Regex("""<meta[^>]+charset=["']?([^"'\s>]+)""", RegexOption.IGNORE_CASE)
            .find(prefix)
        if (metaCharset != null) {
            try { return Charset.forName(metaCharset.groupValues[1]) } catch (_: Exception) { }
        }

        val httpEquiv = Regex(
            """<meta[^>]+http-equiv=["']?Content-Type["']?[^>]+content=["']?[^"']*charset=([^"'\s;>]+)""",
            RegexOption.IGNORE_CASE
        ).find(prefix)
        if (httpEquiv != null) {
            try { return Charset.forName(httpEquiv.groupValues[1]) } catch (_: Exception) { }
        }

        return Charsets.UTF_8
    }

    /**
     * Update Content-Length header after body modification
     */
    fun updateContentLength(responseStr: String, newBodySize: Int): String {
        return responseStr.replace(
            Regex("Content-Length:\\s*\\d+", RegexOption.IGNORE_CASE),
            "Content-Length: $newBodySize"
        )
    }
}
