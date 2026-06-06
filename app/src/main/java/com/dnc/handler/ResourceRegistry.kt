package com.dnc.handler

import android.util.Log
import java.util.concurrent.ConcurrentHashMap
import android.util.Base64

/**
 * Registry of built-in redirect resources for $redirect rules.
 *
 * When a $redirect rule matches, instead of just dropping the request (which
 * can cause broken images, JavaScript errors, etc.), we serve a neutral replacement
 * that's harmless and invisible. This is exactly how uBlock Origin handles it.
 *
 * Built-in resources:
 * - 1x1.gif — 1x1 transparent GIF pixel (for image/ad slots)
 * - 2x2.png — 2x2 transparent PNG (slightly larger placeholder)
 * - 3x2.png — 3x2 transparent PNG
 * - 1x1.png — 1x1 transparent PNG
 * - blank.html — Empty HTML page
 * - blank.js — Empty JavaScript
 * - blank.css — Empty CSS
 * - blank.txt — Empty text
 * - blank.mp3 — Silent MP3 audio
 * - blank/frame — Empty HTML for iframes
 * - noop.html — HTML that does nothing (no-op)
 * - noop.js — JS that does nothing (no-op function)
 * - noop.css — CSS that does nothing (no-op)
 * - noop.txt — Empty text (no-op)
 * - click2load.html — Placeholder with "click to load" button
 */
class ResourceRegistry {

    companion object {
        private const val TAG = "ResourceRegistry"

        @Volatile
        private var instance: ResourceRegistry? = null

        fun getInstance(): ResourceRegistry {
            return instance ?: synchronized(this) {
                instance ?: ResourceRegistry().also { instance = it }
            }
        }
    }

    data class RedirectResource(
        val name: String,
        val alias: String? = null,
        val contentType: String,
        val data: ByteArray,
        val description: String
    ) {
        override fun equals(other: Any?): Boolean = this === other
        override fun hashCode(): Int = name.hashCode()
    }

    private val resources = ConcurrentHashMap<String, RedirectResource>()

    init {
        registerBuiltinResources()
    }

    /**
     * Get a redirect resource by name or alias
     */
    fun getResource(name: String): RedirectResource? {
        return resources[name] ?: resources.entries.find { it.value.alias == name }?.value
    }

    /**
     * Get all registered resources
     */
    fun getAllResources(): List<RedirectResource> = resources.values.toList()

    /**
     * Register a custom redirect resource
     */
    fun registerResource(resource: RedirectResource) {
        resources[resource.name] = resource
        if (resource.alias != null) {
            resources[resource.alias] = resource
        }
    }

    private fun registerBuiltinResources() {
        // ========== Image Resources ==========

        // 1x1 transparent GIF (43 bytes)
        // GIF89a header + logical screen descriptor + image descriptor + LZW min code + data sub-block + terminator
        val gif1x1 = byteArrayOf(
            0x47, 0x49, 0x46, 0x38, 0x39, 0x61, // GIF89a
            0x01, 0x00, 0x01, 0x00,             // 1x1
            0x80.toByte(), 0x00, 0x00,           // GCT flag, color resolution, sort, GCT size
            0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte(), // Color 0: white (background)
            0x00, 0x00, 0x00,                    // Color 1: black
            0x21, 0xF9.toByte(), 0x04, 0x01,    // GCE: dispose=none, user input, transparent
            0x00, 0x00, 0x00,                    // delay, transparent color index=0
            0x2C, 0x00, 0x00, 0x00, 0x00,       // Image descriptor: left, top
            0x01, 0x00, 0x01, 0x00, 0x00,       // width, height, no LCT
            0x02, 0x02, 0x44, 0x01, 0x00,       // LZW min code, data sub-block
            0x3B                                 // GIF terminator
        )
        registerResource(RedirectResource(
            name = "1x1.gif",
            alias = "1x1-transparent.gif",
            contentType = "image/gif",
            data = gif1x1,
            description = "1x1 transparent GIF pixel"
        ))

        // 1x1 transparent PNG
        val png1x1 = Base64.decode(
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAC0lEQVQI12NgAAIABQAB" +
            "Nl7BcQAAAABJRU5ErkJggg==",
            Base64.DEFAULT
        )
        registerResource(RedirectResource(
            name = "1x1.png",
            alias = "1x1-transparent.png",
            contentType = "image/png",
            data = png1x1,
            description = "1x1 transparent PNG pixel"
        ))

        // 2x2 transparent PNG
        val png2x2 = Base64.decode(
            "iVBORw0KGgoAAAANSUhEUgAAAAIAAAACCAYAAABytg0kAAAAG0lEQVQI12NgAAIABQAB" +
            "Nl7BcQAAAABJRU5ErkJggg==",
            Base64.DEFAULT
        )
        registerResource(RedirectResource(
            name = "2x2.png",
            alias = "2x2-transparent.png",
            contentType = "image/png",
            data = png2x2,
            description = "2x2 transparent PNG"
        ))

        // 3x2 transparent PNG
        val png3x2 = Base64.decode(
            "iVBORw0KGgoAAAANSUhEUgAAAAMAAAACCAYAAACYYJw9AAAAG0lEQVQI12NgAAIABQAB" +
            "Nl7BcQAAAABJRU5ErkJggg==",
            Base64.DEFAULT
        )
        registerResource(RedirectResource(
            name = "3x2.png",
            contentType = "image/png",
            data = png3x2,
            description = "3x2 transparent PNG"
        ))

        // ========== Blank Resources (empty content) ==========

        registerResource(RedirectResource(
            name = "blank.html",
            alias = "empty.html",
            contentType = "text/html",
            data = "<!DOCTYPE html><html><head></head><body></body></html>".toByteArray(),
            description = "Empty HTML page"
        ))

        registerResource(RedirectResource(
            name = "blank.js",
            alias = "empty.js",
            contentType = "application/javascript",
            data = ByteArray(0),
            description = "Empty JavaScript"
        ))

        registerResource(RedirectResource(
            name = "blank.css",
            alias = "empty.css",
            contentType = "text/css",
            data = ByteArray(0),
            description = "Empty CSS"
        ))

        registerResource(RedirectResource(
            name = "blank.txt",
            contentType = "text/plain",
            data = ByteArray(0),
            description = "Empty text"
        ))

        registerResource(RedirectResource(
            name = "blank.mp3",
            contentType = "audio/mpeg",
            data = ByteArray(0),
            description = "Silent/empty MP3"
        ))

        // ========== No-Op Resources (minimal content that doesn't break anything) ==========

        registerResource(RedirectResource(
            name = "noop.html",
            contentType = "text/html",
            data = "<!DOCTYPE html><html><head></head><body></body></html>".toByteArray(),
            description = "No-op HTML (does nothing)"
        ))

        registerResource(RedirectResource(
            name = "noop.js",
            contentType = "application/javascript",
            data = "(function(){})();".toByteArray(),
            description = "No-op JavaScript (empty IIFE)"
        ))

        registerResource(RedirectResource(
            name = "noop.css",
            contentType = "text/css",
            data = "/* DNC noop */".toByteArray(),
            description = "No-op CSS"
        ))

        registerResource(RedirectResource(
            name = "noop.txt",
            contentType = "text/plain",
            data = ByteArray(0),
            description = "No-op text"
        ))

        registerResource(RedirectResource(
            name = "noop.frame",
            contentType = "text/html",
            data = "<!DOCTYPE html><html><head></head><body></body></html>".toByteArray(),
            description = "No-op iframe content"
        ))

        // ========== Click-to-Load Placeholder ==========

        registerResource(RedirectResource(
            name = "click2load.html",
            contentType = "text/html",
            data = """
                <!DOCTYPE html>
                <html>
                <head>
                <style>
                    body { margin: 0; display: flex; align-items: center; justify-content: center;
                           min-height: 100vh; background: #f0f0f0; font-family: sans-serif; }
                    .btn { padding: 12px 24px; background: #666; color: white; border: none;
                           border-radius: 8px; cursor: pointer; font-size: 14px; }
                    .btn:hover { background: #888; }
                </style>
                </head>
                <body>
                <button class="btn" onclick="window.parent.postMessage('dnc-click2load','*')">
                    Load blocked content
                </button>
                </body>
                </html>
            """.trimIndent().toByteArray(),
            description = "Click-to-load placeholder for blocked iframes"
        ))

        // ========== SVG Placeholders ==========

        registerResource(RedirectResource(
            name = "1x1.svg",
            contentType = "image/svg+xml",
            data = """<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"/>""".toByteArray(),
            description = "1x1 transparent SVG"
        ))

        // ========== Common uBO Resource Aliases ==========
        // uBO uses short names — map them to our resources

        registerResource(RedirectResource(
            name = "1x1-transparent.gif",
            contentType = "image/gif",
            data = gif1x1,
            description = "[alias] 1x1 transparent GIF"
        ))

        registerResource(RedirectResource(
            name = "fingerprint2.js",
            contentType = "application/javascript",
            data = "(function(){ /* DNC: fingerprint2 neutralized */ });".toByteArray(),
            description = "Neutralized Fingerprint2 library"
        ))

        registerResource(RedirectResource(
            name = "amazon-apstag.js",
            contentType = "application/javascript",
            data = "(function(){ /* DNC: amazon apstag neutralized */ var apstag={init:function(){},fetchBids:function(){return Promise.resolve([])},setDisplayBids:function(){},targetingKeys:function(){return[]}};window.apstag=apstag;})();".toByteArray(),
            description = "Neutralized Amazon apstag.js"
        ))

        registerResource(RedirectResource(
            name = "google-analytics_analytics.js",
            contentType = "application/javascript",
            data = "(function(){ /* DNC: Google Analytics neutralized */ var ga=function(){return{q:arguments,l:Date.now()}};window.GoogleAnalyticsObject='ga';window[window.GoogleAnalyticsObject]=ga;})();".toByteArray(),
            description = "Neutralized Google Analytics"
        ))

        registerResource(RedirectResource(
            name = "googlesyndication_adsbygoogle.js",
            contentType = "application/javascript",
            data = "(function(){ /* DNC: AdSense neutralized */ window.adsbygoogle={push:function(){},length:0};})();".toByteArray(),
            description = "Neutralized Google AdSense"
        ))

        registerResource(RedirectResource(
            name = "googletagmanager_gtm.js",
            contentType = "application/javascript",
            data = "(function(){ /* DNC: GTM neutralized */ window.dataLayer={push:function(){}};window.gtag=function(){dataLayer.push(arguments)};})();".toByteArray(),
            description = "Neutralized Google Tag Manager"
        ))

        registerResource(RedirectResource(
            name = "facebook_fbevents.js",
            contentType = "application/javascript",
            data = "(function(){ /* DNC: Facebook Pixel neutralized */ window.fbq=function(){};window._fbq=window.fbq;})();".toByteArray(),
            description = "Neutralized Facebook Pixel"
        ))

        Log.i(TAG, "Registered ${resources.size} redirect resources")
    }
}
