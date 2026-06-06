package com.dnc.scriptlet

/**
 * Library of uBO-compatible scriptlets ported for network-level injection.
 *
 * In uBlock Origin, scriptlets are self-executing JavaScript functions that run
 * in the page context to neutralize anti-adblock, tracking, and annoyance scripts.
 * At the network level, we inject them into the HTML response body via <script> tags
 * before the page reaches the browser.
 *
 * Each scriptlet has:
 * - A canonical name (uBO-compatible)
 * - Optional aliases (for AdGuard compat)
 * - A JS generator function that takes arguments and returns executable JS code
 *
 * Scriptlet categories:
 * - Abort: Prevent inline scripts from executing
 * - Property: Override object properties (set-constant, abort-on-property-read)
 * - Network: Block XHR/Fetch requests by URL pattern
 * - Storage: Manipulate localStorage/sessionStorage
 * - DOM: Modify DOM elements (remove-class, close-window)
 * - Anti-Adblock: Defeat anti-adblock mechanisms
 */
object ScriptletLibrary {

    private val aliases = mapOf(
        "abort-current-inline-script" to listOf("acis", "abort-current-script"),
        "abort-on-property-read" to listOf("aopr", "abort-on-get"),
        "abort-on-property-write" to listOf("aopw", "abort-on-set"),
        "addEventListener-defuser" to listOf("aeld", "prevent-addEventListener"),
        "cookie-remover" to listOf("cookie-remover"),
        "json-prune" to listOf("json-prune"),
        "set-constant" to listOf("set-const", "setConstant"),
        "set-local-storage-item" to listOf("set-ls", "setLocalStorageItem"),
        "set-session-storage-item" to listOf("set-ss", "setSessionStorageItem"),
        "remove-class" to listOf("rc", "removeClass"),
        "close-window" to listOf("window-close", "window.close"),
        "no-window-open-if" to listOf("nowoif", "prevent-window-open"),
        "no-fetch-if" to listOf("nfi", "prevent-fetch"),
        "no-xhr-if" to listOf("nxhi", "prevent-xhr"),
        "no-requestAnimationFrame-if" to listOf("norafi", "prevent-raf"),
        "no-setInterval-if" to listOf("nosiif", "prevent-setInterval"),
        "no-setTimeout-if" to listOf("nostiif", "prevent-setTimeout"),
        "adjust-setInterval" to listOf("asi", "adjust-setInterval"),
        "adjust-setTimeout" to listOf("ast", "adjust-setTimeout"),
        "href-sanitizer" to listOf("href-san"),
        "m3u-prune" to listOf("m3u-prune"),
        "nano-setInterval-booster" to listOf("nsib"),
        "nano-setTimeout-booster" to listOf("nstb"),
        "trusted-set-constant" to listOf("trusted-set-const"),
        "trusted-click-element" to listOf("tce"),
        "trusted-prune-inbound-object" to listOf("tpio"),
        "trusted-replace-outbound-text" to listOf("trot"),
        "trusted-suppress-network-error" to listOf("tsne")
    )

    fun getAliases(name: String): List<String> = aliases[name] ?: emptyList()

    /**
     * Register all built-in scriptlets into the engine
     */
    fun registerAll(engine: ScriptletEngine) {
        // ========== Abort Scriptlets ==========

        engine.registerScriptlet(ScriptletEngine.ScriptletDef(
            name = "abort-current-inline-script",
            description = "Abort inline <script> execution when it matches a property chain",
            minArgs = 1,
            generator = { args ->
                val propertyChain = args[0].escapeJs()
                val scriptContent = args.getOrNull(1)?.escapeJs() ?: ""
                """
                (function() {
                    const chain = '$propertyChain';
                    const content = '$scriptContent';
                    const abort = function() {
                        const parts = chain.split('.');
                        let obj = window;
                        for (let i = 0; i < parts.length - 1; i++) {
                            if (obj[parts[i]] === undefined) return;
                            obj = obj[parts[i]];
                        }
                        const prop = parts[parts.length - 1];
                        const original = Object.getOwnPropertyDescriptor(obj, prop);
                        if (original && original.set) {
                            Object.defineProperty(obj, prop, {
                                set: function(v) {
                                    if (content === '' || (typeof v === 'string' && v.includes(content))) {
                                        throw new ReferenceError(chain + ' setter aborted by DNC');
                                    }
                                    original.set.call(this, v);
                                },
                                get: original.get
                            });
                        }
                    };
                    if (document.readyState === 'loading') {
                        document.addEventListener('DOMContentLoaded', abort);
                    }
                    abort();
                })();
                """.trimIndent()
            }
        ))

        engine.registerScriptlet(ScriptletEngine.ScriptletDef(
            name = "abort-on-property-read",
            description = "Throw when a property on window is read",
            minArgs = 1,
            generator = { args ->
                val chain = args[0].escapeJs()
                """
                (function() {
                    const chain = '$chain';
                    const parts = chain.split('.');
                    const prop = parts.pop();
                    let obj = window;
                    for (const p of parts) {
                        if (obj[p] === undefined) { obj[p] = {}; }
                        obj = obj[p];
                    }
                    Object.defineProperty(obj, prop, {
                        get: function() { throw new ReferenceError(chain + ' read aborted by DNC'); },
                        set: function() {}
                    });
                })();
                """.trimIndent()
            }
        ))

        engine.registerScriptlet(ScriptletEngine.ScriptletDef(
            name = "abort-on-property-write",
            description = "Throw when a property on window is written",
            minArgs = 1,
            generator = { args ->
                val chain = args[0].escapeJs()
                """
                (function() {
                    const chain = '$chain';
                    const parts = chain.split('.');
                    const prop = parts.pop();
                    let obj = window;
                    for (const p of parts) {
                        if (obj[p] === undefined) { obj[p] = {}; }
                        obj = obj[p];
                    }
                    Object.defineProperty(obj, prop, {
                        set: function() { throw new ReferenceError(chain + ' write aborted by DNC'); }
                    });
                })();
                """.trimIndent()
            }
        ))

        // ========== Event Listener Scriptlets ==========

        engine.registerScriptlet(ScriptletEngine.ScriptletDef(
            name = "addEventListener-defuser",
            description = "Prevent addEventListener calls matching event type and selector",
            minArgs = 1,
            generator = { args ->
                val eventType = args[0].escapeJs()
                val selector = args.getOrNull(1)?.escapeJs() ?: ""
                """
                (function() {
                    const evtType = '$eventType';
                    const sel = '$selector';
                    const origAdd = EventTarget.prototype.addEventListener;
                    EventTarget.prototype.addEventListener = function(type, listener, options) {
                        if (type === evtType) {
                            if (sel === '') return;
                            try {
                                if (this.matches && this.matches(sel)) return;
                            } catch(e) {}
                        }
                        return origAdd.call(this, type, listener, options);
                    };
                })();
                """.trimIndent()
            }
        ))

        // ========== Property Override Scriptlets ==========

        engine.registerScriptlet(ScriptletEngine.ScriptletDef(
            name = "set-constant",
            description = "Set a property to a constant value (true, false, null, undefined, noopFunc, etc.)",
            minArgs = 2,
            generator = { args ->
                val chain = args[0].escapeJs()
                val value = args[1].escapeJs()
                val resolvedValue = when (value.lowercase()) {
                    "true" -> "true"
                    "false" -> "false"
                    "null" -> "null"
                    "undefined" -> "undefined"
                    "noopfunc" -> "function(){}"
                    "truefunc" -> "function(){return true}"
                    "falsefunc" -> "function(){return false}"
                    "0" -> "0"
                    "1" -> "1"
                    "''" -> "''"
                    "emptyarray" -> "[]"
                    "emptyobject" -> "{}"
                    else -> "'$value'"
                }
                """
                (function() {
                    const chain = '$chain';
                    const parts = chain.split('.');
                    const prop = parts.pop();
                    let obj = window;
                    for (const p of parts) {
                        if (obj[p] === undefined) { obj[p] = {}; }
                        obj = obj[p];
                    }
                    Object.defineProperty(obj, prop, {
                        get: function() { return $resolvedValue; },
                        set: function() {}
                    });
                })();
                """.trimIndent()
            }
        ))

        engine.registerScriptlet(ScriptletEngine.ScriptletDef(
            name = "trusted-set-constant",
            description = "Like set-constant but allows arbitrary JS expressions as values",
            minArgs = 2,
            requiresTrust = true,
            generator = { args ->
                val chain = args[0].escapeJs()
                val value = args[1].escapeJs()
                """
                (function() {
                    const chain = '$chain';
                    const parts = chain.split('.');
                    const prop = parts.pop();
                    let obj = window;
                    for (const p of parts) {
                        if (obj[p] === undefined) { obj[p] = {}; }
                        obj = obj[p];
                    }
                    try {
                        Object.defineProperty(obj, prop, {
                            get: function() { return $value; },
                            set: function() {}
                        });
                    } catch(e) {}
                })();
                """.trimIndent()
            }
        ))

        // ========== Network Blocking Scriptlets ==========

        engine.registerScriptlet(ScriptletEngine.ScriptletDef(
            name = "no-xhr-if",
            description = "Block XMLHttpRequest matching a URL pattern",
            minArgs = 1,
            generator = { args ->
                val pattern = args[0].escapeJs()
                val responseType = args.getOrNull(1)?.escapeJs() ?: ""
                """
                (function() {
                    const pattern = new RegExp('$pattern');
                    const rType = '$responseType';
                    const origOpen = XMLHttpRequest.prototype.open;
                    XMLHttpRequest.prototype.open = function(method, url) {
                        if (pattern.test(url)) {
                            this.addEventListener('readystatechange', function() {
                                if (this.readyState === 4) {
                                    Object.defineProperty(this, 'responseText', {value: ''});
                                    Object.defineProperty(this, 'response', {value: rType === 'blob' ? new Blob() : ''});
                                    Object.defineProperty(this, 'status', {value: 200});
                                }
                            });
                            return origOpen.apply(this, arguments);
                        }
                        return origOpen.apply(this, arguments);
                    };
                })();
                """.trimIndent()
            }
        ))

        engine.registerScriptlet(ScriptletEngine.ScriptletDef(
            name = "no-fetch-if",
            description = "Block fetch() calls matching a URL pattern",
            minArgs = 1,
            generator = { args ->
                val pattern = args[0].escapeJs()
                """
                (function() {
                    const pattern = new RegExp('$pattern');
                    const origFetch = window.fetch;
                    window.fetch = function(input, init) {
                        const url = typeof input === 'string' ? input : input?.url || '';
                        if (pattern.test(url)) {
                            return Promise.resolve(new Response('', {status: 200}));
                        }
                        return origFetch.apply(this, arguments);
                    };
                })();
                """.trimIndent()
            }
        ))

        engine.registerScriptlet(ScriptletEngine.ScriptletDef(
            name = "no-window-open-if",
            description = "Block window.open() calls matching a URL pattern",
            minArgs = 0,
            generator = { args ->
                val pattern = args.getOrNull(0)?.escapeJs() ?: ""
                """
                (function() {
                    const pattern = '$pattern' ? new RegExp('$pattern') : /.*/;
                    const origOpen = window.open;
                    window.open = function(url) {
                        if (pattern.test(url || '')) { return null; }
                        return origOpen.apply(this, arguments);
                    };
                })();
                """.trimIndent()
            }
        ))

        engine.registerScriptlet(ScriptletEngine.ScriptletDef(
            name = "no-requestAnimationFrame-if",
            description = "Block requestAnimationFrame calls matching a condition",
            minArgs = 1,
            generator = { args ->
                val pattern = args[0].escapeJs()
                """
                (function() {
                    const pattern = new RegExp('$pattern');
                    const origRAF = window.requestAnimationFrame;
                    window.requestAnimationFrame = function(cb) {
                        if (pattern.test(cb.toString())) return 0;
                        return origRAF.apply(this, arguments);
                    };
                })();
                """.trimIndent()
            }
        ))

        engine.registerScriptlet(ScriptletEngine.ScriptletDef(
            name = "no-setInterval-if",
            description = "Block setInterval calls matching a condition",
            minArgs = 0,
            generator = { args ->
                val pattern = args.getOrNull(0)?.escapeJs() ?: ""
                """
                (function() {
                    const pattern = '$pattern' ? new RegExp('$pattern') : null;
                    const origSI = window.setInterval;
                    window.setInterval = function(cb, delay) {
                        if (pattern && pattern.test(cb.toString())) return 0;
                        return origSI.apply(this, arguments);
                    };
                })();
                """.trimIndent()
            }
        ))

        engine.registerScriptlet(ScriptletEngine.ScriptletDef(
            name = "no-setTimeout-if",
            description = "Block setTimeout calls matching a condition",
            minArgs = 0,
            generator = { args ->
                val pattern = args.getOrNull(0)?.escapeJs() ?: ""
                """
                (function() {
                    const pattern = '$pattern' ? new RegExp('$pattern') : null;
                    const origST = window.setTimeout;
                    window.setTimeout = function(cb, delay) {
                        if (pattern && pattern.test(cb.toString())) return 0;
                        return origST.apply(this, arguments);
                    };
                })();
                """.trimIndent()
            }
        ))

        // ========== Storage Scriptlets ==========

        engine.registerScriptlet(ScriptletEngine.ScriptletDef(
            name = "cookie-remover",
            description = "Remove cookies matching a pattern",
            minArgs = 1,
            generator = { args ->
                val pattern = args[0].escapeJs()
                """
                (function() {
                    const pattern = new RegExp('$pattern');
                    const remove = function() {
                        document.cookie.split(';').forEach(function(c) {
                            const name = c.split('=')[0].trim();
                            if (pattern.test(name)) {
                                document.cookie = name + '=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/';
                                document.cookie = name + '=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/; domain=' + location.hostname;
                            }
                        });
                    };
                    remove();
                    setInterval(remove, 1000);
                })();
                """.trimIndent()
            }
        ))

        engine.registerScriptlet(ScriptletEngine.ScriptletDef(
            name = "set-local-storage-item",
            description = "Set a localStorage item to a specific value",
            minArgs = 2,
            generator = { args ->
                val key = args[0].escapeJs()
                val value = args[1].escapeJs()
                """
                (function() {
                    try { localStorage.setItem('$key', '$value'); } catch(e) {}
                })();
                """.trimIndent()
            }
        ))

        engine.registerScriptlet(ScriptletEngine.ScriptletDef(
            name = "set-session-storage-item",
            description = "Set a sessionStorage item to a specific value",
            minArgs = 2,
            generator = { args ->
                val key = args[0].escapeJs()
                val value = args[1].escapeJs()
                """
                (function() {
                    try { sessionStorage.setItem('$key', '$value'); } catch(e) {}
                })();
                """.trimIndent()
            }
        ))

        // ========== DOM Manipulation Scriptlets ==========

        engine.registerScriptlet(ScriptletEngine.ScriptletDef(
            name = "remove-class",
            description = "Remove CSS class from matching elements",
            minArgs = 1,
            generator = { args ->
                val className = args[0].escapeJs()
                val selector = args.getOrNull(1)?.escapeJs() ?: ""
                """
                (function() {
                    const cls = '$className';
                    const sel = '$selector' || '.' + cls;
                    const remove = function() {
                        document.querySelectorAll(sel).forEach(function(el) {
                            el.classList.remove(cls);
                        });
                    };
                    if (document.readyState === 'loading') {
                        document.addEventListener('DOMContentLoaded', remove);
                    }
                    remove();
                    const obs = new MutationObserver(remove);
                    obs.observe(document.documentElement, {childList: true, subtree: true});
                })();
                """.trimIndent()
            }
        ))

        engine.registerScriptlet(ScriptletEngine.ScriptletDef(
            name = "close-window",
            description = "Close the current window/tab",
            minArgs = 0,
            generator = { _ ->
                """
                (function() {
                    window.close();
                })();
                """.trimIndent()
            }
        ))

        // ========== Data Pruning Scriptlets ==========

        engine.registerScriptlet(ScriptletEngine.ScriptletDef(
            name = "json-prune",
            description = "Prune properties from JSON responses (XHR/Fetch)",
            minArgs = 1,
            generator = { args ->
                val prunePath = args[0].escapeJs()
                val needlePath = args.getOrNull(1)?.escapeJs() ?: ""
                """
                (function() {
                    const prunePath = '$prunePath';
                    const needlePath = '$needlePath';
                    const prune = function(obj, path) {
                        const parts = path.split('.');
                        let current = obj;
                        for (let i = 0; i < parts.length - 1; i++) {
                            if (!current || !current[parts[i]]) return;
                            current = current[parts[i]];
                        }
                        if (current) delete current[parts[parts.length - 1]];
                    };
                    const mustProcess = function(raw) {
                        if (needlePath === '') return true;
                        try {
                            const obj = JSON.parse(raw);
                            const parts = needlePath.split('.');
                            let current = obj;
                            for (const p of parts) {
                                if (!current || !current[p]) return false;
                                current = current[p];
                            }
                            return true;
                        } catch(e) { return false; }
                    };
                    const origParse = JSON.parse;
                    JSON.parse = function(text) {
                        const result = origParse.apply(this, arguments);
                        if (typeof text === 'string' && mustProcess(text)) {
                            prune(result, prunePath);
                        }
                        return result;
                    };
                })();
                """.trimIndent()
            }
        ))

        // ========== Adjust Timers ==========

        engine.registerScriptlet(ScriptletEngine.ScriptletDef(
            name = "adjust-setInterval",
            description = "Adjust setInterval timing by boosting or slowing",
            minArgs = 1,
            generator = { args ->
                val matchPattern = args.getOrNull(0)?.escapeJs() ?: ""
                val boostValue = args.getOrNull(1)?.escapeJs() ?: "1"
                """
                (function() {
                    const match = '$matchPattern' ? new RegExp('$matchPattern') : null;
                    const boost = parseFloat('$boostValue') || 1;
                    const origSI = window.setInterval;
                    window.setInterval = function(cb, delay) {
                        if (match && match.test(cb.toString())) {
                            delay = Math.max(1, Math.round(delay * boost));
                        }
                        return origSI.call(this, cb, delay);
                    };
                })();
                """.trimIndent()
            }
        ))

        engine.registerScriptlet(ScriptletEngine.ScriptletDef(
            name = "adjust-setTimeout",
            description = "Adjust setTimeout timing by boosting or slowing",
            minArgs = 1,
            generator = { args ->
                val matchPattern = args.getOrNull(0)?.escapeJs() ?: ""
                val boostValue = args.getOrNull(1)?.escapeJs() ?: "1"
                """
                (function() {
                    const match = '$matchPattern' ? new RegExp('$matchPattern') : null;
                    const boost = parseFloat('$boostValue') || 1;
                    const origST = window.setTimeout;
                    window.setTimeout = function(cb, delay) {
                        if (match && match.test(cb.toString())) {
                            delay = Math.max(1, Math.round(delay * boost));
                        }
                        return origST.call(this, cb, delay);
                    };
                })();
                """.trimIndent()
            }
        ))

        // ========== URL Sanitization ==========

        engine.registerScriptlet(ScriptletEngine.ScriptletDef(
            name = "href-sanitizer",
            description = "Sanitize href attributes to remove tracking parameters",
            minArgs = 1,
            generator = { args ->
                val selector = args[0].escapeJs()
                val source = args.getOrNull(1)?.escapeJs() ?: ""
                """
                (function() {
                    const sel = '$selector';
                    const src = '$source';
                    const clean = function() {
                        document.querySelectorAll(sel).forEach(function(el) {
                            const href = el.getAttribute('href');
                            if (!href) return;
                            try {
                                const url = new URL(href, location.href);
                                const params = url.searchParams;
                                const keep = new Set();
                                if (src) {
                                    const srcUrl = new URL(src, location.href);
                                    srcUrl.searchParams.forEach(function(_, k) { keep.add(k); });
                                }
                                let changed = false;
                                const toRemove = [];
                                params.forEach(function(_, k) {
                                    if (!keep.has(k)) { toRemove.push(k); changed = true; }
                                });
                                toRemove.forEach(function(k) { params.delete(k); });
                                if (changed) el.setAttribute('href', url.toString());
                            } catch(e) {}
                        });
                    };
                    if (document.readyState === 'loading') {
                        document.addEventListener('DOMContentLoaded', clean);
                    }
                    clean();
                })();
                """.trimIndent()
            }
        ))

        // ========== Trusted Scriptlets ==========

        engine.registerScriptlet(ScriptletEngine.ScriptletDef(
            name = "trusted-click-element",
            description = "Automatically click elements matching a selector after delay",
            minArgs = 1,
            requiresTrust = true,
            generator = { args ->
                val selector = args[0].escapeJs()
                val delay = args.getOrNull(1)?.escapeJs() ?: "0"
                """
                (function() {
                    const sel = '$selector';
                    const delay = parseInt('$delay') || 0;
                    const click = function() {
                        const el = document.querySelector(sel);
                        if (el) el.click();
                    };
                    setTimeout(click, delay);
                })();
                """.trimIndent()
            }
        ))
    }

    /**
     * Escape a string for safe insertion into JS single-quoted strings
     */
    private fun String.escapeJs(): String {
        return this
            .replace("\\", "\\\\")
            .replace("'", "\\'")
            .replace("\n", "\\n")
            .replace("\r", "\\r")
            .replace("\$", "\\$")
    }
}
