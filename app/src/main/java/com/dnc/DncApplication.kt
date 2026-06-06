package com.dnc

import android.app.Application
import com.dnc.filter.FilterEngine
import com.dnc.scriptlet.ScriptletEngine
import com.dnc.cosmetic.CosmeticFilter
import com.dnc.handler.AdvancedRuleHandlers
import com.dnc.handler.ResourceRegistry
import com.dnc.injector.HtmlInjector

class DncApplication : Application() {
    override fun onCreate() {
        super.onCreate()

        // Initialize Phase 1-2: Core filter engine
        val filterEngine = FilterEngine.init(this)

        // Initialize Phase 4: Script engine & advanced filtering
        ScriptletEngine.init()
        CosmeticFilter.getInstance()
        AdvancedRuleHandlers.getInstance()
        ResourceRegistry.getInstance()
        HtmlInjector.getInstance()

        // Rebuild generic cosmetic rules from loaded filter lists
        CosmeticFilter.getInstance().rebuildGenericRules()
    }
}
