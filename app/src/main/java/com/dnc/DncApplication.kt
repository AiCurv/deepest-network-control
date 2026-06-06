package com.dnc

import android.app.Application
import com.dnc.filter.FilterEngine

class DncApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        // Initialize the filter engine
        FilterEngine.init(this)
    }
}
