package com.dnc.ui

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import com.dnc.data.DncRepository
import com.dnc.ui.screens.*
import com.dnc.ui.theme.DncTheme
import com.dnc.vpn.DncVpnService

class MainActivity : ComponentActivity() {

    private lateinit var repository: DncRepository

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            startVpnService()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        repository = DncRepository(this)

        setContent {
            DncTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    DncApp(
                        onVpnToggle = { enabled ->
                            if (enabled) {
                                requestVpnPermission()
                            } else {
                                stopVpnService()
                            }
                        },
                        repository = repository
                    )
                }
            }
        }
    }

    private fun requestVpnPermission() {
        val intent = VpnService.prepare(this)
        if (intent != null) {
            vpnPermissionLauncher.launch(intent)
        } else {
            // Already prepared
            startVpnService()
        }
    }

    private fun startVpnService() {
        val intent = Intent(this, DncVpnService::class.java).apply {
            action = DncVpnService.ACTION_START
        }
        startForegroundService(intent)
    }

    private fun stopVpnService() {
        val intent = Intent(this, DncVpnService::class.java).apply {
            action = DncVpnService.ACTION_STOP
        }
        startService(intent)
    }
}
