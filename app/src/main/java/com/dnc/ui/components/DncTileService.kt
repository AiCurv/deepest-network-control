package com.dnc.ui.components

import android.content.Intent
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import com.dnc.vpn.DncVpnService

class DncTileService : TileService() {

    override fun onStartListening() {
        super.onStartListening()
        updateTile()
    }

    override fun onClick() {
        super.onClick()

        if (DncVpnService.isRunning.value) {
            // Stop VPN
            val intent = Intent(this, DncVpnService::class.java).apply {
                action = DncVpnService.ACTION_STOP
            }
            startService(intent)
        } else {
            // Start VPN
            val intent = Intent(this, DncVpnService::class.java).apply {
                action = DncVpnService.ACTION_START
            }
            startService(intent)
        }

        updateTile()
    }

    private fun updateTile() {
        val isRunning = DncVpnService.isRunning.value

        qsTile?.apply {
            state = if (isRunning) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
            updateTile()
        }
    }
}
