package com.dnc.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import android.util.Log
import androidx.core.app.NotificationCompat
import com.dnc.R
import com.dnc.ui.MainActivity

/**
 * Helper for creating and updating the VPN foreground service notification.
 *
 * Displays a persistent notification while the VPN is active, showing
 * real-time connection statistics and a stop action.
 */
object VpnNotificationHelper {

    private const val TAG = "VpnNotification"

    // Notification IDs and channel
    const val NOTIFICATION_ID = 1001
    private const val CHANNEL_ID = "dnc_vpn_channel"
    private const val CHANNEL_NAME = "DNC VPN Service"

    // Action constants
    const val ACTION_STOP = "com.dnc.vpn.ACTION_STOP"

    // Notification update throttle (ms)
    private const val UPDATE_THROTTLE_MS = 500L

    // Last notification update timestamp
    private var lastUpdateTime = 0L

    /**
     * Create the notification channel (required on Android 8.0+).
     * Must be called before posting any notification.
     */
    fun createChannel(context: Context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                CHANNEL_NAME,
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Shows when DNC VPN is active and filtering traffic"
                setShowBadge(false)
                lockscreenVisibility = Notification.VISIBILITY_PRIVATE
            }
            val notificationManager =
                context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            notificationManager.createNotificationChannel(channel)
            Log.d(TAG, "Notification channel created")
        }
    }

    /**
     * Build the foreground service notification.
     *
     * @param context Application context.
     * @param requestsBlocked Number of ad/tracker requests blocked.
     * @param dnsQueries Number of DNS queries intercepted.
     * @param activeConnections Number of currently active TCP connections.
     * @return A [Notification] suitable for [android.app.Service.startForeground].
     */
    fun buildNotification(
        context: Context,
        requestsBlocked: Long = 0L,
        dnsQueries: Long = 0L,
        activeConnections: Int = 0
    ): Notification {
        createChannel(context)

        // Intent to open the main activity when the notification is tapped
        val contentIntent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val contentPendingIntent = PendingIntent.getActivity(
            context,
            0,
            contentIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        // Intent to stop the VPN service
        val stopIntent = Intent(context, DncVpnService::class.java).apply {
            action = ACTION_STOP
        }
        val stopPendingIntent = PendingIntent.getService(
            context,
            1,
            stopIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        // Build notification content text with stats
        val contentText = buildContentText(requestsBlocked, dnsQueries, activeConnections)

        return NotificationCompat.Builder(context, CHANNEL_ID)
            .setContentTitle("Deepest Network Control")
            .setContentText(contentText)
            .setSmallIcon(R.drawable.ic_shield)
            .setOngoing(true)
            .setSilent(true)
            .setOnlyAlertOnce(true)
            .setContentIntent(contentPendingIntent)
            .addAction(
                android.R.drawable.ic_menu_close_clear_cancel,
                "Stop VPN",
                stopPendingIntent
            )
            .setStyle(
                NotificationCompat.BigTextStyle()
                    .bigText(contentText)
            )
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .build()
    }

    /**
     * Update the currently displayed notification with new statistics.
     *
     * Throttled to avoid excessive notification updates.
     *
     * @param context Application context.
     * @param requestsBlocked Number of ad/tracker requests blocked.
     * @param dnsQueries Number of DNS queries intercepted.
     * @param activeConnections Number of currently active TCP connections.
     */
    fun updateNotification(
        context: Context,
        requestsBlocked: Long,
        dnsQueries: Long,
        activeConnections: Int
    ) {
        val now = System.currentTimeMillis()
        if (now - lastUpdateTime < UPDATE_THROTTLE_MS) {
            return
        }
        lastUpdateTime = now

        try {
            val notification = buildNotification(
                context,
                requestsBlocked,
                dnsQueries,
                activeConnections
            )
            val notificationManager =
                context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            notificationManager.notify(NOTIFICATION_ID, notification)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to update notification", e)
        }
    }

    /**
     * Build the notification content text showing current stats.
     */
    private fun buildContentText(
        requestsBlocked: Long,
        dnsQueries: Long,
        activeConnections: Int
    ): String {
        val parts = mutableListOf<String>()

        if (requestsBlocked > 0) {
            parts.add("Blocked: $requestsBlocked")
        }
        if (dnsQueries > 0) {
            parts.add("DNS: $dnsQueries")
        }
        if (activeConnections > 0) {
            parts.add("Connections: $activeConnections")
        }

        return if (parts.isEmpty()) {
            "VPN active — protecting your traffic"
        } else {
            parts.joinToString("  •  ")
        }
    }

    /**
     * Cancel the foreground service notification.
     */
    fun cancel(context: Context) {
        try {
            val notificationManager =
                context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            notificationManager.cancel(NOTIFICATION_ID)
            Log.d(TAG, "Notification cancelled")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to cancel notification", e)
        }
    }
}
