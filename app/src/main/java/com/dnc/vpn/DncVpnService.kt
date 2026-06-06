package com.dnc.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import com.dnc.dns.DnsInterceptor
import com.dnc.proxy.HttpProxy
import com.dnc.proxy.HttpsProxy
import com.dnc.ui.MainActivity
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.nio.ByteBuffer

class DncVpnService : VpnService() {

    companion object {
        const val ACTION_START = "com.dnc.action.START"
        const val ACTION_STOP = "com.dnc.action.STOP"
        const val NOTIFICATION_CHANNEL_ID = "dnc_vpn_channel"
        const val NOTIFICATION_ID = 1
        const val VPN_ADDRESS = "10.0.0.2"
        const val VPN_ROUTE = "0.0.0.0"
        const val VPN_DNS = "10.0.0.1"
        const val VPN_MTU = 1500
        const val TAG = "DncVpnService"

        private val _isRunning = MutableStateFlow(false)
        val isRunning: StateFlow<Boolean> = _isRunning
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private var vpnThread: Thread? = null
    private var isRunning = false

    private lateinit var dnsInterceptor: DnsInterceptor
    private lateinit var httpProxy: HttpProxy
    private lateinit var httpsProxy: HttpsProxy

    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    // Stats
    private val _blockedCount = MutableStateFlow(0)
    private val _dnsQueryCount = MutableStateFlow(0)
    private val _redirectsBlockedCount = MutableStateFlow(0)
    val blockedCount: StateFlow<Int> = _blockedCount
    val dnsQueryCount: StateFlow<Int> = _dnsQueryCount
    val redirectsBlockedCount: StateFlow<Int> = _redirectsBlockedCount

    override fun onCreate() {
        super.onCreate()
        dnsInterceptor = DnsInterceptor(this)
        httpProxy = HttpProxy(this, dnsInterceptor)
        httpsProxy = HttpsProxy(this, dnsInterceptor)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> startVpn()
            ACTION_STOP -> stopVpn()
        }
        return START_STICKY
    }

    private fun startVpn() {
        if (isRunning) return

        createNotificationChannel()

        val notification = buildNotification("DNC Active - Protecting your network")
        startForeground(NOTIFICATION_ID, notification)

        try {
            val builder = Builder()
            builder.addAddress(VPN_ADDRESS, 24)
            builder.addRoute(VPN_ROUTE, 0)
            builder.addDnsServer(VPN_DNS)
            builder.setSession("DNC")
            builder.setMtu(VPN_MTU)
            builder.setBlocking(true)

            vpnInterface = builder.establish()

            if (vpnInterface == null) {
                Log.e(TAG, "Failed to establish VPN interface")
                stopSelf()
                return
            }

            isRunning = true
            _isRunning.value = true
            dnsInterceptor.start()
            httpProxy.start()
            httpsProxy.setHttpProxy(httpProxy) // Wire up HTTP proxy for MITM decrypted traffic
            httpsProxy.start()

            vpnThread = Thread { processPackets() }
            vpnThread?.start()

            Log.i(TAG, "DNC VPN started successfully")

        } catch (e: Exception) {
            Log.e(TAG, "Failed to start VPN: ${e.message}", e)
            stopVpn()
        }
    }

    private fun stopVpn() {
        isRunning = false
        _isRunning.value = false

        try {
            dnsInterceptor.stop()
            httpProxy.stop()
            httpsProxy.stop()
        } catch (e: Exception) {
            Log.e(TAG, "Error stopping proxies: ${e.message}")
        }

        vpnThread?.interrupt()
        vpnThread = null

        try {
            vpnInterface?.close()
        } catch (e: Exception) {
            Log.e(TAG, "Error closing VPN interface: ${e.message}")
        }
        vpnInterface = null

        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()

        Log.i(TAG, "DNC VPN stopped")
    }

    private fun processPackets() {
        val fileDescriptor = vpnInterface?.fileDescriptor ?: return
        val inputStream = FileInputStream(fileDescriptor)
        val outputStream = FileOutputStream(fileDescriptor)
        val packet = ByteArray(VPN_MTU + 28) // IP header max 60 + TCP header max 60 + data

        while (isRunning && !Thread.currentThread().isInterrupted) {
            try {
                val length = inputStream.read(packet)
                if (length <= 0) continue

                val ipPacket = PacketParser.parseIpPacket(packet, length) ?: continue

                when (ipPacket.protocol) {
                    PacketParser.PROTOCOL_UDP -> handleUdpPacket(ipPacket, outputStream)
                    PacketParser.PROTOCOL_TCP -> handleTcpPacket(ipPacket, outputStream)
                    else -> forwardPacket(ipPacket, outputStream)
                }

            } catch (e: InterruptedException) {
                break
            } catch (e: Exception) {
                if (isRunning) {
                    Log.e(TAG, "Error processing packet: ${e.message}")
                }
            }
        }
    }

    private fun handleUdpPacket(ipPacket: IpPacket, outputStream: FileOutputStream) {
        val udpPacket = PacketParser.parseUdpPacket(ipPacket.payload) ?: return

        // Port 53 = DNS
        if (udpPacket.destinationPort == 53) {
            _dnsQueryCount.value += 1
            val response = dnsInterceptor.handleQuery(udpPacket.payload, ipPacket.destinationAddress)
            if (response != null) {
                val responsePacket = PacketParser.buildUdpResponse(
                    sourceIp = ipPacket.destinationAddress,
                    destIp = ipPacket.sourceAddress,
                    sourcePort = 53,
                    destPort = udpPacket.sourcePort,
                    payload = response,
                    ipPacketId = ipPacket.id
                )
                synchronized(outputStream) {
                    outputStream.write(responsePacket)
                }
                return
            }
        }

        // Forward other UDP
        forwardPacket(ipPacket, outputStream)
    }

    private fun handleTcpPacket(ipPacket: IpPacket, outputStream: FileOutputStream) {
        val tcpPacket = PacketParser.parseTcpPacket(ipPacket.payload) ?: return

        when (tcpPacket.destinationPort) {
            80 -> httpProxy.handlePacket(ipPacket, tcpPacket, outputStream)
            443 -> httpsProxy.handlePacket(ipPacket, tcpPacket, outputStream)
            else -> forwardPacket(ipPacket, outputStream)
        }
    }

    private fun forwardPacket(ipPacket: IpPacket, outputStream: FileOutputStream) {
        // For packets we don't filter, forward directly
        // In a full implementation this would use a protected socket
        // For Phase 1, non-HTTP/HTTPS traffic passes through
    }

    fun protectSocket(socket: java.net.Socket): Boolean {
        return protect(socket)
    }

    fun protectSocket(socket: DatagramSocket): Boolean {
        return protect(socket)
    }

    fun incrementBlocked() {
        _blockedCount.value += 1
    }

    fun incrementRedirectsBlocked() {
        _redirectsBlockedCount.value += 1
    }

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            NOTIFICATION_CHANNEL_ID,
            "DNC VPN Service",
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = "Deepest Network Control VPN service status"
            setShowBadge(false)
        }
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(channel)
    }

    private fun buildNotification(text: String): Notification {
        val intent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP
        }
        val pendingIntent = PendingIntent.getActivity(
            this, 0, intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val stopIntent = Intent(this, DncVpnService::class.java).apply {
            action = ACTION_STOP
        }
        val stopPendingIntent = PendingIntent.getService(
            this, 1, stopIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        return Notification.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setContentTitle("Deepest Network Control")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(pendingIntent)
            .addAction(
                android.R.drawable.ic_menu_close_clear_cancel,
                "Stop",
                stopPendingIntent
            )
            .setOngoing(true)
            .build()
    }

    override fun onDestroy() {
        stopVpn()
        serviceScope.cancel()
        super.onDestroy()
    }

    override fun onRevoke() {
        stopVpn()
        super.onRevoke()
    }
}
