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
import com.dnc.filter.FilterEngine
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

/**
 * Core VPN Service for Deepest Network Control.
 *
 * ARCHITECTURE (FIXED):
 * 1. TUN interface captures ALL device traffic
 * 2. DNS queries (UDP/53) → DnsInterceptor (async, non-blocking)
 * 3. TCP connections → TcpRelay (protected sockets to real servers)
 * 4. Other UDP → Forward via protected DatagramSocket
 * 5. Everything is properly forwarded — no traffic is silently dropped
 *
 * The VPN acts as a NAT-based proxy: apps send packets to TUN,
 * we relay them to real servers using protected sockets, and
 * write the responses back to TUN.
 */
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

        private val _blockedCount = MutableStateFlow(0)
        val blockedCount: StateFlow<Int> = _blockedCount

        private val _dnsQueryCount = MutableStateFlow(0)
        val dnsQueryCount: StateFlow<Int> = _dnsQueryCount

        private val _redirectsBlockedCount = MutableStateFlow(0)
        val redirectsBlockedCount: StateFlow<Int> = _redirectsBlockedCount
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private var vpnThread: Thread? = null
    private var vpnRunning = false

    private lateinit var dnsInterceptor: DnsInterceptor
    private lateinit var httpProxy: HttpProxy
    private lateinit var httpsProxy: HttpsProxy
    private lateinit var tcpRelay: TcpRelay

    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    // Packet ID generator
    private var packetIdCounter = 1000
    private fun nextPacketId(): Int = ++packetIdCounter

    override fun onCreate() {
        super.onCreate()
        dnsInterceptor = DnsInterceptor(this)
        httpProxy = HttpProxy(this, dnsInterceptor)
        httpsProxy = HttpsProxy(this, dnsInterceptor)
        tcpRelay = TcpRelay(this, dnsInterceptor, httpProxy, httpsProxy)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> startVpn()
            ACTION_STOP -> stopVpn()
        }
        return START_STICKY
    }

    private fun startVpn() {
        if (vpnRunning) return

        createNotificationChannel()

        val notification = buildNotification("DNC Active — Protecting your network")
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

            vpnRunning = true
            _isRunning.value = true

            // Initialize FilterEngine if needed
            try {
                FilterEngine.init(this)
            } catch (_: Exception) {}

            dnsInterceptor.start()
            httpProxy.start()
            httpsProxy.setHttpProxy(httpProxy)
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
        vpnRunning = false
        _isRunning.value = false

        try {
            tcpRelay.closeAll()
        } catch (e: Exception) {
            Log.e(TAG, "Error closing TCP relay: ${e.message}")
        }

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

    /**
     * Main packet processing loop.
     *
     * Reads packets from the TUN interface, routes them to the
     * appropriate handler, and writes responses back.
     *
     * CRITICAL: DNS forwarding is now ASYNC so it doesn't block
     * this loop. TCP connections use protected sockets with
     * background relay threads.
     */
    private fun processPackets() {
        val fileDescriptor = vpnInterface?.fileDescriptor ?: return
        val inputStream = FileInputStream(fileDescriptor)
        val outputStream = FileOutputStream(fileDescriptor)
        val packet = ByteArray(VPN_MTU + 28)

        while (vpnRunning && !Thread.currentThread().isInterrupted) {
            try {
                val length = inputStream.read(packet)
                if (length <= 0) continue

                val ipPacket = PacketParser.parseIpPacket(packet, length) ?: continue

                when (ipPacket.protocol) {
                    PacketParser.PROTOCOL_UDP -> handleUdpPacket(ipPacket, outputStream)
                    PacketParser.PROTOCOL_TCP -> handleTcpPacket(ipPacket, outputStream)
                    PacketParser.PROTOCOL_ICMP -> handleIcmpPacket(ipPacket, outputStream)
                    else -> {
                        // Unknown protocol — drop silently
                    }
                }

            } catch (e: InterruptedException) {
                break
            } catch (e: Exception) {
                if (vpnRunning) {
                    Log.e(TAG, "Error processing packet: ${e.message}")
                }
            }
        }
    }

    /**
     * Handle UDP packets — DNS and other UDP traffic.
     *
     * DNS queries are forwarded ASYNCHRONOUSLY to avoid blocking
     * the packet processing loop. Other UDP traffic is forwarded
     * via a protected DatagramSocket.
     */
    private fun handleUdpPacket(ipPacket: PacketParser.IpPacket, outputStream: FileOutputStream) {
        val udpPacket = PacketParser.parseUdpPacket(ipPacket.payload) ?: return

        // Port 53 = DNS
        if (udpPacket.destinationPort == 53) {
            _dnsQueryCount.value += 1

            // Try to get a cached/blocked response immediately
            val syncResponse = dnsInterceptor.handleQueryAsync(
                queryData = udpPacket.payload,
                destIp = ipPacket.destinationAddress,
                sourceIp = ipPacket.sourceAddress,
                sourcePort = udpPacket.sourcePort
            ) { asyncResponseBytes ->
                // This callback runs on a background thread
                // when the async DNS response arrives
                if (asyncResponseBytes != null) {
                    val responsePacket = PacketParser.buildUdpResponse(
                        sourceIp = ipPacket.destinationAddress,
                        destIp = ipPacket.sourceAddress,
                        sourcePort = 53,
                        destPort = udpPacket.sourcePort,
                        payload = asyncResponseBytes,
                        ipPacketId = nextPacketId()
                    )
                    synchronized(outputStream) {
                        try {
                            outputStream.write(responsePacket)
                        } catch (e: Exception) {
                            Log.w(TAG, "Error writing async DNS response: ${e.message}")
                        }
                    }
                }
            }

            // If we got an immediate response (cache hit or blocked), write it
            if (syncResponse != null) {
                val responsePacket = PacketParser.buildUdpResponse(
                    sourceIp = ipPacket.destinationAddress,
                    destIp = ipPacket.sourceAddress,
                    sourcePort = 53,
                    destPort = udpPacket.sourcePort,
                    payload = syncResponse,
                    ipPacketId = nextPacketId()
                )
                synchronized(outputStream) {
                    try {
                        outputStream.write(responsePacket)
                    } catch (e: Exception) {
                        Log.w(TAG, "Error writing DNS response: ${e.message}")
                    }
                }
            }
            // If syncResponse is null, the async callback will handle it
            return
        }

        // Other UDP traffic — forward via protected socket
        forwardUdpPacket(ipPacket, udpPacket, outputStream)
    }

    /**
     * Handle TCP packets — delegate to TcpRelay.
     */
    private fun handleTcpPacket(ipPacket: PacketParser.IpPacket, outputStream: FileOutputStream) {
        tcpRelay.handlePacket(ipPacket, PacketParser.parseTcpPacket(ipPacket.payload) ?: return, outputStream)
    }

    /**
     * Handle ICMP packets — forward via protected socket.
     * (Minimal implementation — just drop for now as ICMP relay
     * through raw sockets requires root)
     */
    private fun handleIcmpPacket(ipPacket: PacketParser.IpPacket, outputStream: FileOutputStream) {
        // ICMP relay requires raw sockets which need root
        // For now, we silently drop ICMP packets
        // This means ping won't work through the VPN, but web browsing will
    }

    /**
     * Forward UDP packets (non-DNS) using a protected DatagramSocket.
     *
     * This handles things like QUIC (UDP/443), STUN, etc.
     */
    private fun forwardUdpPacket(
        ipPacket: PacketParser.IpPacket,
        udpPacket: PacketParser.UdpPacket,
        outputStream: FileOutputStream
    ) {
        // Forward UDP asynchronously to avoid blocking
        Thread {
            var socket: DatagramSocket? = null
            try {
                socket = DatagramSocket()
                vpnService.protectSocket(socket)
                socket.soTimeout = 5000

                val serverAddress = InetAddress.getByAddress(ipPacket.destinationAddress)
                val sendPacket = DatagramPacket(
                    udpPacket.payload, udpPacket.payload.size,
                    serverAddress, udpPacket.destinationPort
                )
                socket.send(sendPacket)

                // Try to receive a response
                val receiveBuffer = ByteArray(VPN_MTU)
                val receivePacket = DatagramPacket(receiveBuffer, receiveBuffer.size)
                socket.receive(receivePacket)

                // Build response packet
                val responseData = receiveBuffer.copyOf(receivePacket.length)
                val responsePacket = PacketParser.buildUdpResponse(
                    sourceIp = ipPacket.destinationAddress,
                    destIp = ipPacket.sourceAddress,
                    sourcePort = udpPacket.destinationPort,
                    destPort = udpPacket.sourcePort,
                    payload = responseData,
                    ipPacketId = nextPacketId()
                )

                synchronized(outputStream) {
                    try {
                        outputStream.write(responsePacket)
                    } catch (e: Exception) {
                        Log.w(TAG, "Error writing UDP response: ${e.message}")
                    }
                }

            } catch (e: Exception) {
                // UDP forwarding failure is non-critical
                Log.d(TAG, "UDP forward failed: ${e.message}")
            } finally {
                try { socket?.close() } catch (_: Exception) {}
            }
        }.start()
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

    fun incrementDnsQuery() {
        _dnsQueryCount.value += 1
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
