package com.dnc.vpn

import java.net.InetAddress
import java.nio.ByteBuffer

object PacketParser {

    const val PROTOCOL_TCP = 6
    const val PROTOCOL_UDP = 17
    const val PROTOCOL_ICMP = 1

    private const val TAG = "PacketParser"

    // ========== Data Classes ==========

    data class IpPacket(
        val version: Int,
        val ihl: Int,
        val totalLength: Int,
        val id: Int,
        val flags: Int,
        val fragmentOffset: Int,
        val ttl: Int,
        val protocol: Int,
        val sourceAddress: ByteArray,
        val destinationAddress: ByteArray,
        val payload: ByteArray
    ) {
        val sourceIp: String
            get() = InetAddress.getByAddress(sourceAddress).hostAddress ?: "unknown"

        val destinationIp: String
            get() = InetAddress.getByAddress(destinationAddress).hostAddress ?: "unknown"
    }

    data class TcpPacket(
        val sourcePort: Int,
        val destinationPort: Int,
        val sequenceNumber: Long,
        val acknowledgmentNumber: Long,
        val dataOffset: Int,
        val flags: Int,
        val windowSize: Int,
        val urgentPointer: Int,
        val payload: ByteArray
    ) {
        val isSyn: Boolean get() = (flags and 0x02) != 0
        val isAck: Boolean get() = (flags and 0x10) != 0
        val isFin: Boolean get() = (flags and 0x01) != 0
        val isRst: Boolean get() = (flags and 0x04) != 0
        val isSynAck: Boolean get() = isSyn && isAck
        val hasPayload: Boolean get() = payload.isNotEmpty()

        companion object {
            const val FLAG_FIN = 0x01
            const val FLAG_SYN = 0x02
            const val FLAG_RST = 0x04
            const val FLAG_PSH = 0x08
            const val FLAG_ACK = 0x10
        }
    }

    data class UdpPacket(
        val sourcePort: Int,
        val destinationPort: Int,
        val length: Int,
        val payload: ByteArray
    )

    // ========== Parse IP Packet ==========

    fun parseIpPacket(data: ByteArray, length: Int): IpPacket? {
        if (length < 20) return null // Minimum IPv4 header

        val version = (data[0].toInt() shr 4) and 0x0F
        if (version != 4) return null // Only IPv4 for now

        val ihl = (data[0].toInt() and 0x0F) * 4
        if (ihl < 20 || length < ihl) return null

        val totalLength = ((data[2].toInt() and 0xFF) shl 8) or (data[3].toInt() and 0xFF)
        val id = ((data[4].toInt() and 0xFF) shl 8) or (data[5].toInt() and 0xFF)
        val flags = (data[6].toInt() and 0xE0) shr 5
        val fragmentOffset = ((data[6].toInt() and 0x1F) shl 8) or (data[7].toInt() and 0xFF)
        val ttl = data[8].toInt() and 0xFF
        val protocol = data[9].toInt() and 0xFF

        val sourceAddress = data.copyOfRange(12, 16)
        val destinationAddress = data.copyOfRange(16, 20)

        val payloadLength = minOf(totalLength, length) - ihl
        if (payloadLength < 0) return null
        val payload = data.copyOfRange(ihl, ihl + payloadLength)

        return IpPacket(
            version = version,
            ihl = ihl,
            totalLength = totalLength,
            id = id,
            flags = flags,
            fragmentOffset = fragmentOffset,
            ttl = ttl,
            protocol = protocol,
            sourceAddress = sourceAddress,
            destinationAddress = destinationAddress,
            payload = payload
        )
    }

    // ========== Parse TCP Packet ==========

    fun parseTcpPacket(data: ByteArray): TcpPacket? {
        if (data.size < 20) return null // Minimum TCP header

        val sourcePort = ((data[0].toInt() and 0xFF) shl 8) or (data[1].toInt() and 0xFF)
        val destinationPort = ((data[2].toInt() and 0xFF) shl 8) or (data[3].toInt() and 0xFF)
        val sequenceNumber = ByteBuffer.wrap(data, 4, 4).int.toLong() and 0xFFFFFFFFL
        val acknowledgmentNumber = ByteBuffer.wrap(data, 8, 4).int.toLong() and 0xFFFFFFFFL
        val dataOffset = ((data[12].toInt() and 0xF0) shr 4) * 4
        val flags = data[13].toInt() and 0x3F
        val windowSize = ((data[14].toInt() and 0xFF) shl 8) or (data[15].toInt() and 0xFF)
        val urgentPointer = ((data[18].toInt() and 0xFF) shl 8) or (data[19].toInt() and 0xFF)

        if (dataOffset < 20 || data.size < dataOffset) return null

        val payloadLength = data.size - dataOffset
        val payload = if (payloadLength > 0) data.copyOfRange(dataOffset, data.size) else ByteArray(0)

        return TcpPacket(
            sourcePort = sourcePort,
            destinationPort = destinationPort,
            sequenceNumber = sequenceNumber,
            acknowledgmentNumber = acknowledgmentNumber,
            dataOffset = dataOffset,
            flags = flags,
            windowSize = windowSize,
            urgentPointer = urgentPointer,
            payload = payload
        )
    }

    // ========== Parse UDP Packet ==========

    fun parseUdpPacket(data: ByteArray): UdpPacket? {
        if (data.size < 8) return null // Minimum UDP header

        val sourcePort = ((data[0].toInt() and 0xFF) shl 8) or (data[1].toInt() and 0xFF)
        val destinationPort = ((data[2].toInt() and 0xFF) shl 8) or (data[3].toInt() and 0xFF)
        val length = ((data[4].toInt() and 0xFF) shl 8) or (data[5].toInt() and 0xFF)

        if (length < 8 || data.size < length) return null

        val payloadLength = length - 8
        val payload = if (payloadLength > 0) data.copyOfRange(8, 8 + payloadLength) else ByteArray(0)

        return UdpPacket(
            sourcePort = sourcePort,
            destinationPort = destinationPort,
            length = length,
            payload = payload
        )
    }

    // ========== Build UDP Response ==========

    fun buildUdpResponse(
        sourceIp: ByteArray,
        destIp: ByteArray,
        sourcePort: Int,
        destPort: Int,
        payload: ByteArray,
        ipPacketId: Int = 0
    ): ByteArray {
        // UDP header (8 bytes) + payload
        val udpLength = 8 + payload.size
        val udpHeader = ByteBuffer.allocate(8)
        udpHeader.putShort(sourcePort.toShort())
        udpHeader.putShort(destPort.toShort())
        udpHeader.putShort(udpLength.toShort())
        udpHeader.putShort(0) // checksum (0 = disabled for IPv4)

        val udpData = ByteArray(udpLength)
        System.arraycopy(udpHeader.array(), 0, udpData, 0, 8)
        System.arraycopy(payload, 0, udpData, 8, payload.size)

        // IP header (20 bytes) + UDP
        val totalLength = 20 + udpLength
        val ipBuffer = ByteBuffer.allocate(totalLength)

        // Version + IHL
        ipBuffer.put((0x45).toByte()) // IPv4, IHL=5 (20 bytes)
        ipBuffer.put(0) // DSCP/ECN
        ipBuffer.putShort(totalLength.toShort())
        ipBuffer.putShort(ipPacketId.toShort()) // ID
        ipBuffer.putShort(0x4000.toShort()) // Don't fragment
        ipBuffer.put(64.toByte()) // TTL
        ipBuffer.put(PROTOCOL_UDP.toByte()) // Protocol: UDP
        ipBuffer.putShort(0) // Checksum (will compute)

        // Source and destination IPs
        ipBuffer.put(sourceIp)
        ipBuffer.put(destIp)

        // Compute IP checksum
        val ipArray = ipBuffer.array()
        val checksum = computeChecksum(ipArray, 0, 20)
        ipArray[10] = (checksum shr 8).toByte()
        ipArray[11] = (checksum and 0xFF).toByte()

        // Append UDP data
        System.arraycopy(udpData, 0, ipArray, 20, udpLength)

        return ipArray
    }

    // ========== Build TCP SYN-ACK Response ==========

    fun buildTcpSynAck(
        sourceIp: ByteArray,
        destIp: ByteArray,
        sourcePort: Int,
        destPort: Int,
        seqNum: Long,
        ackNum: Long,
        ipPacketId: Int = 0
    ): ByteArray {
        val tcpHeaderSize = 24 // 20 base + 4 for MSS option
        val totalLength = 20 + tcpHeaderSize
        val ipBuffer = ByteBuffer.allocate(totalLength)

        // IP header
        ipBuffer.put((0x45).toByte())
        ipBuffer.put(0)
        ipBuffer.putShort(totalLength.toShort())
        ipBuffer.putShort(ipPacketId.toShort())
        ipBuffer.putShort(0x4000.toShort())
        ipBuffer.put(64.toByte())
        ipBuffer.put(PROTOCOL_TCP.toByte())
        ipBuffer.putShort(0) // checksum placeholder
        ipBuffer.put(sourceIp)
        ipBuffer.put(destIp)

        val ipArray = ipBuffer.array()
        val ipChecksum = computeChecksum(ipArray, 0, 20)
        ipArray[10] = (ipChecksum shr 8).toByte()
        ipArray[11] = (ipChecksum and 0xFF).toByte()

        // TCP header
        val tcpBuffer = ByteBuffer.allocate(tcpHeaderSize)
        tcpBuffer.putShort(sourcePort.toShort())
        tcpBuffer.putShort(destPort.toShort())
        tcpBuffer.putInt((seqNum and 0xFFFFFFFFL).toInt())
        tcpBuffer.putInt((ackNum and 0xFFFFFFFFL).toInt())
        tcpBuffer.put((6 shl 4).toByte()) // data offset = 6 (24 bytes)
        tcpBuffer.put((TcpPacket.FLAG_SYN or TcpPacket.FLAG_ACK).toByte())
        tcpBuffer.putShort(65535.toShort()) // window
        tcpBuffer.putShort(0) // checksum placeholder
        tcpBuffer.putShort(0) // urgent pointer

        // MSS option (kind=2, length=4, mss=1460)
        tcpBuffer.put(2)
        tcpBuffer.put(4)
        tcpBuffer.putShort(1460)

        System.arraycopy(tcpBuffer.array(), 0, ipArray, 20, tcpHeaderSize)

        // Compute TCP checksum
        val tcpChecksum = computeTcpChecksum(sourceIp, destIp, ipArray, 20, tcpHeaderSize)
        ipArray[36] = (tcpChecksum shr 8).toByte()
        ipArray[37] = (tcpChecksum and 0xFF).toByte()

        return ipArray
    }

    // ========== Build TCP ACK Packet ==========

    fun buildTcpAck(
        sourceIp: ByteArray,
        destIp: ByteArray,
        sourcePort: Int,
        destPort: Int,
        seqNum: Long,
        ackNum: Long,
        ipPacketId: Int = 0
    ): ByteArray {
        val tcpHeaderSize = 20
        val totalLength = 20 + tcpHeaderSize
        val ipBuffer = ByteBuffer.allocate(totalLength)

        // IP header
        ipBuffer.put((0x45).toByte())
        ipBuffer.put(0)
        ipBuffer.putShort(totalLength.toShort())
        ipBuffer.putShort(ipPacketId.toShort())
        ipBuffer.putShort(0x4000.toShort())
        ipBuffer.put(64.toByte())
        ipBuffer.put(PROTOCOL_TCP.toByte())
        ipBuffer.putShort(0) // checksum placeholder
        ipBuffer.put(sourceIp)
        ipBuffer.put(destIp)

        val ipArray = ipBuffer.array()
        val ipChecksum = computeChecksum(ipArray, 0, 20)
        ipArray[10] = (ipChecksum shr 8).toByte()
        ipArray[11] = (ipChecksum and 0xFF).toByte()

        // TCP header
        val tcpBuffer = ByteBuffer.allocate(tcpHeaderSize)
        tcpBuffer.putShort(sourcePort.toShort())
        tcpBuffer.putShort(destPort.toShort())
        tcpBuffer.putInt((seqNum and 0xFFFFFFFFL).toInt())
        tcpBuffer.putInt((ackNum and 0xFFFFFFFFL).toInt())
        tcpBuffer.put((5 shl 4).toByte()) // data offset = 5 (20 bytes)
        tcpBuffer.put(TcpPacket.FLAG_ACK.toByte())
        tcpBuffer.putShort(65535.toShort()) // window
        tcpBuffer.putShort(0) // checksum placeholder
        tcpBuffer.putShort(0) // urgent pointer

        System.arraycopy(tcpBuffer.array(), 0, ipArray, 20, tcpHeaderSize)

        // Compute TCP checksum
        val tcpChecksum = computeTcpChecksum(sourceIp, destIp, ipArray, 20, tcpHeaderSize)
        ipArray[34] = (tcpChecksum shr 8).toByte()
        ipArray[35] = (tcpChecksum and 0xFF).toByte()

        return ipArray
    }

    // ========== Build TCP Data Packet ==========

    fun buildTcpDataPacket(
        sourceIp: ByteArray,
        destIp: ByteArray,
        sourcePort: Int,
        destPort: Int,
        seqNum: Long,
        ackNum: Long,
        payload: ByteArray,
        flags: Int = TcpPacket.FLAG_ACK or TcpPacket.FLAG_PSH,
        ipPacketId: Int = 0
    ): ByteArray {
        val tcpHeaderSize = 20
        val totalLength = 20 + tcpHeaderSize + payload.size
        val ipBuffer = ByteBuffer.allocate(totalLength)

        // IP header
        ipBuffer.put((0x45).toByte())
        ipBuffer.put(0)
        ipBuffer.putShort(totalLength.toShort())
        ipBuffer.putShort(ipPacketId.toShort())
        ipBuffer.putShort(0x4000.toShort())
        ipBuffer.put(64.toByte())
        ipBuffer.put(PROTOCOL_TCP.toByte())
        ipBuffer.putShort(0) // checksum placeholder
        ipBuffer.put(sourceIp)
        ipBuffer.put(destIp)

        val ipArray = ipBuffer.array()
        val ipChecksum = computeChecksum(ipArray, 0, 20)
        ipArray[10] = (ipChecksum shr 8).toByte()
        ipArray[11] = (ipChecksum and 0xFF).toByte()

        // TCP header
        val tcpBuffer = ByteBuffer.allocate(tcpHeaderSize)
        tcpBuffer.putShort(sourcePort.toShort())
        tcpBuffer.putShort(destPort.toShort())
        tcpBuffer.putInt((seqNum and 0xFFFFFFFFL).toInt())
        tcpBuffer.putInt((ackNum and 0xFFFFFFFFL).toInt())
        tcpBuffer.put((5 shl 4).toByte()) // data offset = 5 (20 bytes)
        tcpBuffer.put(flags.toByte())
        tcpBuffer.putShort(65535.toShort()) // window
        tcpBuffer.putShort(0) // checksum placeholder
        tcpBuffer.putShort(0) // urgent pointer

        System.arraycopy(tcpBuffer.array(), 0, ipArray, 20, tcpHeaderSize)

        // TCP payload
        if (payload.isNotEmpty()) {
            System.arraycopy(payload, 0, ipArray, 20 + tcpHeaderSize, payload.size)
        }

        // Compute TCP checksum
        val tcpChecksum = computeTcpChecksum(sourceIp, destIp, ipArray, 20, tcpHeaderSize + payload.size)
        ipArray[34] = (tcpChecksum shr 8).toByte()
        ipArray[35] = (tcpChecksum and 0xFF).toByte()

        return ipArray
    }

    // ========== Build TCP FIN Packet ==========

    fun buildTcpFin(
        sourceIp: ByteArray,
        destIp: ByteArray,
        sourcePort: Int,
        destPort: Int,
        seqNum: Long,
        ackNum: Long,
        ipPacketId: Int = 0
    ): ByteArray {
        return buildTcpDataPacket(
            sourceIp, destIp, sourcePort, destPort,
            seqNum, ackNum, ByteArray(0),
            flags = TcpPacket.FLAG_FIN or TcpPacket.FLAG_ACK,
            ipPacketId = ipPacketId
        )
    }

    // ========== Build TCP RST Packet ==========

    fun buildTcpRst(
        sourceIp: ByteArray,
        destIp: ByteArray,
        sourcePort: Int,
        destPort: Int,
        seqNum: Long,
        ipPacketId: Int = 0
    ): ByteArray {
        val tcpHeaderSize = 20
        val totalLength = 20 + tcpHeaderSize
        val ipBuffer = ByteBuffer.allocate(totalLength)

        // IP header
        ipBuffer.put((0x45).toByte())
        ipBuffer.put(0)
        ipBuffer.putShort(totalLength.toShort())
        ipBuffer.putShort(ipPacketId.toShort())
        ipBuffer.putShort(0x4000.toShort())
        ipBuffer.put(64.toByte())
        ipBuffer.put(PROTOCOL_TCP.toByte())
        ipBuffer.putShort(0)
        ipBuffer.put(sourceIp)
        ipBuffer.put(destIp)

        val ipArray = ipBuffer.array()
        val ipChecksum = computeChecksum(ipArray, 0, 20)
        ipArray[10] = (ipChecksum shr 8).toByte()
        ipArray[11] = (ipChecksum and 0xFF).toByte()

        // TCP header
        val tcpBuffer = ByteBuffer.allocate(tcpHeaderSize)
        tcpBuffer.putShort(sourcePort.toShort())
        tcpBuffer.putShort(destPort.toShort())
        tcpBuffer.putInt((seqNum and 0xFFFFFFFFL).toInt())
        tcpBuffer.putInt(0)
        tcpBuffer.put((5 shl 4).toByte())
        tcpBuffer.put(TcpPacket.FLAG_RST.toByte())
        tcpBuffer.putShort(0)
        tcpBuffer.putShort(0)
        tcpBuffer.putShort(0)

        System.arraycopy(tcpBuffer.array(), 0, ipArray, 20, tcpHeaderSize)

        val tcpChecksum = computeTcpChecksum(sourceIp, destIp, ipArray, 20, tcpHeaderSize)
        ipArray[34] = (tcpChecksum shr 8).toByte()
        ipArray[35] = (tcpChecksum and 0xFF).toByte()

        return ipArray
    }

    // ========== Compute IP Checksum ==========

    private fun computeChecksum(data: ByteArray, offset: Int, length: Int): Int {
        var sum = 0L
        var i = offset
        var remaining = length

        while (remaining > 1) {
            sum += ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            i += 2
            remaining -= 2
        }

        if (remaining == 1) {
            sum += (data[i].toInt() and 0xFF) shl 8
        }

        while (sum shr 16 != 0L) {
            sum = (sum and 0xFFFF) + (sum shr 16)
        }

        return (sum.toInt().inv()) and 0xFFFF
    }

    // ========== Compute TCP Checksum with Pseudo-Header ==========

    private fun computeTcpChecksum(
        sourceIp: ByteArray,
        destIp: ByteArray,
        packet: ByteArray,
        tcpOffset: Int,
        tcpLength: Int
    ): Int {
        var sum = 0L

        // Pseudo-header: source IP + dest IP + zero + protocol + TCP length
        for (i in sourceIp.indices) {
            sum += if (i % 2 == 0) {
                ((sourceIp[i].toInt() and 0xFF) shl 8)
            } else {
                (sourceIp[i].toInt() and 0xFF)
            }
        }
        for (i in destIp.indices) {
            sum += if (i % 2 == 0) {
                ((destIp[i].toInt() and 0xFF) shl 8)
            } else {
                (destIp[i].toInt() and 0xFF)
            }
        }
        sum += PROTOCOL_TCP.toLong() // protocol
        sum += tcpLength.toLong() // TCP length

        // TCP header + data
        var i = tcpOffset
        var remaining = tcpLength
        while (remaining > 1) {
            if (i + 1 < packet.size) {
                sum += ((packet[i].toInt() and 0xFF) shl 8) or (packet[i + 1].toInt() and 0xFF)
            }
            i += 2
            remaining -= 2
        }
        if (remaining == 1 && i < packet.size) {
            sum += (packet[i].toInt() and 0xFF) shl 8
        }

        while (sum shr 16 != 0L) {
            sum = (sum and 0xFFFF) + (sum shr 16)
        }

        return (sum.toInt().inv()) and 0xFFFF
    }

    // ========== Utility ==========

    fun ipStringToBytes(ip: String): ByteArray {
        return InetAddress.getByName(ip).address
    }

    fun bytesToIpString(bytes: ByteArray): String {
        return InetAddress.getByAddress(bytes).hostAddress ?: "0.0.0.0"
    }
}
