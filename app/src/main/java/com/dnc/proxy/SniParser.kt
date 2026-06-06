package com.dnc.proxy

import android.util.Log

/**
 * Parses TLS ClientHello to extract the Server Name Indication (SNI).
 *
 * The SNI extension contains the domain name the client is connecting to,
 * sent in plaintext even in TLS 1.3 (though Encrypted Client Hello / ECH
 * is changing this — for now, most connections still have visible SNI).
 *
 * This allows us to:
 * - Block HTTPS connections by domain (without MITM)
 * - Decide which domains to MITM (skip banking etc.)
 * - Log which domains are being accessed
 */
object SniParser {

    private const val TAG = "SniParser"

    // TLS record types
    private const val RECORD_TYPE_HANDSHAKE = 22
    private const val RECORD_TYPE_CHANGE_CIPHER_SPEC = 20
    private const val RECORD_TYPE_APPLICATION_DATA = 23

    // Handshake types
    private const val HANDSHAKE_CLIENT_HELLO = 1

    // Extension types
    private const val EXTENSION_SERVER_NAME = 0x0000
    private const val EXTENSION_ENCRYPTED_SERVER_NAME = 0xFE0D // ECH

    // SNI name types
    private const val SNI_NAME_TYPE_HOSTNAME = 0

    /**
     * Extract the SNI domain name from raw TLS ClientHello bytes.
     * Returns null if no SNI found or parsing fails.
     */
    fun extractSni(data: ByteArray): String? {
        try {
            if (data.size < 44) return null // Minimum TLS record header + ClientHello start

            var offset = 0

            // Check if this starts with a TLS record
            val recordType = data[offset].toInt() and 0xFF
            if (recordType != RECORD_TYPE_HANDSHAKE) return null

            offset += 1

            // TLS version (2 bytes)
            if (offset + 2 > data.size) return null
            val tlsVersion = ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)
            offset += 2

            // Record length (2 bytes)
            if (offset + 2 > data.size) return null
            val recordLength = ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)
            offset += 2

            // Handshake type
            if (offset >= data.size) return null
            val handshakeType = data[offset].toInt() and 0xFF
            if (handshakeType != HANDSHAKE_CLIENT_HELLO) return null
            offset += 1

            // Handshake length (3 bytes)
            if (offset + 3 > data.size) return null
            offset += 3

            // ClientHello version (2 bytes)
            if (offset + 2 > data.size) return null
            offset += 2

            // Random (32 bytes)
            if (offset + 32 > data.size) return null
            offset += 32

            // Session ID length (1 byte) + session ID
            if (offset >= data.size) return null
            val sessionIdLength = data[offset].toInt() and 0xFF
            offset += 1
            if (offset + sessionIdLength > data.size) return null
            offset += sessionIdLength

            // Cipher suites length (2 bytes) + cipher suites
            if (offset + 2 > data.size) return null
            val cipherSuitesLength = ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)
            offset += 2
            if (offset + cipherSuitesLength > data.size) return null
            offset += cipherSuitesLength

            // Compression methods length (1 byte) + compression methods
            if (offset >= data.size) return null
            val compressionMethodsLength = data[offset].toInt() and 0xFF
            offset += 1
            if (offset + compressionMethodsLength > data.size) return null
            offset += compressionMethodsLength

            // Extensions start here
            if (offset + 2 > data.size) return null
            val extensionsLength = ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)
            offset += 2

            val extensionsEnd = offset + extensionsLength

            // Parse extensions
            while (offset + 4 <= extensionsEnd && offset + 4 <= data.size) {
                val extensionType = ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)
                val extensionLength = ((data[offset + 2].toInt() and 0xFF) shl 8) or (data[offset + 3].toInt() and 0xFF)
                offset += 4

                if (offset + extensionLength > data.size) break

                when (extensionType) {
                    EXTENSION_SERVER_NAME -> {
                        return parseSniExtension(data, offset, extensionLength)
                    }
                    EXTENSION_ENCRYPTED_SERVER_NAME -> {
                        // ECH — SNI is encrypted, we can't read it
                        Log.d(TAG, "Encrypted Client Hello detected — SNI not readable")
                        return null
                    }
                }

                offset += extensionLength
            }

        } catch (e: Exception) {
            Log.w(TAG, "Error parsing SNI: ${e.message}")
        }

        return null
    }

    /**
     * Parse the SNI extension to extract the hostname
     */
    private fun parseSniExtension(data: ByteArray, offset: Int, length: Int): String? {
        var pos = offset

        // Server Name List Length (2 bytes)
        if (pos + 2 > data.size) return null
        val listLength = ((data[pos].toInt() and 0xFF) shl 8) or (data[pos + 1].toInt() and 0xFF)
        pos += 2

        val listEnd = pos + listLength

        // Parse each Server Name entry
        while (pos + 3 <= listEnd && pos + 3 <= data.size) {
            val nameType = data[pos].toInt() and 0xFF
            pos += 1

            val nameLength = ((data[pos].toInt() and 0xFF) shl 8) or (data[pos + 1].toInt() and 0xFF)
            pos += 2

            if (pos + nameLength > data.size) break

            if (nameType == SNI_NAME_TYPE_HOSTNAME) {
                val hostname = String(data, pos, nameLength, Charsets.US_ASCII)
                return hostname
            }

            pos += nameLength
        }

        return null
    }

    /**
     * Quick check if a byte array might be a TLS ClientHello
     * (used for fast filtering before full parsing)
     */
    fun isTlsClientHello(data: ByteArray): Boolean {
        if (data.size < 5) return false
        val recordType = data[0].toInt() and 0xFF
        if (recordType != RECORD_TYPE_HANDSHAKE) return false

        // Check TLS version byte
        val versionMajor = data[1].toInt() and 0xFF
        if (versionMajor != 3) return false // TLS 1.0-1.3 all use 0x03 as major version

        return true
    }
}
