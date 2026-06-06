package com.dnc.dns

/**
 * DNS configuration data class
 */
data class DnsConfig(
    val serverIp: String,
    val serverPort: Int,
    val name: String,
    val useDoh: Boolean = false,
    val dohUrl: String? = null,
    val blockResponseType: BlockResponseType = BlockResponseType.ADDRESS_0_0_0_0,
    val cacheEnabled: Boolean = true,
    val cacheMaxSize: Int = 1000,
    val cacheTtlOverride: Int = 0 // 0 = use original TTL
) {
    companion object {
        fun default(): DnsConfig = CLOUDFLARE

        val CLOUDFLARE = DnsConfig(
            serverIp = "1.1.1.1",
            serverPort = 53,
            name = "Cloudflare",
            useDoh = true,
            dohUrl = "https://cloudflare-dns.com/dns-query"
        )

        val GOOGLE = DnsConfig(
            serverIp = "8.8.8.8",
            serverPort = 53,
            name = "Google",
            useDoh = true,
            dohUrl = "https://dns.google/dns-query"
        )

        val QUAD9 = DnsConfig(
            serverIp = "9.9.9.9",
            serverPort = 53,
            name = "Quad9",
            useDoh = true,
            dohUrl = "https://dns.quad9.net/dns-query"
        )

        val ADGUARD = DnsConfig(
            serverIp = "94.140.14.14",
            serverPort = 53,
            name = "AdGuard DNS",
            useDoh = true,
            dohUrl = "https://dns.adguard-dns.com/dns-query"
        )

        val ADGUARD_FAMILY = DnsConfig(
            serverIp = "94.140.14.15",
            serverPort = 53,
            name = "AdGuard Family",
            useDoh = true,
            dohUrl = "https://dns-family.adguard-dns.com/dns-query"
        )

        val ALL_PROVIDERS = listOf(CLOUDFLARE, GOOGLE, QUAD9, ADGUARD, ADGUARD_FAMILY)
    }
}

enum class BlockResponseType {
    ADDRESS_0_0_0_0,  // Return 0.0.0.0 (empty response, fast fail)
    NXDOMAIN,         // Return NXDOMAIN (domain doesn't exist)
    REFUSED           // Return REFUSED (server refused query)
}
