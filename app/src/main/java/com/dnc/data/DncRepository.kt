package com.dnc.data

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.core.stringSetPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

enum class DnsProvider(val displayName: String, val primaryDns: String, val secondaryDns: String) {
    CLOUDFLARE("Cloudflare", "1.1.1.1", "1.0.0.1"),
    GOOGLE("Google", "8.8.8.8", "8.8.4.4"),
    QUAD9("Quad9", "9.9.9.9", "149.112.112.112"),
    ADGUARD("AdGuard", "94.140.14.14", "94.140.15.15"),
    CUSTOM("Custom", "", "")
}

enum class BlockResponseType(val displayName: String) {
    ZERO_ADDRESS("0.0.0.0"),
    NXDOMAIN("NXDOMAIN"),
    REFUSED("REFUSED")
}

enum class RedirectBlockAction(val displayName: String) {
    REPLACE_EMPTY("Replace with empty"),
    REPLACE_SAFE_URL("Replace with safe URL"),
    CUSTOM_PAGE("Custom page")
}

private val Context.dataStore: DataStore<Preferences> by preferencesDataStore(name = "dnc_settings")

class DncRepository(private val context: Context) {

    private val dataStore = context.dataStore

    companion object {
        private val KEY_VPN_ENABLED = booleanPreferencesKey("vpn_enabled")
        private val KEY_DNS_PROVIDER = stringPreferencesKey("dns_provider")
        private val KEY_CUSTOM_DNS_IP = stringPreferencesKey("custom_dns_ip")
        private val KEY_DNS_CACHE_ENABLED = booleanPreferencesKey("dns_cache_enabled")
        private val KEY_BLOCK_RESPONSE_TYPE = stringPreferencesKey("block_response_type")
        private val KEY_HTTPS_FILTERING_ENABLED = booleanPreferencesKey("https_filtering_enabled")
        private val KEY_CA_CERT_INSTALLED = booleanPreferencesKey("ca_cert_installed")
        private val KEY_EXCLUDED_DOMAINS = stringSetPreferencesKey("excluded_domains")
        private val KEY_REDIRECT_BLOCKING_ENABLED = booleanPreferencesKey("redirect_blocking_enabled")
        private val KEY_REDIRECT_BLOCK_ACTION = stringPreferencesKey("redirect_block_action")
        private val KEY_CUSTOM_SAFE_URL = stringPreferencesKey("custom_safe_url")
        private val KEY_EXCLUDED_APPS = stringSetPreferencesKey("excluded_apps")
        private val KEY_LOG_RETENTION_DAYS = intPreferencesKey("log_retention_days")
        private val KEY_AUTO_START_ENABLED = booleanPreferencesKey("auto_start_enabled")
        private val KEY_DNS_FILTERING_ENABLED = booleanPreferencesKey("dns_filtering_enabled")
        private val KEY_CUSTOM_RULES = stringSetPreferencesKey("custom_rules")
        private val KEY_FILTER_LIST_URLS = stringSetPreferencesKey("filter_list_urls")
    }

    // --- VPN ---

    fun isVpnEnabled(): Flow<Boolean> = dataStore.data.map { it[KEY_VPN_ENABLED] ?: false }

    suspend fun setVpnEnabled(enabled: Boolean) {
        dataStore.edit { it[KEY_VPN_ENABLED] = enabled }
    }

    // --- DNS ---

    fun getDnsProvider(): Flow<DnsProvider> = dataStore.data.map { prefs ->
        val name = prefs[KEY_DNS_PROVIDER] ?: DnsProvider.CLOUDFLARE.name
        runCatching { DnsProvider.valueOf(name) }.getOrDefault(DnsProvider.CLOUDFLARE)
    }

    suspend fun setDnsProvider(provider: DnsProvider) {
        dataStore.edit { it[KEY_DNS_PROVIDER] = provider.name }
    }

    fun getCustomDnsIp(): Flow<String> = dataStore.data.map { it[KEY_CUSTOM_DNS_IP] ?: "" }

    suspend fun setCustomDnsIp(ip: String) {
        dataStore.edit { it[KEY_CUSTOM_DNS_IP] = ip }
    }

    fun isDnsCacheEnabled(): Flow<Boolean> = dataStore.data.map { it[KEY_DNS_CACHE_ENABLED] ?: true }

    suspend fun setDnsCacheEnabled(enabled: Boolean) {
        dataStore.edit { it[KEY_DNS_CACHE_ENABLED] = enabled }
    }

    fun getBlockResponseType(): Flow<BlockResponseType> = dataStore.data.map { prefs ->
        val name = prefs[KEY_BLOCK_RESPONSE_TYPE] ?: BlockResponseType.ZERO_ADDRESS.name
        runCatching { BlockResponseType.valueOf(name) }.getOrDefault(BlockResponseType.ZERO_ADDRESS)
    }

    suspend fun setBlockResponseType(type: BlockResponseType) {
        dataStore.edit { it[KEY_BLOCK_RESPONSE_TYPE] = type.name }
    }

    // --- DNS Filtering ---

    fun isDnsFilteringEnabled(): Flow<Boolean> = dataStore.data.map { it[KEY_DNS_FILTERING_ENABLED] ?: true }

    suspend fun setDnsFilteringEnabled(enabled: Boolean) {
        dataStore.edit { it[KEY_DNS_FILTERING_ENABLED] = enabled }
    }

    // --- HTTPS Filtering ---

    fun isHttpsFilteringEnabled(): Flow<Boolean> = dataStore.data.map { it[KEY_HTTPS_FILTERING_ENABLED] ?: false }

    suspend fun setHttpsFilteringEnabled(enabled: Boolean) {
        dataStore.edit { it[KEY_HTTPS_FILTERING_ENABLED] = enabled }
    }

    fun isCaCertInstalled(): Flow<Boolean> = dataStore.data.map { it[KEY_CA_CERT_INSTALLED] ?: false }

    suspend fun setCaCertInstalled(installed: Boolean) {
        dataStore.edit { it[KEY_CA_CERT_INSTALLED] = installed }
    }

    // --- Excluded Domains ---

    fun getExcludedDomains(): Flow<Set<String>> = dataStore.data.map { it[KEY_EXCLUDED_DOMAINS] ?: emptySet() }

    suspend fun addExcludedDomain(domain: String) {
        dataStore.edit { prefs ->
            val current = prefs[KEY_EXCLUDED_DOMAINS] ?: emptySet()
            prefs[KEY_EXCLUDED_DOMAINS] = current + domain
        }
    }

    suspend fun removeExcludedDomain(domain: String) {
        dataStore.edit { prefs ->
            val current = prefs[KEY_EXCLUDED_DOMAINS] ?: emptySet()
            prefs[KEY_EXCLUDED_DOMAINS] = current - domain
        }
    }

    // --- Redirect Blocking ---

    fun isRedirectBlockingEnabled(): Flow<Boolean> = dataStore.data.map { it[KEY_REDIRECT_BLOCKING_ENABLED] ?: false }

    suspend fun setRedirectBlockingEnabled(enabled: Boolean) {
        dataStore.edit { it[KEY_REDIRECT_BLOCKING_ENABLED] = enabled }
    }

    fun getRedirectBlockAction(): Flow<RedirectBlockAction> = dataStore.data.map { prefs ->
        val name = prefs[KEY_REDIRECT_BLOCK_ACTION] ?: RedirectBlockAction.REPLACE_EMPTY.name
        runCatching { RedirectBlockAction.valueOf(name) }.getOrDefault(RedirectBlockAction.REPLACE_EMPTY)
    }

    suspend fun setRedirectBlockAction(action: RedirectBlockAction) {
        dataStore.edit { it[KEY_REDIRECT_BLOCK_ACTION] = action.name }
    }

    fun getCustomSafeUrl(): Flow<String> = dataStore.data.map { it[KEY_CUSTOM_SAFE_URL] ?: "" }

    suspend fun setCustomSafeUrl(url: String) {
        dataStore.edit { it[KEY_CUSTOM_SAFE_URL] = url }
    }

    // --- Excluded Apps ---

    fun getExcludedApps(): Flow<Set<String>> = dataStore.data.map { it[KEY_EXCLUDED_APPS] ?: emptySet() }

    suspend fun addExcludedApp(packageName: String) {
        dataStore.edit { prefs ->
            val current = prefs[KEY_EXCLUDED_APPS] ?: emptySet()
            prefs[KEY_EXCLUDED_APPS] = current + packageName
        }
    }

    suspend fun removeExcludedApp(packageName: String) {
        dataStore.edit { prefs ->
            val current = prefs[KEY_EXCLUDED_APPS] ?: emptySet()
            prefs[KEY_EXCLUDED_APPS] = current - packageName
        }
    }

    // --- Log Retention ---

    fun getLogRetentionDays(): Flow<Int> = dataStore.data.map { it[KEY_LOG_RETENTION_DAYS] ?: 7 }

    suspend fun setLogRetentionDays(days: Int) {
        dataStore.edit { it[KEY_LOG_RETENTION_DAYS] = days }
    }

    // --- Auto Start ---

    fun isAutoStartEnabled(): Flow<Boolean> = dataStore.data.map { it[KEY_AUTO_START_ENABLED] ?: false }

    suspend fun setAutoStartEnabled(enabled: Boolean) {
        dataStore.edit { it[KEY_AUTO_START_ENABLED] = enabled }
    }

    // --- Custom Rules ---

    fun getCustomRules(): Flow<Set<String>> = dataStore.data.map { it[KEY_CUSTOM_RULES] ?: emptySet() }

    suspend fun addCustomRule(rule: String) {
        dataStore.edit { prefs ->
            val current = prefs[KEY_CUSTOM_RULES] ?: emptySet()
            prefs[KEY_CUSTOM_RULES] = current + rule
        }
    }

    suspend fun removeCustomRule(rule: String) {
        dataStore.edit { prefs ->
            val current = prefs[KEY_CUSTOM_RULES] ?: emptySet()
            prefs[KEY_CUSTOM_RULES] = current - rule
        }
    }

    // --- Filter List URLs ---

    fun getFilterListUrls(): Flow<Set<String>> = dataStore.data.map {
        it[KEY_FILTER_LIST_URLS] ?: setOf(
            "https://easylist.to/easylist/easylist.txt",
            "https://easylist.to/easylist/easyprivacy.txt",
            "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters.txt",
            "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=adblockplus&showintro=1&mimetype=plaintext",
            "https://filters.adtidy.org/extension/ublock/filters/11.txt"
        )
    }

    suspend fun addFilterListUrl(url: String) {
        dataStore.edit { prefs ->
            val current = prefs[KEY_FILTER_LIST_URLS] ?: emptySet()
            prefs[KEY_FILTER_LIST_URLS] = current + url
        }
    }

    suspend fun removeFilterListUrl(url: String) {
        dataStore.edit { prefs ->
            val current = prefs[KEY_FILTER_LIST_URLS] ?: emptySet()
            prefs[KEY_FILTER_LIST_URLS] = current - url
        }
    }
}
