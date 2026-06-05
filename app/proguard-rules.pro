# DNC ProGuard Rules

# Keep VPN service
-keep class com.dnc.vpn.DncVpnService { *; }

# Keep certificate classes
-keep class com.dnc.cert.CertificateManager { *; }

# Keep filter engine
-keep class com.dnc.filter.FilterEngine { *; }
-keep class com.dnc.filter.FilterRule { *; }

# Keep DNS classes
-keep class com.dnc.dns.** { *; }

# Keep proxy classes
-keep class com.dnc.proxy.** { *; }

# Keep data models
-keep class com.dnc.data.** { *; }

# Kotlin coroutines
-keepnames class kotlinx.coroutines.internal.MainDispatcherFactory {}
-keepnames class kotlinx.coroutines.CoroutineExceptionHandler {}
