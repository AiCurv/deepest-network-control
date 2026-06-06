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

# DNC - Keep all model/data classes used in serialization
-keepclassmembers class com.dnc.filter.** { *; }
-keepclassmembers class com.dnc.dns.** { *; }
-keepclassmembers class com.dnc.vpn.** { *; }
-keepclassmembers class com.dnc.proxy.** { *; }
-keepclassmembers class com.dnc.cert.** { *; }
-keepclassmembers class com.dnc.scriptlet.** { *; }
-keepclassmembers class com.dnc.cosmetic.** { *; }
-keepclassmembers class com.dnc.handler.** { *; }
-keepclassmembers class com.dnc.injector.** { *; }
-keepclassmembers class com.dnc.data.** { *; }

# BouncyCastle
-keep class org.bouncycastle.** { *; }
-dontwarn org.bouncycastle.**

# OkHttp
-dontwarn okhttp3.**
-dontwarn okio.**

# Kotlin coroutines
-keepnames class kotlinx.coroutines.internal.MainDispatcherFactory {}
-keepnames class kotlinx.coroutines.CoroutineExceptionHandler {}
-keepclassmembers class kotlinx.coroutines.** {
    volatile <fields>;
}

# Compose
-dontwarn androidx.compose.**
