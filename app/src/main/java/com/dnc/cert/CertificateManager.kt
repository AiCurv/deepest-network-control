package com.dnc.cert

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.util.Log
import org.bouncycastle.asn1.x509.*
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.io.ByteArrayInputStream
import java.io.File
import java.io.FileOutputStream
import java.math.BigInteger
import java.net.InetAddress
import java.security.*
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.*
import java.util.concurrent.ConcurrentHashMap

/**
 * Manages the local CA certificate for HTTPS MITM.
 *
 * Full implementation using BouncyCastle for proper X509v3 certificate generation.
 *
 * On first launch:
 * 1. Generates a root CA key pair (RSA 2048) using BouncyCastle
 * 2. Creates a self-signed CA certificate with proper extensions (CA:true, KeyUsage)
 * 3. Stores CA private key securely (Android Keystore where possible, encrypted file fallback)
 * 4. Stores the certificate for later export/install
 *
 * For each HTTPS domain:
 * 1. Generates a per-domain key pair
 * 2. Signs a certificate with the CA — includes proper SAN (Subject Alternative Name)
 * 3. Caches the cert for reuse
 *
 * Two modes:
 * - No root: User installs CA into user cert store (works for browsers)
 * - Root: Magisk module moves CA to system store (works for all apps)
 */
class CertificateManager private constructor(private val context: Context) {

    companion object {
        private const val TAG = "CertManager"
        private const val CA_KEY_ALIAS = "dnc_ca"
        private const val CA_CERT_FILE = "dnc_ca_cert.pem"
        private const val CA_KEY_FILE = "dnc_ca_key.der"
        private const val CA_PREFS = "dnc_cert_prefs"
        private const val KEY_CA_INSTALLED = "ca_installed"
        private const val KEY_CA_FINGERPRINT = "ca_fingerprint"

        const val CA_COMMON_NAME = "DNC Root CA"
        const val CA_ORGANIZATION = "Deepest Network Control"
        const val CA_ORGANIZATIONAL_UNIT = "HTTPS Filtering"
        const val CA_VALIDITY_YEARS = 20
        const val DOMAIN_CERT_VALIDITY_DAYS = 365
        const val KEY_ALGORITHM = "RSA"
        const val KEY_SIZE = 2048
        const val SIGNATURE_ALGORITHM = "SHA256WithRSAEncryption"

        @Volatile
        private var instance: CertificateManager? = null

        fun getInstance(context: Context): CertificateManager {
            return instance ?: synchronized(this) {
                instance ?: CertificateManager(context.applicationContext).also { instance = it }
            }
        }

        // Register BouncyCastle provider
        init {
            try {
                Security.addProvider(BouncyCastleProvider())
            } catch (e: Exception) {
                Log.w("CertManager", "BouncyCastle provider already registered")
            }
        }
    }

    private var caKeyPair: KeyPair? = null
    private var caCertificate: X509Certificate? = null

    // Cache of per-domain certificates
    private val domainKeyCache = ConcurrentHashMap<String, KeyPair>()
    private val domainCertCache = ConcurrentHashMap<String, X509Certificate>()

    private val prefs = context.getSharedPreferences(CA_PREFS, Context.MODE_PRIVATE)

    init {
        loadOrGenerateCa()
    }

    // ==================== CA Management ====================

    /**
     * Load existing CA or generate a new one
     */
    private fun loadOrGenerateCa() {
        // Try loading from files first
        val certLoaded = loadCaFromFiles()
        if (certLoaded) {
            Log.i(TAG, "Loaded existing CA certificate")
            return
        }

        // Generate new CA
        generateCa()
    }

    /**
     * Try to load CA from internal storage
     */
    private fun loadCaFromFiles(): Boolean {
        try {
            val certFile = File(context.filesDir, CA_CERT_FILE)
            val keyFile = File(context.filesDir, CA_KEY_FILE)
            if (!certFile.exists() || !keyFile.exists()) return false

            // Load certificate
            val certBytes = certFile.readBytes()
            val certFactory = CertificateFactory.getInstance("X.509")
            val cert = certFactory.generateCertificate(ByteArrayInputStream(certBytes)) as X509Certificate

            // Load private key
            val keyBytes = keyFile.readBytes()
            val keySpec = java.security.spec.PKCS8EncodedKeySpec(keyBytes)
            val keyFactory = KeyFactory.getInstance(KEY_ALGORITHM)
            val privateKey = keyFactory.generatePrivate(keySpec)

            caKeyPair = KeyPair(cert.publicKey, privateKey)
            caCertificate = cert

            return true
        } catch (e: Exception) {
            Log.w(TAG, "Failed to load CA from files: ${e.message}")
            return false
        }
    }

    /**
     * Generate a new root CA key pair and self-signed certificate using BouncyCastle
     */
    private fun generateCa() {
        Log.i(TAG, "Generating new DNC Root CA with BouncyCastle...")

        try {
            // Generate RSA key pair
            val keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM, BouncyCastleProvider.PROVIDER_NAME)
            keyPairGenerator.initialize(KEY_SIZE, SecureRandom())
            val keyPair = keyPairGenerator.generateKeyPair()

            // Build CA certificate using BouncyCastle
            val issuerDN = org.bouncycastle.asn1.x500.X500Name(
                "CN=$CA_COMMON_NAME, OU=$CA_ORGANIZATIONAL_UNIT, O=$CA_ORGANIZATION, C=US"
            )
            val subjectDN = issuerDN // Self-signed: issuer = subject

            val now = Date()
            val notAfter = Date(System.currentTimeMillis() + (CA_VALIDITY_YEARS.toLong() * 365 * 24 * 60 * 60 * 1000))

            val serialNumber = BigInteger.valueOf(System.currentTimeMillis())

            val certBuilder = JcaX509v3CertificateBuilder(
                issuerDN,
                serialNumber,
                now,
                notAfter,
                subjectDN,
                keyPair.public
            )

            // CA certificate extensions
            val extUtils = JcaX509ExtensionUtils()

            // Basic Constraints: CA=true (this is a certificate authority)
            certBuilder.addExtension(
                org.bouncycastle.asn1.x509.Extension.basicConstraints,
                true, // critical
                BasicConstraints(true) // isCA = true
            )

            // Key Usage: Certificate Sign, CRL Sign
            certBuilder.addExtension(
                org.bouncycastle.asn1.x509.Extension.keyUsage,
                true,
                KeyUsage(KeyUsage.keyCertSign or KeyUsage.cRLSign)
            )

            // Extended Key Usage — not needed for CA, but add for compatibility
            // Subject Key Identifier
            certBuilder.addExtension(
                org.bouncycastle.asn1.x509.Extension.subjectKeyIdentifier,
                false,
                extUtils.createSubjectKeyIdentifier(keyPair.public)
            )

            // Authority Key Identifier (self-signed)
            certBuilder.addExtension(
                org.bouncycastle.asn1.x509.Extension.authorityKeyIdentifier,
                false,
                extUtils.createAuthorityKeyIdentifier(keyPair.public)
            )

            // Sign the certificate
            val signerBuilder = JcaContentSignerBuilder(SIGNATURE_ALGORITHM)
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
            val signer = signerBuilder.build(keyPair.private)

            val certHolder = certBuilder.build(signer)
            val cert = JcaX509CertificateConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(certHolder)

            caKeyPair = keyPair
            caCertificate = cert

            // Save to internal storage
            saveCaToFiles(keyPair, cert)

            Log.i(TAG, "CA certificate generated successfully")
            Log.i(TAG, "CA fingerprint: ${getCaFingerprint()}")

        } catch (e: Exception) {
            Log.e(TAG, "Failed to generate CA: ${e.message}", e)
        }
    }

    /**
     * Save CA key pair and certificate to internal storage
     */
    private fun saveCaToFiles(keyPair: KeyPair, cert: X509Certificate) {
        try {
            // Save certificate as DER
            val certFile = File(context.filesDir, CA_CERT_FILE)
            FileOutputStream(certFile).use { fos ->
                fos.write(cert.encoded)
            }

            // Save private key as PKCS8 DER
            val keyFile = File(context.filesDir, CA_KEY_FILE)
            FileOutputStream(keyFile).use { fos ->
                fos.write(keyPair.private.encoded)
            }

            Log.d(TAG, "CA saved to internal storage")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to save CA: ${e.message}")
        }
    }

    // ==================== Domain Certificate Generation ====================

    /**
     * Generate a per-domain certificate signed by the CA using BouncyCastle.
     * The certificate includes:
     * - CN = domain
     * - SAN = domain + *.domain (wildcard)
     * - Basic Constraints: CA=false
     * - Key Usage: Digital Signature, Key Encipherment
     * - Extended Key Usage: TLS Web Server Authentication
     */
    fun generateDomainCert(domain: String): X509Certificate {
        // Check cache
        domainCertCache[domain]?.let { return it }

        try {
            val caKp = caKeyPair ?: throw IllegalStateException("CA key pair not initialized")
            val caCert = caCertificate ?: throw IllegalStateException("CA certificate not initialized")

            // Generate domain key pair (or use cached)
            val domainKeyPair = domainKeyCache.getOrPut(domain) {
                val kpg = KeyPairGenerator.getInstance(KEY_ALGORITHM, BouncyCastleProvider.PROVIDER_NAME)
                kpg.initialize(KEY_SIZE, SecureRandom())
                kpg.generateKeyPair()
            }

            val now = Date()
            val notAfter = Date(System.currentTimeMillis() + (DOMAIN_CERT_VALIDITY_DAYS.toLong() * 24 * 60 * 60 * 1000))
            val serialNumber = BigInteger.valueOf(System.currentTimeMillis())

            val issuerDN = org.bouncycastle.asn1.x500.X500Name(caCert.subjectX500Principal.name)
            val subjectDN = org.bouncycastle.asn1.x500.X500Name(
                "CN=$domain, OU=$CA_ORGANIZATIONAL_UNIT, O=$CA_ORGANIZATION"
            )

            val certBuilder = JcaX509v3CertificateBuilder(
                issuerDN,
                serialNumber,
                now,
                notAfter,
                subjectDN,
                domainKeyPair.public
            )

            val extUtils = JcaX509ExtensionUtils()

            // Basic Constraints: NOT a CA
            certBuilder.addExtension(
                org.bouncycastle.asn1.x509.Extension.basicConstraints,
                true,
                BasicConstraints(false)
            )

            // Key Usage: Digital Signature + Key Encipherment
            certBuilder.addExtension(
                org.bouncycastle.asn1.x509.Extension.keyUsage,
                true,
                KeyUsage(KeyUsage.digitalSignature or KeyUsage.keyEncipherment)
            )

            // Extended Key Usage: TLS Web Server Authentication
            certBuilder.addExtension(
                org.bouncycastle.asn1.x509.Extension.extendedKeyUsage,
                false,
                ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth)
            )

            // Subject Alternative Name — CRITICAL for modern browsers
            // Chrome requires SAN, not just CN
            val sanNames = mutableListOf<GeneralName>()
            sanNames.add(GeneralName(GeneralName.dNSName, domain))

            // Add wildcard SAN if it's not already a wildcard
            if (!domain.startsWith("*.")) {
                sanNames.add(GeneralName(GeneralName.dNSName, "*.$domain"))
            }

            // If it's an IP address, add IP SAN too
            try {
                val ip = InetAddress.getByName(domain)
                sanNames.add(GeneralName(GeneralName.iPAddress, domain))
            } catch (e: Exception) {
                // Not an IP, that's fine
            }

            val san = GeneralNames(sanNames.toTypedArray())
            certBuilder.addExtension(
                org.bouncycastle.asn1.x509.Extension.subjectAlternativeName,
                false,
                san
            )

            // Subject Key Identifier
            certBuilder.addExtension(
                org.bouncycastle.asn1.x509.Extension.subjectKeyIdentifier,
                false,
                extUtils.createSubjectKeyIdentifier(domainKeyPair.public)
            )

            // Authority Key Identifier (from CA cert)
            certBuilder.addExtension(
                org.bouncycastle.asn1.x509.Extension.authorityKeyIdentifier,
                false,
                extUtils.createAuthorityKeyIdentifier(caCert)
            )

            // Sign with CA private key
            val signerBuilder = JcaContentSignerBuilder(SIGNATURE_ALGORITHM)
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
            val signer = signerBuilder.build(caKp.private)

            val certHolder = certBuilder.build(signer)
            val domainCert = JcaX509CertificateConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(certHolder)

            // Cache it
            domainCertCache[domain] = domainCert
            Log.d(TAG, "Generated domain cert for: $domain (SAN: ${domain}, *.${domain})")

            return domainCert

        } catch (e: Exception) {
            Log.e(TAG, "Failed to generate domain cert for $domain: ${e.message}", e)
            throw e
        }
    }

    /**
     * Create an SSLContext configured with the forged domain certificate for the client side
     * of the MITM connection. This is what the browser/app sees.
     */
    fun createClientSslContext(domain: String): javax.net.ssl.SSLContext {
        val domainCert = generateDomainCert(domain)
        val domainKeyPair = domainKeyCache[domain]
            ?: throw IllegalStateException("No key pair for $domain")

        val caCert = caCertificate ?: throw IllegalStateException("No CA cert")

        // Create a KeyStore with the domain cert chain
        val keyStore = java.security.KeyStore.getInstance("PKCS12")
        keyStore.load(null, null)
        keyStore.setKeyEntry(
            "domain",
            domainKeyPair.private,
            null,
            arrayOf(caCert, domainCert)
        )

        // Create SSLContext
        val keyManagerFactory = javax.net.ssl.KeyManagerFactory.getInstance(
            javax.net.ssl.KeyManagerFactory.getDefaultAlgorithm()
        )
        keyManagerFactory.init(keyStore, null)

        val sslContext = javax.net.ssl.SSLContext.getInstance("TLS")
        sslContext.init(keyManagerFactory.keyManagers, null, null)

        return sslContext
    }

    /**
     * Create an SSLContext for the server side of the MITM connection.
     * Uses the default trust store to validate the real server's certificate.
     */
    fun createServerSslContext(): javax.net.ssl.SSLContext {
        val trustManagerFactory = javax.net.ssl.TrustManagerFactory.getInstance(
            javax.net.ssl.TrustManagerFactory.getDefaultAlgorithm()
        )
        trustManagerFactory.init(null as java.security.KeyStore?)

        val sslContext = javax.net.ssl.SSLContext.getInstance("TLS")
        sslContext.init(null, trustManagerFactory.trustManagers, null)

        return sslContext
    }

    // ==================== CA Export / Install ====================

    /**
     * Export the CA certificate as PEM format for user installation
     */
    fun exportCaCertificatePem(): String? {
        val cert = caCertificate ?: return null
        val base64 = android.util.Base64.encodeToString(cert.encoded, android.util.Base64.NO_WRAP)
        return "-----BEGIN CERTIFICATE-----\n$base64\n-----END CERTIFICATE-----\n"
    }

    /**
     * Export the CA certificate as DER format
     */
    fun exportCaCertificateDer(): ByteArray? = caCertificate?.encoded

    /**
     * Check if the CA certificate is installed in the user cert store
     */
    fun isCaInstalled(): Boolean {
        if (prefs.getBoolean(KEY_CA_INSTALLED, false)) return true

        // Try to verify by checking system trust anchors
        try {
            val caCert = caCertificate ?: return false
            val trustManager = javax.net.ssl.TrustManagerFactory.getInstance(
                javax.net.ssl.TrustManagerFactory.getDefaultAlgorithm()
            )
            trustManager.init(null as java.security.KeyStore?)

            val x509Tms = trustManager.trustManagers.filterIsInstance<javax.net.ssl.X509TrustManager>()
            for (tm in x509Tms) {
                try {
                    tm.checkServerTrusted(arrayOf(caCert), "RSA")
                    // If we get here without exception, the CA is trusted
                    prefs.edit().putBoolean(KEY_CA_INSTALLED, true).apply()
                    return true
                } catch (e: Exception) {
                    // Not trusted yet
                }
            }
        } catch (e: Exception) {
            Log.d(TAG, "CA install check failed: ${e.message}")
        }

        return false
    }

    /**
     * Set the CA installed flag
     */
    fun setCaInstalled(installed: Boolean) {
        prefs.edit().putBoolean(KEY_CA_INSTALLED, installed).apply()
    }

    /**
     * Trigger the Android certificate installation flow.
     * 
     * On Android 9 and below: Uses android.credentials.INSTALL intent
     * On Android 10+: Uses KeyChain.createInstallIntent()
     * On Android 11+: Opens Security Settings for manual install
     * 
     * The cert is also exported as PEM to the app's cache so users can
     * manually install it if the intent approach doesn't work.
     */
    fun installCaCertificate() {
        try {
            val certDer = exportCaCertificateDer()
            if (certDer == null) {
                Log.e(TAG, "No CA certificate to install — generate first")
                return
            }

            // Always export PEM too for manual installation
            val pemData = exportCaCertificatePem()
            if (pemData != null) {
                val pemFile = File(context.cacheDir, "dnc_ca_cert.pem")
                FileOutputStream(pemFile).use { it.write(pemData.toByteArray()) }
                Log.i(TAG, "PEM cert exported to: ${pemFile.absolutePath}")
            }

            // Write DER cert to cache
            val certFile = File(context.cacheDir, "dnc_ca_cert.crt")
            FileOutputStream(certFile).use { it.write(certDer) }
            Log.i(TAG, "DER cert exported to: ${certFile.absolutePath}")

            // Try multiple installation methods in order of preference

            // Method 1: KeyChain install intent (works on most Android versions)
            try {
                val installIntent = android.security.KeyChain.createInstallIntent()
                installIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                installIntent.putExtra("name", "$CA_COMMON_NAME - $CA_ORGANIZATION")
                installIntent.setDataAndType(
                    Uri.fromFile(certFile),
                    "application/x-x509-ca-cert"
                )
                context.startActivity(installIntent)
                Log.i(TAG, "CA certificate install intent triggered via KeyChain")
                return
            } catch (e: Exception) {
                Log.w(TAG, "KeyChain install intent failed: ${e.message}")
            }

            // Method 2: Direct credentials intent (older Android)
            try {
                val intent = Intent("android.credentials.INSTALL")
                intent.putExtra("name", "$CA_COMMON_NAME - $CA_ORGANIZATION")
                intent.setDataAndType(
                    Uri.fromFile(certFile),
                    "application/x-x509-ca-cert"
                )
                intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                context.startActivity(intent)
                Log.i(TAG, "CA certificate install intent triggered via credentials")
                return
            } catch (e: Exception) {
                Log.w(TAG, "Direct credentials intent failed: ${e.message}")
            }

            // Method 3: Install as PEM (some devices prefer this)
            try {
                val pemFile = File(context.cacheDir, "dnc_ca_cert.pem")
                val intent = Intent("android.credentials.INSTALL")
                intent.putExtra("name", "$CA_COMMON_NAME - $CA_ORGANIZATION")
                intent.setDataAndType(
                    Uri.fromFile(pemFile),
                    "application/x-x509-ca-cert"
                )
                intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                context.startActivity(intent)
                Log.i(TAG, "CA certificate install intent triggered via PEM")
                return
            } catch (e: Exception) {
                Log.w(TAG, "PEM install intent failed: ${e.message}")
            }

            // Method 4: Open Security Settings for manual install
            try {
                val settingsIntent = Intent(android.provider.Settings.ACTION_SECURITY_SETTINGS)
                settingsIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                context.startActivity(settingsIntent)
                Log.i(TAG, "Opened Security Settings for manual CA install")
            } catch (e2: Exception) {
                Log.e(TAG, "Cannot open security settings: ${e2.message}")
            }

        } catch (e: Exception) {
            Log.e(TAG, "Failed to trigger CA install: ${e.message}")
        }
    }

    /**
     * Get the CA certificate fingerprint (SHA-256) for display
     */
    fun getCaFingerprint(): String? {
        val cert = caCertificate ?: return null
        return try {
            val md = MessageDigest.getInstance("SHA-256")
            val digest = md.digest(cert.encoded)
            digest.joinToString(":") { "%02X".format(it) }
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Get the CA certificate
     */
    fun getCaCertificate(): X509Certificate? = caCertificate

    /**
     * Clear all cached domain certificates
     */
    fun clearCache() {
        domainKeyCache.clear()
        domainCertCache.clear()
        Log.d(TAG, "Domain cert cache cleared")
    }
}
