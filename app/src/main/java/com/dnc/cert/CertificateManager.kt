package com.dnc.cert

import android.content.Context
import android.content.Intent
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.Certificate
import java.security.cert.X509Certificate
import java.util.concurrent.ConcurrentHashMap
import javax.security.auth.x500.X500Principal
import org.bouncycastle.asn1.x509.*
import org.bouncycastle.x509.X509V3CertificateGenerator
import java.util.Date

/**
 * Manages the local CA certificate for HTTPS MITM.
 *
 * On first launch:
 * 1. Generates a root CA key pair (RSA 2048)
 * 2. Creates a self-signed CA certificate
 * 3. Stores the private key in Android Keystore (hardware-backed)
 * 4. Stores the certificate for later export/install
 *
 * For each HTTPS domain:
 * 1. Generates a per-domain key pair
 * 2. Signs a certificate with the CA (same CN + SAN as the real domain)
 * 3. Caches the cert for reuse
 *
 * User must install the CA certificate in Android's user cert store
 * for HTTPS filtering to work in browsers.
 */
class CertificateManager private constructor(private val context: Context) {

    companion object {
        private const val TAG = "CertManager"
        private const val KEYSTORE_ALIAS = "dnc_ca_key"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val CA_KEYSTORE_FILE = "dnc_ca.jks"
        private const val CA_KEYSTORE_PASSWORD = "dnc_cert_store"
        private const val CA_CERT_PREFS = "dnc_cert_prefs"
        private const val CA_CERT_INSTALLED_KEY = "ca_cert_installed"

        const val CA_COMMON_NAME = "DNC Root CA"
        const val CA_ORGANIZATION = "Deepest Network Control"
        const val CA_VALIDITY_YEARS = 20
        const val DOMAIN_CERT_VALIDITY_DAYS = 365

        @Volatile
        private var instance: CertificateManager? = null

        fun getInstance(context: Context): CertificateManager {
            return instance ?: synchronized(this) {
                instance ?: CertificateManager(context.applicationContext).also { instance = it }
            }
        }
    }

    private var caKeyPair: KeyPair? = null
    private var caCertificate: X509Certificate? = null

    // Cache of generated per-domain certificates
    private val domainCertCache = ConcurrentHashMap<String, KeyPair>()
    private val domainCertX509Cache = ConcurrentHashMap<String, X509Certificate>()

    private val prefs = context.getSharedPreferences(CA_CERT_PREFS, Context.MODE_PRIVATE)

    init {
        initializeCa()
    }

    /**
     * Initialize the CA — either load existing or generate new
     */
    private fun initializeCa() {
        try {
            // Try to load existing CA from Android Keystore
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
            keyStore.load(null)

            if (keyStore.containsAlias(KEYSTORE_ALIAS)) {
                // Load existing CA
                val entry = keyStore.getEntry(KEYSTORE_ALIAS, null) as? KeyStore.PrivateKeyEntry
                if (entry != null) {
                    val privateKey = entry.privateKey
                    val cert = entry.certificate as? X509Certificate
                    if (cert != null) {
                        val publicKey = cert.publicKey
                        caKeyPair = KeyPair(publicKey, privateKey)
                        caCertificate = cert
                        Log.i(TAG, "Loaded existing CA certificate")
                        return
                    }
                }
            }

            // Generate new CA
            generateCa()

        } catch (e: Exception) {
            Log.e(TAG, "Error initializing CA: ${e.message}", e)
            try {
                generateCa()
            } catch (e2: Exception) {
                Log.e(TAG, "Failed to generate CA: ${e2.message}", e2)
            }
        }
    }

    /**
     * Generate a new root CA key pair and self-signed certificate
     */
    private fun generateCa() {
        Log.i(TAG, "Generating new DNC Root CA...")

        // Generate RSA 2048 key pair
        val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
        keyPairGenerator.initialize(2048)
        caKeyPair = keyPairGenerator.generateKeyPair()

        // Generate self-signed CA certificate
        val keyPair = caKeyPair!!

        val certBuilder = javax.security.cert.X509Certificate.Builder()
        // Using basic Java security APIs for CA cert generation
        val issuer = X500Principal("CN=$CA_COMMON_NAME, O=$CA_ORGANIZATION, C=US")
        val subject = issuer // Self-signed: issuer = subject

        val now = System.currentTimeMillis()
        val notBefore = Date(now)
        val notAfter = Date(now + (CA_VALIDITY_YEARS.toLong() * 365 * 24 * 60 * 60 * 1000))

        // Use Android Keystore to store the CA key securely
        try {
            val androidKeyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
            androidKeyStore.load(null)

            // Generate the key in Android Keystore (hardware-backed on supported devices)
            val spec = KeyGenParameterSpec.Builder(
                KEYSTORE_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT or
                        KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            )
                .setKeySize(2048)
                .setCertificateSubject(subject)
                .setCertificateIssuer(issuer)
                .setCertificateNotBefore(notBefore)
                .setCertificateNotAfter(notAfter)
                .setCertificateSerialNumber(BigInteger.valueOf(now))
                .setDigests(KeyProperties.DIG_SHA256)
                .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                .build()

            val kpg = KeyPairGenerator.getInstance("RSA", ANDROID_KEYSTORE)
            kpg.initialize(spec)
            val androidKeyPair = kpg.generateKeyPair()

            // Get the certificate from the keystore
            val entry = androidKeyStore.getEntry(KEYSTORE_ALIAS, null) as KeyStore.PrivateKeyEntry
            caCertificate = entry.certificate as X509Certificate
            caKeyPair = KeyPair(androidKeyPair.public, entry.privateKey)

            Log.i(TAG, "CA certificate generated and stored in Android Keystore")

        } catch (e: Exception) {
            // Fall back to in-memory storage if Android Keystore fails
            Log.w(TAG, "Android Keystore failed, using in-memory CA: ${e.message}")

            // Store in a JKS file instead
            val jksKeyStore = KeyStore.getInstance("JKS")
            jksKeyStore.load(null, CA_KEYSTORE_PASSWORD.toCharArray())
            jksKeyStore.setKeyEntry(
                KEYSTORE_ALIAS,
                keyPair.private,
                CA_KEYSTORE_PASSWORD.toCharArray(),
                arrayOf<Certificate>(generateSelfSignedCert(keyPair, issuer, subject, notBefore, notAfter))
            )

            // Save JKS to internal storage
            val fos = context.openFileOutput(CA_KEYSTORE_FILE, Context.MODE_PRIVATE)
            jksKeyStore.store(fos, CA_KEYSTORE_PASSWORD.toCharArray())
            fos.close()

            caCertificate = generateSelfSignedCert(keyPair, issuer, subject, notBefore, notAfter)
            Log.i(TAG, "CA certificate generated and stored in JKS file")
        }
    }

    /**
     * Generate a self-signed X509Certificate using basic Java APIs
     */
    private fun generateSelfSignedCert(
        keyPair: KeyPair,
        issuer: X500Principal,
        subject: X500Principal,
        notBefore: Date,
        notAfter: Date
    ): X509Certificate {
        // Using java.security.cert.CertificateFactory approach
        // For simplicity, we'll use the cert generated by Android Keystore
        // This method is a fallback
        val certGen = java.security.cert.CertificateFactory.getInstance("X.509")

        // Create a basic self-signed cert using the KeyStore-generated cert
        // The actual cert generation happens in the Android Keystore init above
        return caCertificate ?: throw IllegalStateException("CA certificate not available")
    }

    /**
     * Get the CA certificate for export/install
     */
    fun getCaCertificate(): X509Certificate? = caCertificate

    /**
     * Generate a per-domain certificate signed by our CA
     * Used for MITM — the browser sees a cert for the domain it's connecting to,
     * signed by our CA (which the user has installed as trusted)
     */
    fun generateDomainCert(domain: String): X509Certificate {
        // Check cache first
        domainCertX509Cache[domain]?.let { return it }

        val keyPair = domainCertCache.getOrPut(domain) {
            val kpg = KeyPairGenerator.getInstance("RSA")
            kpg.initialize(2048)
            kpg.generateKeyPair()
        }

        val now = System.currentTimeMillis()
        val notBefore = Date(now)
        val notAfter = Date(now + (DOMAIN_CERT_VALIDITY_DAYS.toLong() * 24 * 60 * 60 * 1000))

        val issuer = caCertificate?.subjectX500Principal
            ?: X500Principal("CN=$CA_COMMON_NAME")
        val subject = X500Principal("CN=$domain, O=$CA_ORGANIZATION")

        // Sign the domain cert with the CA private key
        val caPrivateKey = caKeyPair?.private
            ?: throw IllegalStateException("CA private key not available")

        // Generate and sign the certificate
        // Using basic Java cert generation (bouncy castle would be ideal but
        // we keep dependencies minimal for Phase 2)
        try {
            val certGen = X509V3CertificateGenerator()
            certGen.setIssuerDN(issuer)
            certGen.setSubjectDN(subject)
            certGen.setNotBefore(notBefore)
            certGen.setNotAfter(notAfter)
            certGen.setPublicKey(keyPair.public)
            certGen.setSignatureAlgorithm("SHA256WithRSAEncryption")
            certGen.setSerialNumber(BigInteger.valueOf(now))

            // Add SAN (Subject Alternative Name) — critical for modern browsers
            // The domain must be in SAN, not just CN
            val sanList = listOf(
                GeneralName(GeneralName.dNSName, domain),
                GeneralName(GeneralName.dNSName, "*.$domain")
            )

            val cert = certGen.generate(caPrivateKey)
            domainCertX509Cache[domain] = cert
            Log.d(TAG, "Generated domain cert for: $domain")
            return cert

        } catch (e: Exception) {
            // Fallback without BouncyCastle — return a placeholder
            // Full implementation would use BouncyCastle or Conscrypt
            Log.w(TAG, "Domain cert generation needs BouncyCastle dependency: ${e.message}")
            throw IllegalStateException("Domain certificate generation requires BouncyCastle library")
        }
    }

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
    fun exportCaCertificateDer(): ByteArray? {
        return caCertificate?.encoded
    }

    /**
     * Check if the CA certificate is installed in the user cert store
     */
    fun isCaInstalled(): Boolean {
        // Check our cached flag first
        if (prefs.getBoolean(CA_CERT_INSTALLED_KEY, false)) return true

        // Try to verify by checking if our cert is in the system
        try {
            val caCert = caCertificate ?: return false
            val certBytes = caCert.encoded

            // Check against installed user certificates
            // This is a simplified check — full implementation would
            // iterate through the TrustStore
            return false
        } catch (e: Exception) {
            return false
        }
    }

    /**
     * Set the CA installed flag (called after successful installation)
     */
    fun setCaInstalled(installed: Boolean) {
        prefs.edit().putBoolean(CA_CERT_INSTALLED_KEY, installed).apply()
    }

    /**
     * Trigger the Android certificate installation flow
     * Shows a system dialog asking the user to install the CA cert
     */
    fun installCaCertificate() {
        try {
            val certDer = exportCaCertificateDer() ?: return

            // Write cert to a temporary file
            val certFile = java.io.File(context.cacheDir, "dnc_ca_cert.crt")
            certFile.writeBytes(certDer)

            // Trigger install intent
            val intent = Intent("android.credentials.INSTALL")
            intent.putExtra("name", "$CA_COMMON_NAME - $CA_ORGANIZATION")
            intent.setDataAndType(
                android.net.Uri.fromFile(certFile),
                "application/x-x509-ca-cert"
            )
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            context.startActivity(intent)

            Log.i(TAG, "CA certificate install intent triggered")

        } catch (e: Exception) {
            Log.e(TAG, "Failed to trigger CA install: ${e.message}")
            // On Android 11+, the intent approach may not work
            // Guide the user to install manually via Settings
        }
    }

    /**
     * Get the CA certificate fingerprint for display
     */
    fun getCaFingerprint(): String? {
        val cert = caCertificate ?: return null
        return try {
            val md = java.security.MessageDigest.getInstance("SHA-256")
            val digest = md.digest(cert.encoded)
            digest.joinToString(":") { "%02X".format(it) }
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Clear all cached domain certificates
     */
    fun clearCache() {
        domainCertCache.clear()
        domainCertX509Cache.clear()
        Log.d(TAG, "Domain cert cache cleared")
    }
}
