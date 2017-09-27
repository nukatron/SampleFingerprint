package com.nutron.sample.fingerprint

import android.Manifest
import android.app.KeyguardManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.support.annotation.RequiresApi
import android.support.v4.app.ActivityCompat
import android.support.v4.content.ContextCompat
import android.support.v4.hardware.fingerprint.FingerprintManagerCompat
import android.support.v4.os.CancellationSignal
import android.widget.Toast
import java.io.IOException
import java.security.*
import java.security.cert.CertificateException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.NoSuchPaddingException
import javax.crypto.SecretKey


class FingerprintHandler(private val context: Context): FingerprintManagerCompat.AuthenticationCallback() {

    private val KEY_NAME = "example_key"

    private lateinit var cancellationSignal: CancellationSignal
    private lateinit var cipher: Cipher
    private lateinit var fingerprintManager: FingerprintManagerCompat
    private lateinit var keyguardManager: KeyguardManager
    private var cryptoObject: FingerprintManagerCompat.CryptoObject? = null
    private val keyStore by lazy { KeyStore.getInstance("AndroidKeyStore") }
    private val keyGenerator by lazy {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        } else {
            return@lazy null
        }
    }

    @RequiresApi(Build.VERSION_CODES.M)
    fun init() {
        fingerprintManager = FingerprintManagerCompat.from(context)
        keyguardManager = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager

        if (!fingerprintManager.isHardwareDetected) {
            Toast.makeText(context, "No fingerprint hardware", Toast.LENGTH_LONG).show()
            return
        } else if(!keyguardManager.isKeyguardSecure) {
            Toast.makeText(context, "Lock screen security not enabled in Settings", Toast.LENGTH_LONG).show()
            return
        } else if (ContextCompat.checkSelfPermission(context,
                Manifest.permission.USE_FINGERPRINT) != PackageManager.PERMISSION_GRANTED) {
            Toast.makeText(context, "Fingerprint Permission not granted", Toast.LENGTH_LONG).show()
            return
        } else if (!fingerprintManager.hasEnrolledFingerprints()) {
            Toast.makeText(context, "No fingerprint enrolled", Toast.LENGTH_LONG).show()
            return
        }

        generateKey()

        if (cipherInit()) {
            cryptoObject = FingerprintManagerCompat.CryptoObject(cipher)
        }
    }

    @RequiresApi(Build.VERSION_CODES.M)
    fun startAuth() {
        if (ActivityCompat.checkSelfPermission(context,
                Manifest.permission.USE_FINGERPRINT) != PackageManager.PERMISSION_GRANTED) {
            Toast.makeText(context, "Fingerprint Permission not granted", Toast.LENGTH_LONG).show()
            return
        }

        if(cryptoObject == null) {
            Toast.makeText(context, "Somethings wrong, Maybe you miss to call init()", Toast.LENGTH_LONG).show()
            return
        }

        cancellationSignal = CancellationSignal()
        fingerprintManager.authenticate(cryptoObject, 0, cancellationSignal, this, null)

    }

    override fun onAuthenticationError(errMsgId: Int, errString: CharSequence?) {
        super.onAuthenticationError(errMsgId, errString)
        Toast.makeText(context, "Authentication error\n" + errString, Toast.LENGTH_LONG).show()
    }

    override fun onAuthenticationSucceeded(result: FingerprintManagerCompat.AuthenticationResult?) {
        super.onAuthenticationSucceeded(result)
        Toast.makeText(context, "Authentication succeeded.", Toast.LENGTH_LONG).show()
    }

    override fun onAuthenticationHelp(helpMsgId: Int, helpString: CharSequence?) {
        super.onAuthenticationHelp(helpMsgId, helpString)
        Toast.makeText(context, "Authentication help\n" + helpString, Toast.LENGTH_LONG).show()
    }

    override fun onAuthenticationFailed() {
        super.onAuthenticationFailed()
        Toast.makeText(context, "Authentication failed.", Toast.LENGTH_LONG).show()
    }

    @RequiresApi(Build.VERSION_CODES.M)
    private fun generateKey() {
        try {
            keyStore.load(null)
            keyGenerator?.init(KeyGenParameterSpec.Builder(KEY_NAME,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    .setUserAuthenticationRequired(true)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                    .build())
            keyGenerator?.generateKey()
        } catch (e: NoSuchAlgorithmException) {
            throw RuntimeException(e)
        } catch (e: InvalidAlgorithmParameterException) {
            throw RuntimeException(e)
        } catch (e: CertificateException) {
            throw RuntimeException(e)
        } catch (e: IOException) {
            throw RuntimeException(e)
        }
    }

    @RequiresApi(Build.VERSION_CODES.M)
    private fun cipherInit(): Boolean {
        try {
            cipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/"
                    + KeyProperties.BLOCK_MODE_CBC + "/"
                    + KeyProperties.ENCRYPTION_PADDING_PKCS7)

            keyStore.load(null)
            val key = keyStore.getKey(KEY_NAME, null) as SecretKey
            cipher.init(Cipher.ENCRYPT_MODE, key)
            return true
        } catch (e: KeyPermanentlyInvalidatedException) {
            return false
        } catch (e: KeyStoreException) {
            throw RuntimeException("Failed to init Cipher", e)
        } catch (e: CertificateException) {
            throw RuntimeException("Failed to init Cipher", e)
        } catch (e: IOException) {
            throw RuntimeException("Failed to init Cipher", e)
        } catch (e: NoSuchAlgorithmException) {
            throw RuntimeException("Failed to init Cipher", e)
        } catch (e: UnrecoverableKeyException) {
            throw RuntimeException("Failed to init Cipher", e)
        } catch (e: InvalidKeyException) {
            throw RuntimeException("Failed to init Cipher", e)
        } catch (e: NoSuchPaddingException) {
            throw RuntimeException("Failed to get Cipher", e)
        }
    }
}