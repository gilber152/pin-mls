package com.pinmls.app.security

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Genera una clave aleatoria de 32 bytes para SQLCipher y la guarda cifrada
 * con una clave maestra no exportable dentro de Android Keystore (AES-256-GCM).
 */
object VaultKeyManager {
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val KEY_ALIAS = "pin_mls_sqlcipher_master_key_v1"
    private const val PREFS_NAME = "pin_mls_keystore_wrap"
    private const val PREF_WRAPPED_KEY = "wrapped_db_key_b64"
    private const val PREF_IV = "wrapped_db_iv_b64"

    fun getOrCreateDbKeyHex(context: Context): String {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val wrappedB64 = prefs.getString(PREF_WRAPPED_KEY, null)
        val ivB64 = prefs.getString(PREF_IV, null)

        val masterKey = getOrCreateMasterKey()

        if (wrappedB64 != null && ivB64 != null) {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(
                Cipher.DECRYPT_MODE,
                masterKey,
                GCMParameterSpec(128, Base64.decode(ivB64, Base64.NO_WRAP)),
            )
            val rawKey = cipher.doFinal(Base64.decode(wrappedB64, Base64.NO_WRAP))
            return rawKey.joinToString("") { "%02x".format(it) }
        }

        val rawKey = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, masterKey)
        val wrapped = cipher.doFinal(rawKey)

        prefs.edit()
            .putString(PREF_WRAPPED_KEY, Base64.encodeToString(wrapped, Base64.NO_WRAP))
            .putString(PREF_IV, Base64.encodeToString(cipher.iv, Base64.NO_WRAP))
            .apply()

        return rawKey.joinToString("") { "%02x".format(it) }
    }

    private fun getOrCreateMasterKey(): SecretKey {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        (ks.getKey(KEY_ALIAS, null) as? SecretKey)?.let { return it }

        val spec = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .build()

        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
            .apply { init(spec) }
            .generateKey()
    }
}
