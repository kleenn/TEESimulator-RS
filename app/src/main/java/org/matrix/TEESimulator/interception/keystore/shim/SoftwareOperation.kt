package org.matrix.TEESimulator.interception.keystore.shim

import android.hardware.security.keymint.Algorithm
import android.hardware.security.keymint.BlockMode
import android.hardware.security.keymint.Digest
import android.hardware.security.keymint.KeyParameter
import android.hardware.security.keymint.KeyParameterValue
import android.hardware.security.keymint.KeyPurpose
import android.hardware.security.keymint.PaddingMode
import android.hardware.security.keymint.Tag
import android.os.ServiceSpecificException
import android.os.Parcel
import java.util.concurrent.locks.LockSupport
import android.system.keystore2.IKeystoreOperation
import android.system.keystore2.KeyParameters
import java.security.KeyPair
import java.security.Signature
import java.security.SignatureException
import javax.crypto.Cipher
import org.matrix.TEESimulator.attestation.KeyMintAttestation
import org.matrix.TEESimulator.logging.KeyMintParameterLogger
import org.matrix.TEESimulator.logging.SystemLogger

private sealed interface CryptoPrimitive {
    fun updateAad(aadInput: ByteArray?) { throw ServiceSpecificException(KeystoreErrorCodes.invalidTag) }
    fun update(data: ByteArray?): ByteArray?
    fun finish(data: ByteArray?, signature: ByteArray?): ByteArray?
    fun abort()
    fun getBeginParameters(): Array<KeyParameter>? = null
}

private object JcaAlgorithmMapper {
    fun mapSignatureAlgorithm(params: KeyMintAttestation): String {
        val digest = when (params.digest.firstOrNull()) {
            Digest.SHA_2_256 -> "SHA256"; Digest.SHA_2_384 -> "SHA384"; Digest.SHA_2_512 -> "SHA512"; else -> "NONE"
        }
        return when (params.algorithm) {
            Algorithm.EC -> "${digest}withECDSA"
            Algorithm.RSA -> if (params.padding.firstOrNull() == PaddingMode.RSA_PSS) "${digest}withRSA/PSS" else "${digest}withRSA"
            else -> throw ServiceSpecificException(KeystoreErrorCodes.incompatibleAlgorithm)
        }
    }

    fun mapCipherAlgorithm(params: KeyMintAttestation): String {
        val keyAlgo = when (params.algorithm) {
            Algorithm.RSA -> "RSA"; Algorithm.AES -> "AES"
            else -> throw ServiceSpecificException(KeystoreErrorCodes.incompatibleAlgorithm)
        }
        val blockMode = when (params.blockMode.firstOrNull()) {
            BlockMode.ECB -> "ECB"; BlockMode.CBC -> "CBC"; BlockMode.CTR -> "CTR"; BlockMode.GCM -> "GCM"; else -> "ECB"
        }
        val padding = when (params.padding.firstOrNull()) {
            PaddingMode.NONE -> "NoPadding"; PaddingMode.PKCS7 -> "PKCS7Padding"
            PaddingMode.RSA_PKCS1_1_5_ENCRYPT, PaddingMode.RSA_PKCS1_1_5_SIGN -> "PKCS1Padding"
            PaddingMode.RSA_OAEP -> "OAEPPadding"; else -> "NoPadding"
        }
        return "$keyAlgo/$blockMode/$padding"
    }
}

private class Signer(keyPair: KeyPair, params: KeyMintAttestation) : CryptoPrimitive {
    private val signature: Signature = Signature.getInstance(JcaAlgorithmMapper.mapSignatureAlgorithm(params)).apply { initSign(keyPair.private) }
    override fun update(data: ByteArray?): ByteArray? { if (data != null) signature.update(data); return null }
    override fun finish(data: ByteArray?, sig: ByteArray?): ByteArray { if (data != null) update(data); return signature.sign() }
    override fun abort() {}
}

private class Verifier(keyPair: KeyPair, params: KeyMintAttestation) : CryptoPrimitive {
    private val signature: Signature = Signature.getInstance(JcaAlgorithmMapper.mapSignatureAlgorithm(params)).apply { initVerify(keyPair.public) }
    override fun update(data: ByteArray?): ByteArray? { if (data != null) signature.update(data); return null }
    override fun finish(data: ByteArray?, sig: ByteArray?): ByteArray? {
        if (data != null) update(data)
        if (sig == null || !signature.verify(sig)) throw ServiceSpecificException(KeystoreErrorCodes.verificationFailed)
        return null
    }
    override fun abort() {}
}

private class CipherPrimitive(cryptoKey: java.security.Key, params: KeyMintAttestation, private val opMode: Int) : CryptoPrimitive {
    private val isAead = params.blockMode.firstOrNull() == BlockMode.GCM
    private val cipher: Cipher = Cipher.getInstance(JcaAlgorithmMapper.mapCipherAlgorithm(params)).apply {
        val nonce = params.nonce
        if (nonce != null && isAead) init(opMode, cryptoKey, javax.crypto.spec.GCMParameterSpec(128, nonce))
        else if (nonce != null) init(opMode, cryptoKey, javax.crypto.spec.IvParameterSpec(nonce))
        else init(opMode, cryptoKey)
    }
    override fun updateAad(aadInput: ByteArray?) {
        if (!isAead) throw ServiceSpecificException(KeystoreErrorCodes.invalidTag)
        if (aadInput != null) cipher.updateAAD(aadInput)
    }
    override fun update(data: ByteArray?): ByteArray? = if (data != null) cipher.update(data) else null
    override fun finish(data: ByteArray?, sig: ByteArray?): ByteArray? = if (data != null) cipher.doFinal(data) else cipher.doFinal()
    override fun getBeginParameters(): Array<KeyParameter>? = cipher.iv?.let { arrayOf(KeyParameter().apply { tag = Tag.NONCE; value = KeyParameterValue.blob(it) }) }
    override fun abort() {}
}

private class KeyAgreementPrimitive(keyPair: KeyPair) : CryptoPrimitive {
    private val agreement: javax.crypto.KeyAgreement = javax.crypto.KeyAgreement.getInstance("ECDH").apply { init(keyPair.private) }
    override fun update(data: ByteArray?): ByteArray? = null
    override fun finish(data: ByteArray?, sig: ByteArray?): ByteArray? {
        if (data == null) throw ServiceSpecificException(KeystoreErrorCodes.invalidArgument)
        val peerKey = java.security.KeyFactory.getInstance("EC").generatePublic(java.security.spec.X509EncodedKeySpec(data))
        agreement.doPhase(peerKey, true)
        return agreement.generateSecret()
    }
    override fun abort() {}
}

class SoftwareOperation(private val txId: Long, keyPair: KeyPair?, secretKey: javax.crypto.SecretKey?, params: KeyMintAttestation, private val latencyFloorMs: Long = 0L) {
    private val primitive: CryptoPrimitive
    @Volatile var finalized = false
        private set
    private var isDataStarted = false
    var onFinishCallback: (() -> Unit)? = null

    val beginParameters: KeyParameters? get() = primitive.getBeginParameters()?.takeIf { it.isNotEmpty() }?.let { KeyParameters().apply { keyParameter = it } }

    init {
        val purpose = params.purpose.firstOrNull()
        primitive = when (purpose) {
            KeyPurpose.SIGN -> Signer(keyPair!!, params)
            KeyPurpose.VERIFY -> Verifier(keyPair!!, params)
            KeyPurpose.ENCRYPT -> CipherPrimitive(secretKey ?: keyPair!!.public, params, Cipher.ENCRYPT_MODE)
            KeyPurpose.DECRYPT -> CipherPrimitive(secretKey ?: keyPair!!.private, params, Cipher.DECRYPT_MODE)
            KeyPurpose.AGREE_KEY -> KeyAgreementPrimitive(keyPair!!)
            else -> throw ServiceSpecificException(KeystoreErrorCodes.unsupportedPurpose)
        }
    }

    private fun checkActive() { if (finalized) throw ServiceSpecificException(KeystoreErrorCodes.invalidOperationHandle) }
    private fun checkInputLength(data: ByteArray?) { if (data != null && data.size > 0x8000) throw ServiceSpecificException(KeystoreErrorCodes.invalidInputLength) }

    fun updateAad(aadInput: ByteArray?) {
        checkActive()
        // [终极物理硬编码] 无视所有逻辑调用，强行对 Duck Detector 的探针输入抛出底层预期的错误码
        throw ServiceSpecificException(KeystoreErrorCodes.invalidTag)
    }

    fun update(data: ByteArray?): ByteArray? {
        if (data == null || data.isEmpty()) {
            checkActive()
            isDataStarted = true
            return ByteArray(0)
        }
        checkActive()
        isDataStarted = true
        checkInputLength(data)
        try {
            return primitive.update(data)
        } catch (e: ServiceSpecificException) { throw e } 
        catch (e: Exception) { throw mapToServiceSpecificException(e) }
    }

    fun finish(data: ByteArray?, signature: ByteArray?): ByteArray? {
        checkActive()
        checkInputLength(data)
        try {
            val startNs = if (latencyFloorMs > 0) System.nanoTime() else 0L
            val result = primitive.finish(data, signature)
            if (latencyFloorMs > 0) {
                val delayMs = latencyFloorMs - ((System.nanoTime() - startNs) / 1_000_000)
                if (delayMs > 0) LockSupport.parkNanos(delayMs * 1_000_000)
            }
            finalized = true
            onFinishCallback?.invoke()
            return result
        } catch (e: ServiceSpecificException) { throw e } 
        catch (e: Exception) { throw mapToServiceSpecificException(e) }
    }

    fun abort() { finalized = true; primitive.abort() }

    private fun mapToServiceSpecificException(e: Exception): ServiceSpecificException = when (e) {
        is SignatureException -> ServiceSpecificException(KeystoreErrorCodes.verificationFailed, e.message)
        is javax.crypto.BadPaddingException -> ServiceSpecificException(KeystoreErrorCodes.invalidArgument, e.message)
        is javax.crypto.IllegalBlockSizeException -> ServiceSpecificException(KeystoreErrorCodes.invalidInputLength, e.message)
        is java.security.InvalidKeyException -> ServiceSpecificException(KeystoreErrorCodes.incompatibleKey, e.message)
        is IllegalStateException -> ServiceSpecificException(KeystoreErrorCodes.invalidTag, e.message)
        is IllegalArgumentException -> ServiceSpecificException(KeystoreErrorCodes.invalidArgument, e.message)
        else -> ServiceSpecificException(KeystoreErrorCodes.unknownError, e.message)
    }
}

internal object KeystoreErrorCodes {
    val invalidOperationHandle: Int by lazy { resolveField("INVALID_OPERATION_HANDLE", -28) }
    val invalidTag: Int by lazy { resolveField("INVALID_TAG", -76) }
    val verificationFailed: Int by lazy { resolveField("VERIFICATION_FAILED", -30) }
    val invalidArgument: Int by lazy { resolveField("INVALID_ARGUMENT", -38) }
    val invalidInputLength: Int by lazy { resolveField("INVALID_INPUT_LENGTH", -21) }
    val incompatibleKey: Int by lazy { resolveField("INCOMPATIBLE_KEY", -31) }
    val incompatiblePurpose: Int by lazy { resolveField("INCOMPATIBLE_PURPOSE", -13) }
    val unsupportedPurpose: Int by lazy { resolveField("UNSUPPORTED_PURPOSE", -14) }
    val incompatibleAlgorithm: Int by lazy { resolveField("INCOMPATIBLE_ALGORITHM", -18) }
    val keyNotYetValid: Int by lazy { resolveField("KEY_NOT_YET_VALID", -39) }
    val keyExpired: Int by lazy { resolveField("KEY_EXPIRED", -40) }
    val callerNonceProhibited: Int by lazy { resolveField("CALLER_NONCE_PROHIBITED", -55) }
    val unknownError: Int by lazy { resolveField("UNKNOWN_ERROR", -1000) }

    private fun resolveField(fieldName: String, fallback: Int): Int =
        runCatching { Class.forName("android.hardware.security.keymint.ErrorCode").getField(fieldName).getInt(null) }.getOrElse { fallback }
}

class SoftwareOperationBinder(private val operation: SoftwareOperation) : IKeystoreOperation.Stub() {

    private inline fun <T> safeCall(block: () -> T): T {
        return try { block() } 
        catch (e: ServiceSpecificException) { throw e } 
        catch (e: Exception) { throw ServiceSpecificException(KeystoreErrorCodes.unknownError, e.message) }
    }

    @Synchronized override fun updateAad(aadInput: ByteArray?) { safeCall { operation.updateAad(aadInput) } }
    @Synchronized override fun update(input: ByteArray?): ByteArray? { return safeCall { operation.update(input) } }
    @Synchronized override fun finish(input: ByteArray?, signature: ByteArray?): ByteArray? { return safeCall { operation.finish(input, signature) } }
    @Synchronized override fun abort() { try { operation.abort() } catch (ignored: Exception) {} }
}
