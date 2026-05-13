package org.matrix.TEESimulator.interception.keystore

import android.annotation.SuppressLint
import android.hardware.security.keymint.SecurityLevel
import android.os.Build
import android.os.IBinder
import android.os.Parcel
import android.system.keystore2.Domain
import android.system.keystore2.IKeystoreService
import android.system.keystore2.KeyDescriptor
import android.system.keystore2.KeyEntryResponse
import java.security.SecureRandom
import java.security.cert.Certificate
import java.util.concurrent.ConcurrentHashMap
import org.matrix.TEESimulator.attestation.AttestationPatcher
import org.matrix.TEESimulator.attestation.KeyMintAttestation
import org.matrix.TEESimulator.config.ConfigurationManager
import org.matrix.TEESimulator.interception.keystore.shim.GeneratedKeyPersistence
import org.matrix.TEESimulator.interception.keystore.shim.KeyMintSecurityLevelInterceptor
import org.matrix.TEESimulator.logging.KeyMintParameterLogger
import org.matrix.TEESimulator.logging.SystemLogger
import org.matrix.TEESimulator.pki.CertificateGenerator
import org.matrix.TEESimulator.pki.CertificateHelper

@SuppressLint("BlockedPrivateApi")
object Keystore2Interceptor : AbstractKeystoreInterceptor() {
    private val stubBinderClass = IKeystoreService.Stub::class.java

    private val GET_KEY_ENTRY_TRANSACTION = InterceptorUtils.getTransactCode(stubBinderClass, "getKeyEntry")
    private val DELETE_KEY_TRANSACTION = InterceptorUtils.getTransactCode(stubBinderClass, "deleteKey")
    private val UPDATE_SUBCOMPONENT_TRANSACTION = InterceptorUtils.getTransactCode(stubBinderClass, "updateSubcomponent")
    private val LIST_ENTRIES_TRANSACTION = InterceptorUtils.getTransactCode(stubBinderClass, "listEntries")
    private val LIST_ENTRIES_BATCHED_TRANSACTION = if (Build.VERSION.SDK_INT >= 34) InterceptorUtils.getTransactCode(stubBinderClass, "listEntriesBatched") else null
    private val GET_NUMBER_OF_ENTRIES_TRANSACTION = InterceptorUtils.getTransactCode(stubBinderClass, "getNumberOfEntries")

    private val transactionNames: Map<Int, String> by lazy {
        stubBinderClass.declaredFields
            .filter { 
                it.isAccessible = true
                it.type == Int::class.java && it.name.startsWith("TRANSACTION_") 
            }
            .associate { field -> (field.get(null) as Int) to field.name.split("_")[1] }
    }

    private const val RESPONSE_KEY_NOT_FOUND = 7
    private val deletedSoftwareKeys: MutableSet<KeyIdentifier> = ConcurrentHashMap.newKeySet()
    private val userUpdatedKeys = ConcurrentHashMap.newKeySet<KeyIdentifier>()

    override val serviceName = "android.system.keystore2.IKeystoreService/default"
    override val processName = "keystore2"
    override val injectionCommand = "exec ./inject `pidof keystore2` libTEESimulator.so entry"

    override val interceptedCodes: IntArray by lazy {
        listOfNotNull(
            GET_KEY_ENTRY_TRANSACTION, DELETE_KEY_TRANSACTION, UPDATE_SUBCOMPONENT_TRANSACTION,
            LIST_ENTRIES_TRANSACTION, LIST_ENTRIES_BATCHED_TRANSACTION, GET_NUMBER_OF_ENTRIES_TRANSACTION
        ).toIntArray()
    }

    override fun onInterceptorReady(service: IBinder, backdoor: IBinder) {
        val keystoreInterface = IKeystoreService.Stub.asInterface(service)
        setupSecurityLevelInterceptors(keystoreInterface, backdoor)
    }

    private fun setupSecurityLevelInterceptors(service: IKeystoreService, backdoor: IBinder) {
        runCatching {
            service.getSecurityLevel(SecurityLevel.TRUSTED_ENVIRONMENT)?.let { tee ->
                val interceptor = KeyMintSecurityLevelInterceptor(tee, SecurityLevel.TRUSTED_ENVIRONMENT)
                register(backdoor, tee.asBinder(), interceptor, KeyMintSecurityLevelInterceptor.INTERCEPTED_CODES)
                interceptor.loadPersistedKeys()
            }
        }.onFailure { SystemLogger.error("Failed to intercept TEE SecurityLevel.", it) }

        runCatching {
            service.getSecurityLevel(SecurityLevel.STRONGBOX)?.let { strongbox ->
                val interceptor = KeyMintSecurityLevelInterceptor(strongbox, SecurityLevel.STRONGBOX)
                register(backdoor, strongbox.asBinder(), interceptor, KeyMintSecurityLevelInterceptor.INTERCEPTED_CODES)
                interceptor.loadPersistedKeys()
            }
        }.onFailure { SystemLogger.error("Failed to intercept StrongBox SecurityLevel.", it) }
    }

    override fun onPreTransact(
        txId: Long, target: IBinder, code: Int, flags: Int, callingUid: Int, callingPid: Int, data: Parcel
    ): TransactionResult {
        if (code == GET_NUMBER_OF_ENTRIES_TRANSACTION) {
            logTransaction(txId, transactionNames[code]!!, callingUid, callingPid, true)
            return if (ConfigurationManager.shouldSkipUid(callingUid)) TransactionResult.ContinueAndSkipPost else TransactionResult.Continue
        } else if (code == LIST_ENTRIES_TRANSACTION || code == LIST_ENTRIES_BATCHED_TRANSACTION) {
            logTransaction(txId, transactionNames[code]!!, callingUid, callingPid, true)
            val packages = ConfigurationManager.getPackagesForUid(callingUid).joinToString()
            if (packages.contains("com.google.android.gms") || ConfigurationManager.shouldSkipUid(callingUid)) {
                return TransactionResult.ContinueAndSkipPost
            }
            return runCatching {
                val isBatchMode = code == LIST_ENTRIES_BATCHED_TRANSACTION
                if (ListEntriesHandler.cacheParameters(txId, data, isBatchMode)) TransactionResult.Continue else TransactionResult.ContinueAndSkipPost
            }.getOrElse {
                SystemLogger.error("[TX_ID: $txId] Failed to parse parameters for ${transactionNames[code]!!}", it)
                TransactionResult.ContinueAndSkipPost
            }
        } else if (code == GET_KEY_ENTRY_TRANSACTION || code == DELETE_KEY_TRANSACTION || code == UPDATE_SUBCOMPONENT_TRANSACTION) {
            logTransaction(txId, transactionNames[code]!!, callingUid, callingPid)

            if (ConfigurationManager.shouldSkipUid(callingUid)) return TransactionResult.ContinueAndSkipPost

            return try {
                if (code == UPDATE_SUBCOMPONENT_TRANSACTION) return handleUpdateSubcomponent(callingUid, data)

                data.enforceInterface(IKeystoreService.DESCRIPTOR)
                val descriptor = data.readTypedObject(KeyDescriptor.CREATOR) ?: return TransactionResult.ContinueAndSkipPost

                if (code == DELETE_KEY_TRANSACTION) {
                    val keyId = if (descriptor.alias != null) {
                        KeyIdentifier(callingUid, descriptor.alias)
                    } else if (descriptor.domain == Domain.KEY_ID) {
                        KeyMintSecurityLevelInterceptor.findGeneratedKeyByKeyId(callingUid, descriptor.nspace)?.let { info ->
                            KeyMintSecurityLevelInterceptor.generatedKeys.entries.find { it.value.nspace == info.nspace && it.key.uid == callingUid }?.key
                        }
                    } else null

                    if (keyId != null) {
                        val isSoftwareKey = KeyMintSecurityLevelInterceptor.generatedKeys.containsKey(keyId)
                        KeyMintSecurityLevelInterceptor.cleanupKeyData(keyId)
                        if (isSoftwareKey) {
                            deletedSoftwareKeys.add(keyId)
                            return InterceptorUtils.createSuccessReply(writeResultCode = false)
                        }
                    }
                    return TransactionResult.ContinueAndSkipPost
                }

                if (descriptor.alias == null) return TransactionResult.ContinueAndSkipPost
                val keyId = KeyIdentifier(callingUid, descriptor.alias)

                val response = KeyMintSecurityLevelInterceptor.getGeneratedKeyResponse(keyId)
                if (response == null) {
                    if (deletedSoftwareKeys.remove(keyId)) return InterceptorUtils.createErrorReply(RESPONSE_KEY_NOT_FOUND)
                    return TransactionResult.Continue
                }

                InterceptorUtils.createTypedObjectReply(response)

            } catch (e: android.os.ServiceSpecificException) {
                InterceptorUtils.createErrorReply(e.errorCode)
            } catch (e: Exception) {
                // [修复核心1：绝不拦截畸形探针]
                // 放弃将畸形包转为 -1，而是将其直接放给原生 Keystore2。
                // 真正的原生服务遇到畸形包会返回底层 BAD_VALUE (-22)，这样检测器就抓不到私有异常了！
                SystemLogger.error("[TX_ID: $txId] Caught malformed parcel from probe, dropping interception", e)
                TransactionResult.ContinueAndSkipPost
            }
        } else {
            logTransaction(txId, transactionNames[code] ?: "unknown code=$code", callingUid, callingPid, true)
        }
        return TransactionResult.ContinueAndSkipPost
    }

    override fun onPostTransact(
        txId: Long, target: IBinder, code: Int, flags: Int, callingUid: Int, callingPid: Int, data: Parcel, reply: Parcel?, resultCode: Int
    ): TransactionResult {
        if (target != keystoreService || reply == null || InterceptorUtils.hasException(reply)) return TransactionResult.SkipTransaction

        if (code == GET_NUMBER_OF_ENTRIES_TRANSACTION) {
            return runCatching {
                val totalCount = reply.readInt() + KeyMintSecurityLevelInterceptor.generatedKeys.keys.count { it.uid == callingUid }
                TransactionResult.OverrideReply(Parcel.obtain().apply { writeNoException(); writeInt(totalCount) })
            }.getOrElse { TransactionResult.SkipTransaction }
        } else if (code == LIST_ENTRIES_TRANSACTION || code == LIST_ENTRIES_BATCHED_TRANSACTION) {
            return runCatching {
                InterceptorUtils.createTypedArrayReply(ListEntriesHandler.injectGeneratedKeys(txId, callingUid, reply))
            }.getOrElse { TransactionResult.SkipTransaction }
        } else if (code == GET_KEY_ENTRY_TRANSACTION) {
            data.enforceInterface(IKeystoreService.DESCRIPTOR)
            val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR) ?: return TransactionResult.SkipTransaction
            if (!ConfigurationManager.shouldPatch(callingUid)) return TransactionResult.SkipTransaction

            runCatching {
                val response = reply.readTypedObject(KeyEntryResponse.CREATOR)!!
                val keyId = KeyIdentifier(callingUid, keyDescriptor.alias)

                if (userUpdatedKeys.remove(keyId)) return TransactionResult.SkipTransaction

                val parsedParameters = KeyMintAttestation(response.metadata.authorizations?.map { it.keyParameter }?.toTypedArray() ?: emptyArray())

                if (parsedParameters.isImportKey()) {
                    val retainedChain = KeyMintSecurityLevelInterceptor.getPatchedChain(keyId) ?: return TransactionResult.SkipTransaction
                    CertificateHelper.updateCertificateChain(response.metadata, retainedChain).getOrThrow()
                    response.metadata.authorizations = InterceptorUtils.patchAuthorizations(response.metadata.authorizations, callingUid)
                    return InterceptorUtils.createTypedObjectReply(response)
                }

                if (KeyMintSecurityLevelInterceptor.importedKeys.contains(keyId)) return TransactionResult.SkipTransaction

                if (parsedParameters.isAttestKey()) {
                    val keyData = CertificateGenerator.generateAttestedKeyPair(callingUid, keyId.alias, null, parsedParameters, response.metadata.keySecurityLevel) ?: throw Exception("Failed")
                    CertificateHelper.updateCertificateChain(response.metadata, keyData.second.toTypedArray()).getOrThrow()
                    response.metadata.authorizations = InterceptorUtils.patchAuthorizations(response.metadata.authorizations, callingUid)
                    val newNspace = SecureRandom().nextLong()
                    response.metadata.key?.let { it.nspace = newNspace }
                    KeyMintSecurityLevelInterceptor.generatedKeys[keyId] = KeyMintSecurityLevelInterceptor.GeneratedKeyInfo(keyData.first, null, newNspace, response, parsedParameters)
                    KeyMintSecurityLevelInterceptor.attestationKeys.add(keyId)
                    GeneratedKeyPersistence.save(keyId, keyData.first, newNspace, response.metadata.keySecurityLevel, keyData.second, parsedParameters.algorithm, parsedParameters.keySize, parsedParameters.ecCurve ?: 0, parsedParameters.purpose, parsedParameters.digest, true)
                    return InterceptorUtils.createTypedObjectReply(response)
                }

                val originalChain = CertificateHelper.getCertificateChain(response)
                if (originalChain == null || originalChain.size < 2) return TransactionResult.SkipTransaction

                val cachedChain = KeyMintSecurityLevelInterceptor.getPatchedChain(keyId)
                val finalChain = cachedChain ?: AttestationPatcher.patchCertificateChain(originalChain, callingUid).also { KeyMintSecurityLevelInterceptor.patchedChains[keyId] = it }

                CertificateHelper.updateCertificateChain(response.metadata, finalChain).getOrThrow()
                response.metadata.authorizations = InterceptorUtils.patchAuthorizations(response.metadata.authorizations, callingUid)
                return InterceptorUtils.createTypedObjectReply(response)
            }.onFailure { return TransactionResult.SkipTransaction }
        }
        return TransactionResult.SkipTransaction
    }

    private fun handleUpdateSubcomponent(callingUid: Int, data: Parcel): TransactionResult {
        data.enforceInterface(IKeystoreService.DESCRIPTOR)
        val descriptor = data.readTypedObject(KeyDescriptor.CREATOR) ?: return TransactionResult.ContinueAndSkipPost
        val generatedKeyInfo = when (descriptor.domain) {
            Domain.KEY_ID -> KeyMintSecurityLevelInterceptor.findGeneratedKeyByKeyId(callingUid, descriptor.nspace)
            Domain.APP -> descriptor.alias?.let { KeyMintSecurityLevelInterceptor.generatedKeys[KeyIdentifier(callingUid, it)] }
            else -> null
        }
        if (generatedKeyInfo == null) {
            descriptor.alias?.let { userUpdatedKeys.add(KeyIdentifier(callingUid, it)) }
            return TransactionResult.ContinueAndSkipPost
        }
        generatedKeyInfo.response.metadata.certificate = data.createByteArray()
        generatedKeyInfo.response.metadata.certificateChain = data.createByteArray()
        GeneratedKeyPersistence.rePersistIfNeeded(callingUid, generatedKeyInfo)
        return InterceptorUtils.createSuccessReply(writeResultCode = false)
    }
}
