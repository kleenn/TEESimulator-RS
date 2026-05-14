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
import android.util.Log
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap
import org.matrix.TEESimulator.attestation.AttestationPatcher
import org.matrix.TEESimulator.attestation.KeyMintAttestation
import org.matrix.TEESimulator.config.ConfigurationManager
import org.matrix.TEESimulator.interception.keystore.shim.GeneratedKeyPersistence
import org.matrix.TEESimulator.interception.keystore.shim.KeyMintSecurityLevelInterceptor
import org.matrix.TEESimulator.logging.SystemLogger
import org.matrix.TEESimulator.pki.CertificateGenerator
import org.matrix.TEESimulator.pki.CertificateHelper

@SuppressLint("BlockedPrivateApi")
object Keystore2Interceptor : AbstractKeystoreInterceptor() {
    private const val TRACE_TAG = "TEESim_Trace"

    private fun trace(uid: Int, txId: Long, message: String) {
        if (ConfigurationManager.shouldPatch(uid)) {
            Log.i(TRACE_TAG, "[UID:$uid] [TX:$txId] $message")
        }
    }

    private val stubBinderClass = IKeystoreService.Stub::class.java

    private val GET_KEY_ENTRY_TRANSACTION = InterceptorUtils.getTransactCode(stubBinderClass, "getKeyEntry")
    private val DELETE_KEY_TRANSACTION = InterceptorUtils.getTransactCode(stubBinderClass, "deleteKey")
    private val UPDATE_SUBCOMPONENT_TRANSACTION = InterceptorUtils.getTransactCode(stubBinderClass, "updateSubcomponent")
    private val LIST_ENTRIES_TRANSACTION = InterceptorUtils.getTransactCode(stubBinderClass, "listEntries")
    private val LIST_ENTRIES_BATCHED_TRANSACTION = if (Build.VERSION.SDK_INT >= 34) InterceptorUtils.getTransactCode(stubBinderClass, "listEntriesBatched") else null
    private val GET_NUMBER_OF_ENTRIES_TRANSACTION = InterceptorUtils.getTransactCode(stubBinderClass, "getNumberOfEntries")
    private val GET_SECURITY_LEVEL_TRANSACTION = InterceptorUtils.getTransactCode(stubBinderClass, "getSecurityLevel")

    private val transactionNames: Map<Int, String> by lazy {
        stubBinderClass.declaredFields
            .filter { it.isAccessible = true; it.type == Int::class.java && it.name.startsWith("TRANSACTION_") }
            .associate { field -> (field.get(null) as Int) to field.name.split("_")[1] }
    }

    private const val RESPONSE_KEY_NOT_FOUND = 7
    private val deletedSoftwareKeys: MutableSet<KeyIdentifier> = ConcurrentHashMap.newKeySet()
    private val userUpdatedKeys = ConcurrentHashMap.newKeySet<KeyIdentifier>()
    private lateinit var interceptorBackdoor: IBinder

    override val serviceName = "android.system.keystore2.IKeystoreService/default"
    override val processName = "keystore2"
    override val injectionCommand = "exec ./inject `pidof keystore2` libTEESimulator.so entry"

    override val interceptedCodes: IntArray by lazy {
        listOfNotNull(
            GET_KEY_ENTRY_TRANSACTION, DELETE_KEY_TRANSACTION, UPDATE_SUBCOMPONENT_TRANSACTION,
            LIST_ENTRIES_TRANSACTION, LIST_ENTRIES_BATCHED_TRANSACTION, GET_NUMBER_OF_ENTRIES_TRANSACTION,
            GET_SECURITY_LEVEL_TRANSACTION
        ).toIntArray()
    }

    override fun onInterceptorReady(service: IBinder, backdoor: IBinder) {
        interceptorBackdoor = backdoor
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

    override fun onPreTransact(txId: Long, target: IBinder, code: Int, flags: Int, callingUid: Int, callingPid: Int, data: Parcel): TransactionResult {
        val txName = transactionNames[code] ?: "UNKNOWN_CODE_$code"
        trace(callingUid, txId, "==> onPreTransact: $txName started")

        // 记录原始游标，用于在不拦截时恢复，避免破坏原生包裹
        val originalDataPosition = data.dataPosition()

        if (code == GET_SECURITY_LEVEL_TRANSACTION) {
            return TransactionResult.Continue
        } else if (code == GET_NUMBER_OF_ENTRIES_TRANSACTION) {
            return if (ConfigurationManager.shouldSkipUid(callingUid)) TransactionResult.ContinueAndSkipPost else TransactionResult.Continue
        } else if (code == LIST_ENTRIES_TRANSACTION || code == LIST_ENTRIES_BATCHED_TRANSACTION) {
            if (ConfigurationManager.shouldSkipUid(callingUid)) return TransactionResult.ContinueAndSkipPost
            return runCatching {
                val isBatchMode = code == LIST_ENTRIES_BATCHED_TRANSACTION
                if (ListEntriesHandler.cacheParameters(txId, data, isBatchMode)) {
                    data.setDataPosition(originalDataPosition) // 恢复游标
                    TransactionResult.Continue 
                } else {
                    TransactionResult.ContinueAndSkipPost
                }
            }.getOrElse { TransactionResult.ContinueAndSkipPost }
        } else if (code == GET_KEY_ENTRY_TRANSACTION || code == DELETE_KEY_TRANSACTION || code == UPDATE_SUBCOMPONENT_TRANSACTION) {
            if (ConfigurationManager.shouldSkipUid(callingUid)) return TransactionResult.ContinueAndSkipPost

            return try {
                if (code == UPDATE_SUBCOMPONENT_TRANSACTION) {
                    val result = handleUpdateSubcomponent(callingUid, data)
                    if (result is TransactionResult.ContinueAndSkipPost || result is TransactionResult.Continue) {
                        data.setDataPosition(originalDataPosition)
                    }
                    return result
                }

                data.enforceInterface(IKeystoreService.DESCRIPTOR)
                val descriptor = data.readTypedObject(KeyDescriptor.CREATOR) ?: run {
                    trace(callingUid, txId, "onPreTransact: Failed to read KeyDescriptor")
                    data.setDataPosition(originalDataPosition)
                    return TransactionResult.ContinueAndSkipPost
                }

                trace(callingUid, txId, "Parsed Descriptor -> Domain: ${descriptor.domain}, Alias: ${descriptor.alias}, NSpace: ${descriptor.nspace}")

                var resolvedKeyId: KeyIdentifier? = null
                if (descriptor.domain == Domain.KEY_ID) {
                    for ((k, v) in KeyMintSecurityLevelInterceptor.generatedKeys) {
                        if (v.nspace == descriptor.nspace && k.uid == callingUid) {
                            resolvedKeyId = k
                            break
                        }
                    }
                } else if (descriptor.alias != null) {
                    resolvedKeyId = KeyIdentifier(callingUid, descriptor.alias)
                }

                if (code == DELETE_KEY_TRANSACTION) {
                    if (resolvedKeyId != null) {
                        val isSoftwareKey = KeyMintSecurityLevelInterceptor.generatedKeys.containsKey(resolvedKeyId)
                        KeyMintSecurityLevelInterceptor.cleanupKeyData(resolvedKeyId)
                        trace(callingUid, txId, "DELETE_KEY intercepted. isSoftwareKey=$isSoftwareKey")
                        if (isSoftwareKey) {
                            deletedSoftwareKeys.add(resolvedKeyId)
                            return InterceptorUtils.createSuccessReply(writeResultCode = false)
                        }
                    }
                    // [核心修补] 不拦截的 DELETE，必须倒带让硬件处理
                    data.setDataPosition(originalDataPosition)
                    return TransactionResult.ContinueAndSkipPost
                }

                if (resolvedKeyId == null) {
                    trace(callingUid, txId, "Key not found in local cache. Leaking to hardware.")
                    // [核心修补] 未在软件池找到，必须倒带后漏给硬件！
                    data.setDataPosition(originalDataPosition)
                    return TransactionResult.ContinueAndSkipPost
                }

                val response = KeyMintSecurityLevelInterceptor.getGeneratedKeyResponse(resolvedKeyId)
                if (response == null) {
                    if (deletedSoftwareKeys.remove(resolvedKeyId)) return InterceptorUtils.createErrorReply(RESPONSE_KEY_NOT_FOUND)
                    // [核心修补] 软件池为空，必须倒带后让硬件处理它的报错逻辑
                    data.setDataPosition(originalDataPosition)
                    return TransactionResult.Continue
                }

                trace(callingUid, txId, "Successfully hijacked $txName. Returning simulated KeyEntryResponse.")
                InterceptorUtils.createTypedObjectReply(response)

            } catch (e: Exception) {
                trace(callingUid, txId, "Exception in onPreTransact: ${e.message}")
                data.setDataPosition(originalDataPosition)
                TransactionResult.ContinueAndSkipPost
            }
        }
        return TransactionResult.ContinueAndSkipPost
    }

    override fun onPostTransact(txId: Long, target: IBinder, code: Int, flags: Int, callingUid: Int, callingPid: Int, data: Parcel, reply: Parcel?, resultCode: Int): TransactionResult {
        if (target != keystoreService || reply == null || InterceptorUtils.hasException(reply)) return TransactionResult.SkipTransaction

        if (code == GET_SECURITY_LEVEL_TRANSACTION) {
            return runCatching {
                val originalDataPosition = data.dataPosition()
                data.enforceInterface(IKeystoreService.DESCRIPTOR)
                val requestedLevel = data.readInt()
                data.setDataPosition(originalDataPosition) // Post 阶段习惯性回退，保持纯净
                
                val replyCopy = Parcel.obtain()
                replyCopy.appendFrom(reply, 0, reply.dataSize())
                replyCopy.setDataPosition(0)
                replyCopy.readException()
                val returnedBinder = replyCopy.readStrongBinder()
                replyCopy.recycle()

                if (returnedBinder != null) {
                    trace(callingUid, txId, "<== onPostTransact: Hijacking newly created SecurityLevel session (level=$requestedLevel)")
                    val securityLevelInterface = android.system.keystore2.IKeystoreSecurityLevel.Stub.asInterface(returnedBinder)
                    val interceptor = KeyMintSecurityLevelInterceptor(securityLevelInterface, requestedLevel)
                    register(interceptorBackdoor, returnedBinder, interceptor, KeyMintSecurityLevelInterceptor.INTERCEPTED_CODES)
                }
                TransactionResult.SkipTransaction
            }.getOrElse { TransactionResult.SkipTransaction }
        } else if (code == GET_KEY_ENTRY_TRANSACTION) {
            try {
                val originalDataPosition = data.dataPosition()
                data.enforceInterface(IKeystoreService.DESCRIPTOR)
                val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR) ?: run {
                    data.setDataPosition(originalDataPosition)
                    return TransactionResult.SkipTransaction
                }
                data.setDataPosition(originalDataPosition)

                if (!ConfigurationManager.shouldPatch(callingUid)) return TransactionResult.SkipTransaction

                var keyId: KeyIdentifier? = null
                if (keyDescriptor.domain == Domain.KEY_ID) {
                    for ((k, v) in KeyMintSecurityLevelInterceptor.generatedKeys) {
                        if (v.nspace == keyDescriptor.nspace && k.uid == callingUid) {
                            keyId = k
                            break
                        }
                    }
                } else if (keyDescriptor.alias != null) {
                    keyId = KeyIdentifier(callingUid, keyDescriptor.alias)
                }
                
                if (keyId == null) return TransactionResult.SkipTransaction

                trace(callingUid, txId, "<== onPostTransact: Hardware GET_KEY_ENTRY completed for known KeyId. We are patching the certificate chain now.")
                
                val response = reply.readTypedObject(KeyEntryResponse.CREATOR) ?: return TransactionResult.SkipTransaction
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
                    val keyData = CertificateGenerator.generateAttestedKeyPair(callingUid, keyId.alias, null, parsedParameters, response.metadata.keySecurityLevel) ?: return TransactionResult.SkipTransaction
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
            } catch (e: Exception) {
                trace(callingUid, txId, "<== onPostTransact Exception: ${e.message}")
                return TransactionResult.SkipTransaction
            }
        } else if (code == GET_NUMBER_OF_ENTRIES_TRANSACTION) {
             return runCatching {
                val totalCount = reply.readInt() + KeyMintSecurityLevelInterceptor.generatedKeys.keys.count { it.uid == callingUid }
                TransactionResult.OverrideReply(Parcel.obtain().apply { writeNoException(); writeInt(totalCount) })
            }.getOrElse { TransactionResult.SkipTransaction }
        } else if (code == LIST_ENTRIES_TRANSACTION || code == LIST_ENTRIES_BATCHED_TRANSACTION) {
            return runCatching {
                InterceptorUtils.createTypedArrayReply(ListEntriesHandler.injectGeneratedKeys(txId, callingUid, reply))
            }.getOrElse { TransactionResult.SkipTransaction }
        }
        
        return TransactionResult.SkipTransaction
    }

    private fun handleUpdateSubcomponent(callingUid: Int, data: Parcel): TransactionResult {
        try {
            data.enforceInterface(IKeystoreService.DESCRIPTOR)
            val descriptor = data.readTypedObject(KeyDescriptor.CREATOR) ?: return TransactionResult.ContinueAndSkipPost
            var generatedKeyInfo: KeyMintSecurityLevelInterceptor.GeneratedKeyInfo? = null
            if (descriptor.domain == Domain.KEY_ID) {
                for ((k, v) in KeyMintSecurityLevelInterceptor.generatedKeys) {
                    if (v.nspace == descriptor.nspace && k.uid == callingUid) {
                        generatedKeyInfo = v; break
                    }
                }
            } else if (descriptor.domain == Domain.APP && descriptor.alias != null) {
                generatedKeyInfo = KeyMintSecurityLevelInterceptor.generatedKeys[KeyIdentifier(callingUid, descriptor.alias!!)]
            }
            if (generatedKeyInfo == null) {
                descriptor.alias?.let { userUpdatedKeys.add(KeyIdentifier(callingUid, it)) }
                return TransactionResult.ContinueAndSkipPost
            }
            generatedKeyInfo.response.metadata.certificate = data.createByteArray()
            generatedKeyInfo.response.metadata.certificateChain = data.createByteArray()
            GeneratedKeyPersistence.rePersistIfNeeded(callingUid, generatedKeyInfo)
            return InterceptorUtils.createSuccessReply(writeResultCode = false)
        } catch (e: Exception) { return TransactionResult.ContinueAndSkipPost }
    }
}
