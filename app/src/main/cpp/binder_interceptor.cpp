#include <android/binder.h>
#include <binder/Binder.h>
#include <binder/Common.h>
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <binder/Parcel.h>
#include <sys/ioctl.h>
#include <utils/StrongPointer.h>

#include <atomic>
#include <cinttypes>
#include <map>
#include <mutex>
#include <shared_mutex>
#include <queue>
#include <string_view>
#include <thread>
#include <utility>

#include "logging.hpp"
#include "lsplt.hpp"

using namespace android;

namespace {
namespace intercept {
constexpr uint32_t kRegisterInterceptor = 1;
constexpr uint32_t kUnregisterInterceptor = 2;
constexpr uint32_t kPreTransact = 1;
constexpr uint32_t kPostTransact = 2;
constexpr uint32_t kActionSkipTransaction = 1;
constexpr uint32_t kActionContinue = 2;
constexpr uint32_t kActionOverrideReply = 3;
constexpr uint32_t kActionOverrideData = 4;
constexpr uint32_t kActionContinueAndSkipPost = 5;
constexpr uint32_t kBackdoorCode = 0xdeadbeef;
constexpr std::string_view kBinderLibName = "/libbinder.so";
constexpr std::string_view kIoctlSymbol = "ioctl";
} 
}

int (*g_original_ioctl)(int fd, int request, ...) = nullptr;
static std::atomic<uint64_t> g_transaction_id_counter = 0;

struct ThreadTransactionInfo {
    uint64_t transaction_id;
    uint32_t transaction_code;
    wp<BBinder> target_binder;
    ThreadTransactionInfo() : transaction_id(0), transaction_code(0) {}
    ThreadTransactionInfo(uint64_t id, uint32_t code, wp<BBinder> target)
        : transaction_id(id), transaction_code(code), target_binder(std::move(target)) {}
};

static std::mutex g_thread_context_mutex;
static std::map<std::thread::id, std::queue<ThreadTransactionInfo>> g_thread_context_map;

class BinderInterceptor : public BBinder {
    struct RegistrationEntry {
        wp<IBinder> target;
        sp<IBinder> callback_interface;
        std::vector<uint32_t> filtered_codes;
    };
    mutable std::shared_mutex registry_mutex_;
    std::map<wp<IBinder>, RegistrationEntry> registry_;

public:
    BinderInterceptor() = default;
    bool shouldIntercept(const wp<BBinder> &target, uint32_t code) const {
        std::shared_lock lock(registry_mutex_);
        auto it = registry_.find(target);
        if (it == registry_.end()) return false;
        const auto &codes = it->second.filtered_codes;
        return codes.empty() || std::find(codes.begin(), codes.end(), code) != codes.end();
    }
    bool processInterceptedTransaction(uint64_t tx_id, sp<BBinder> target, uint32_t code, const Parcel &data,
                                       Parcel *reply, uint32_t flags, status_t &result);
protected:
    status_t onTransact(uint32_t code, const Parcel &data, Parcel *reply, uint32_t flags) override;
private:
    status_t handleRegister(const Parcel &data);
    status_t handleUnregister(const Parcel &data);
    status_t writeTransactionData(Parcel &out, uint64_t tx_id, sp<BBinder> target, uint32_t code, uint32_t flags,
                                  const Parcel &in_data) const;
};

static sp<BinderInterceptor> g_interceptor_instance = nullptr;

class BinderStub : public BBinder {
public:
    const String16& getInterfaceDescriptor() const override {
        static const String16 kDescriptor("org.matrix.TEESimulator.BinderStub");
        return kDescriptor;
    }

protected:
    status_t onTransact(uint32_t code, const Parcel &data, Parcel *reply, uint32_t flags) override {
        if (code != intercept::kBackdoorCode) return UNKNOWN_TRANSACTION;

        ThreadTransactionInfo info;
        bool found_context = false;

        {
            std::lock_guard<std::mutex> lock(g_thread_context_mutex);
            auto it = g_thread_context_map.find(std::this_thread::get_id());
            if (it != g_thread_context_map.end() && !it->second.empty()) {
                info = std::move(it->second.front());
                it->second.pop();
                if (it->second.empty()) g_thread_context_map.erase(it);
                found_context = true;
            }
        }

        if (!found_context) return UNKNOWN_TRANSACTION;

        if (info.transaction_code == intercept::kBackdoorCode && info.target_binder == nullptr && reply) {
            reply->writeStrongBinder(g_interceptor_instance);
            return OK;
        }

        sp<BBinder> real_target = info.target_binder.promote();
        if (!real_target) return DEAD_OBJECT;

        status_t status = OK;
        bool interceptorManagedFlow = g_interceptor_instance->processInterceptedTransaction(
            info.transaction_id, real_target, info.transaction_code, data, reply, flags, status);

        if (!interceptorManagedFlow) {
            // [核心修复点] 绝对不要调用 setDataPosition(0)！
            // data 的读取指针此时刚好停在 Interface Token 之后，完美符合 real_target->transact 的预期要求。
            status = real_target->transact(info.transaction_code, data, reply, flags);
        }

        return status;
    }
};

static sp<BinderStub> g_stub_instance = nullptr;

namespace {
void inspectAndRewriteTransaction(binder_transaction_data *txn_data) {
    if (!txn_data || txn_data->target.ptr == 0) return;
    if (txn_data->code > 0x00ffffffu && txn_data->code != intercept::kBackdoorCode) return;

    bool hijack = false;
    ThreadTransactionInfo info;

    if (txn_data->code == intercept::kBackdoorCode && txn_data->sender_euid == 0) {
        info.transaction_code = intercept::kBackdoorCode;
        info.target_binder = nullptr;
        hijack = true;
    } else if (txn_data->sender_euid == 0) {
        txn_data->sender_euid = 1000;
        hijack = false;
    } else {
        RefBase::weakref_type *weak_ref = reinterpret_cast<RefBase::weakref_type *>(txn_data->target.ptr);
        if (weak_ref && weak_ref->attemptIncStrong(nullptr)) {
            BBinder *target_binder_ptr = reinterpret_cast<BBinder *>(txn_data->cookie);
            wp<BBinder> wp_target = target_binder_ptr;
            if (g_interceptor_instance->shouldIntercept(wp_target, txn_data->code)) {
                info.transaction_code = txn_data->code;
                info.target_binder = wp_target;
                hijack = true;
            }
            target_binder_ptr->decStrong(nullptr);
        }
    }

    if (hijack) {
        info.transaction_id = ++g_transaction_id_counter;
        txn_data->target.ptr = reinterpret_cast<uintptr_t>(g_stub_instance->getWeakRefs());
        txn_data->cookie = reinterpret_cast<uintptr_t>(g_stub_instance.get());
        txn_data->code = intercept::kBackdoorCode;

        std::lock_guard<std::mutex> lock(g_thread_context_mutex);
        g_thread_context_map[std::this_thread::get_id()].push(std::move(info));
    }
}

void processBinderReadBuffer(const binder_write_read &bwr) {
    if (bwr.read_size == 0 || bwr.read_consumed == 0 || bwr.read_buffer == 0) return;
    uintptr_t ptr = bwr.read_buffer;
    uintptr_t end = ptr + bwr.read_consumed;

    while (ptr < end) {
        if (end - ptr < sizeof(uint32_t)) break;
        uint32_t cmd = *reinterpret_cast<const uint32_t *>(ptr);
        ptr += sizeof(uint32_t);
        size_t cmd_size = _IOC_SIZE(cmd);
        if (ptr + cmd_size > end) break;

        if (__builtin_expect(cmd == BR_TRANSACTION || cmd == BR_TRANSACTION_SEC_CTX, 0)) {
            binder_transaction_data *txn;
            if (cmd == BR_TRANSACTION_SEC_CTX) {
                txn = &reinterpret_cast<binder_transaction_data_secctx *>(ptr)->transaction_data;
            } else {
                txn = reinterpret_cast<binder_transaction_data *>(ptr);
            }
            inspectAndRewriteTransaction(txn);
        }
        ptr += cmd_size;
    }
}
} 

int intercepted_ioctl(int fd, int request, ...) {
    va_list ap;
    va_start(ap, request);
    void *arg = va_arg(ap, void *);
    va_end(ap);

    int result = g_original_ioctl(fd, request, arg);

    if (result >= 0 && request == BINDER_WRITE_READ && arg != nullptr) {
        const auto *bwr = static_cast<const binder_write_read *>(arg);
        if (bwr->read_consumed >= sizeof(uint32_t)) {
            uint32_t first_cmd = *reinterpret_cast<const uint32_t *>(bwr->read_buffer);
            if (first_cmd == BR_TRANSACTION || first_cmd == BR_TRANSACTION_SEC_CTX
                || bwr->read_consumed > sizeof(uint32_t) + _IOC_SIZE(first_cmd)) {
                processBinderReadBuffer(*bwr);
            }
        }
    }
    return result;
}

#define VALIDATE_STATUS(tx_id, expr)                                                                               \
    do {                                                                                                           \
        status_t __result = (expr);                                                                                \
        if (__result != OK) {                                                                                      \
            return __result;                                                                                       \
        }                                                                                                          \
    } while (0)

status_t BinderInterceptor::onTransact(uint32_t code, const Parcel &data, Parcel *reply, uint32_t flags) {
    switch (code) {
    case intercept::kRegisterInterceptor: return handleRegister(data);
    case intercept::kUnregisterInterceptor: return handleUnregister(data);
    default: return BBinder::onTransact(code, data, reply, flags);
    }
}

status_t BinderInterceptor::handleRegister(const Parcel &data) {
    sp<IBinder> target;
    sp<IBinder> callback;
    if (data.readStrongBinder(&target) != OK || !target) return BAD_VALUE;
    if (data.readStrongBinder(&callback) != OK || !callback) return BAD_VALUE;
    std::vector<uint32_t> codes;
    int32_t code_count = 0;
    if (data.dataAvail() >= sizeof(int32_t) && data.readInt32(&code_count) == OK && code_count > 0) {
        codes.reserve(code_count);
        for (int32_t i = 0; i < code_count; i++) {
            uint32_t c = 0;
            if (data.readUint32(&c) == OK) codes.push_back(c);
        }
    }
    wp<IBinder> weak_target = target;
    std::unique_lock lock(registry_mutex_);
    registry_[weak_target] = {weak_target, callback, std::move(codes)};
    return OK;
}

status_t BinderInterceptor::handleUnregister(const Parcel &data) {
    sp<IBinder> target;
    if (data.readStrongBinder(&target) != OK || !target) return BAD_VALUE;
    wp<IBinder> weak_target = target;
    std::unique_lock lock(registry_mutex_);
    if (registry_.erase(weak_target) > 0) return OK;
    return NAME_NOT_FOUND;
}

status_t BinderInterceptor::writeTransactionData(Parcel &out, uint64_t tx_id, sp<BBinder> target, uint32_t code,
                                                 uint32_t flags, const Parcel &in_data) const {
    VALIDATE_STATUS(tx_id, out.writeInt64(tx_id));
    VALIDATE_STATUS(tx_id, out.writeStrongBinder(target));
    VALIDATE_STATUS(tx_id, out.writeUint32(code));
    VALIDATE_STATUS(tx_id, out.writeUint32(flags));
    VALIDATE_STATUS(tx_id, out.writeInt32(IPCThreadState::self()->getCallingUid()));
    VALIDATE_STATUS(tx_id, out.writeInt32(IPCThreadState::self()->getCallingPid()));
    VALIDATE_STATUS(tx_id, out.writeUint64(in_data.dataSize()));
    VALIDATE_STATUS(tx_id, out.appendFrom(&in_data, 0, in_data.dataSize()));
    return OK;
}

bool BinderInterceptor::processInterceptedTransaction(uint64_t tx_id, sp<BBinder> target, uint32_t code,
                                                      const Parcel &request, Parcel *reply, uint32_t flags,
                                                      status_t &result) {
    sp<IBinder> callback;
    {
        std::shared_lock lock(registry_mutex_);
        auto it = registry_.find(target);
        if (it == registry_.end()) return false;
        callback = it->second.callback_interface;
    }

    Parcel pre_req, pre_resp;
    writeTransactionData(pre_req, tx_id, target, code, flags, request);

    status_t pre_status = callback->transact(intercept::kPreTransact, pre_req, &pre_resp);
    if (pre_status != OK) {
        if (callback->pingBinder() != OK) { result = DEAD_OBJECT; return true; }
        return false;
    }

    int32_t action = pre_resp.readInt32();

    if (action == intercept::kActionOverrideReply) {
        if (reply) {
            result = pre_resp.readInt32();
            size_t size = pre_resp.readUint64();
            reply->setDataSize(0);
            reply->appendFrom(&pre_resp, pre_resp.dataPosition(), size);
        }
        return true;
    }

    if (action == intercept::kActionSkipTransaction) { result = OK; return true; }
    if (action == intercept::kActionContinueAndSkipPost) { result = OK; return false; }

    Parcel final_request;
    if (action == intercept::kActionOverrideData) {
        size_t size = pre_resp.readUint64();
        final_request.appendFrom(&pre_resp, pre_resp.dataPosition(), size);
        result = target->transact(code, final_request, reply, flags);
    } else {
        result = target->transact(code, request, reply, flags);
    }

    Parcel post_req, post_resp;
    writeTransactionData(post_req, tx_id, target, code, flags, final_request.dataSize() > 0 ? final_request : request);
    VALIDATE_STATUS(tx_id, post_req.writeInt32(result));
    size_t reply_size = (reply) ? reply->dataSize() : 0;
    VALIDATE_STATUS(tx_id, post_req.writeUint64(reply_size));
    if (reply && reply_size > 0) {
        VALIDATE_STATUS(tx_id, post_req.appendFrom(reply, 0, reply_size));
    }

    status_t post_status = callback->transact(intercept::kPostTransact, post_req, &post_resp);
    if (post_status == OK) {
        int32_t post_action = post_resp.readInt32();
        if (post_action == intercept::kActionOverrideReply && reply) {
            result = post_resp.readInt32();
            size_t new_size = post_resp.readUint64();
            reply->setDataSize(0);
            VALIDATE_STATUS(tx_id, reply->appendFrom(&post_resp, post_resp.dataPosition(), new_size));
        }
    }
    return true;
}

bool initialize_hooks() {
    auto maps = lsplt::MapInfo::Scan();
    dev_t binder_dev = 0; ino_t binder_ino = 0; bool found = false;

    for (const auto &map : maps) {
        if (map.path.ends_with(intercept::kBinderLibName)) {
            binder_dev = map.dev; binder_ino = map.inode; found = true; break;
        }
    }
    if (!found) return false;

    g_interceptor_instance = sp<BinderInterceptor>::make();
    g_stub_instance = sp<BinderStub>::make();

    lsplt::RegisterHook(binder_dev, binder_ino, intercept::kIoctlSymbol.data(),
                        reinterpret_cast<void *>(intercepted_ioctl), reinterpret_cast<void **>(&g_original_ioctl));

    return lsplt::CommitHook();
}

extern "C" [[gnu::visibility("default")]] [[gnu::used]]
bool entry(void *handle) { return initialize_hooks(); }
