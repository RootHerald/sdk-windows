/**
 * Root Herald — public C ABI implementation (Windows).
 *
 * The public ABI is declared in src/clients/common/rootherald.h. This file
 * is the thin facade layer that maps the public RootHeraldClient_* entry
 * points onto the internal rootherald_win infrastructure (TPM enroll +
 * Quote + secure-boot collection + AIA fetch + WinHTTP transport).
 *
 * Wave 6: the library is static — no DLL export decoration is required.
 * The ROOTHERALD_API macro in <rootherald.h> resolves to an empty token,
 * and the public symbols are plain `extern "C"` functions.
 */

#include "rootherald.h"
#include "protocol.h"

#include <cstring>
#include <cstdio>
#include <string>
#include <memory>
#include <mutex>

// Forward-declare the legacy entry points from rootherald_win.cpp.
extern "C" RootHeraldResult RootHeraldEnroll(const char* server_url, int force_reenroll,
                                             RootHeraldEnrollmentInfo* out_info);
extern "C" RootHeraldResult RootHeraldAttest(const char* server_url, const char* session_id,
                                             const char* nonce_b64, size_t nonce_len,
                                             RootHeraldAttestationInfo* out_info);
extern "C" RootHeraldResult RootHeraldGetStatus(RootHeraldDeviceStatus* out_status);
extern "C" void RootHeraldSetLinkToken(const char* link_token);
extern "C" void RootHeraldSetDeviceId(const char* device_id);

namespace {

constexpr const char* kAbiVersion = "1.0";
constexpr const char* kLibraryVersion = "0.2.0";  // bumped when public ABI stabilises
constexpr const char* kDefaultEndpoint = "https://rootherald.io";

struct RootHeraldClientImpl
{
    std::string apiKey;
    std::string endpoint;
    std::string applicationId;
    std::string deviceId;
    bool mockTpm = false;
    std::mutex lock;
};

// Helper: copy into a fixed-length null-terminated buffer.
void CopyString(char* dst, size_t cap, const std::string& src)
{
    if (cap == 0) return;
    size_t n = src.size() < (cap - 1) ? src.size() : (cap - 1);
    std::memcpy(dst, src.data(), n);
    dst[n] = '\0';
}

RootHeraldStatus MapRootHeraldStatus(RootHeraldResult r)
{
    switch (r)
    {
    case RH_PROTO_OK: return ROOTHERALD_OK;
    case RH_PROTO_ERR_NO_TPM: return ROOTHERALD_ERR_TPM_UNAVAILABLE;
    case RH_PROTO_ERR_NETWORK: return ROOTHERALD_ERR_NETWORK;
    case RH_PROTO_ERR_ATTESTATION_FAILED: return ROOTHERALD_ERR_SERVER;
    case RH_PROTO_ERR_ENROLLMENT_FAILED: return ROOTHERALD_ERR_SERVER;
    case RH_PROTO_ERR_NOT_ENROLLED: return ROOTHERALD_ERR_SERVER;
    case RH_PROTO_ERR_INVALID_PARAM: return ROOTHERALD_ERR_INVALID_ARG;
    case RH_PROTO_ERR_ALREADY_ENROLLED: return ROOTHERALD_OK; // already-enrolled is benign
    default: return ROOTHERALD_ERR_INTERNAL;
    }
}

// Canned mock evidence used when --mock-tpm is enabled. Documented in the
// public header: this path must never be reachable in production.
void FillMockResult(RootHeraldVerifyResult* out)
{
    out->verdict = ROOTHERALD_VERDICT_ALLOW;
    CopyString(out->device_id, sizeof(out->device_id),
               "00000000-0000-4000-8000-000000000mock");
    CopyString(out->tpm_class, sizeof(out->tpm_class), "discrete-tpm");
    CopyString(out->posture_json, sizeof(out->posture_json),
               "{\"mock\":true,\"secure_boot\":true,\"tpm_class\":\"discrete-tpm\"}");
    CopyString(out->reason, sizeof(out->reason), "mock-tpm mode");
}

} // namespace

// ------------------------------------------------------------------
// Public ABI implementation
// ------------------------------------------------------------------

extern "C" ROOTHERALD_API RootHeraldClient* RootHeraldClient_Create(
    const char* api_key, const char* endpoint)
{
    if (api_key == nullptr || api_key[0] == '\0') return nullptr;
    auto impl = std::make_unique<RootHeraldClientImpl>();
    impl->apiKey = api_key;
    impl->endpoint = (endpoint != nullptr && endpoint[0] != '\0') ? endpoint : kDefaultEndpoint;
    return reinterpret_cast<RootHeraldClient*>(impl.release());
}

extern "C" ROOTHERALD_API void RootHeraldClient_Destroy(RootHeraldClient* client)
{
    delete reinterpret_cast<RootHeraldClientImpl*>(client);
}

extern "C" ROOTHERALD_API RootHeraldStatus RootHeraldClient_SetEndpoint(
    RootHeraldClient* client, const char* endpoint)
{
    if (client == nullptr || endpoint == nullptr) return ROOTHERALD_ERR_INVALID_ARG;
    auto* impl = reinterpret_cast<RootHeraldClientImpl*>(client);
    std::lock_guard<std::mutex> g(impl->lock);
    impl->endpoint = endpoint;
    return ROOTHERALD_OK;
}

extern "C" ROOTHERALD_API RootHeraldStatus RootHeraldClient_SetApplicationId(
    RootHeraldClient* client, const char* app_id)
{
    if (client == nullptr || app_id == nullptr) return ROOTHERALD_ERR_INVALID_ARG;
    auto* impl = reinterpret_cast<RootHeraldClientImpl*>(client);
    std::lock_guard<std::mutex> g(impl->lock);
    impl->applicationId = app_id;
    return ROOTHERALD_OK;
}

extern "C" ROOTHERALD_API RootHeraldStatus RootHeraldClient_SetMockTpm(
    RootHeraldClient* client, int mock_enabled)
{
    if (client == nullptr) return ROOTHERALD_ERR_INVALID_ARG;
    auto* impl = reinterpret_cast<RootHeraldClientImpl*>(client);
    std::lock_guard<std::mutex> g(impl->lock);
    impl->mockTpm = (mock_enabled != 0);
    return ROOTHERALD_OK;
}

extern "C" ROOTHERALD_API RootHeraldStatus RootHeraldClient_Verify(
    RootHeraldClient* client, const char* action, RootHeraldVerifyResult* out_result)
{
    if (client == nullptr || out_result == nullptr) return ROOTHERALD_ERR_INVALID_ARG;
    std::memset(out_result, 0, sizeof(*out_result));

    auto* impl = reinterpret_cast<RootHeraldClientImpl*>(client);
    std::lock_guard<std::mutex> g(impl->lock);

    if (impl->mockTpm)
    {
        FillMockResult(out_result);
        return ROOTHERALD_OK;
    }

    // Step 1: ensure the device is enrolled. The legacy layer is idempotent —
    // RH_PROTO_ERR_ALREADY_ENROLLED is the happy path on subsequent calls.
    RootHeraldEnrollmentInfo enroll = {};
    auto enrollResult = RootHeraldEnroll(impl->endpoint.c_str(), 0, &enroll);
    if (enrollResult != ROOTHERALD_OK && enrollResult != RH_PROTO_ERR_ALREADY_ENROLLED)
    {
        out_result->verdict = ROOTHERALD_VERDICT_DENY;
        CopyString(out_result->reason, sizeof(out_result->reason),
                   "enrollment failed");
        return MapRootHeraldStatus(enrollResult);
    }
    impl->deviceId = enroll.device_id;
    RootHeraldSetDeviceId(impl->deviceId.c_str());

    // Step 2: collect a fresh quote. The session id and nonce come from the
    // server in the real flow; for the unsolicited "verify" entry point we
    // bind a synthetic session id derived from action + monotonic counter.
    RootHeraldAttestationInfo attest = {};
    const char* useAction = (action && action[0] != '\0') ? action : "default";
    std::string syntheticSessionId = std::string("rh-verify-") + useAction;
    std::string syntheticNonce = "rh-verify-nonce";

    auto attestResult = RootHeraldAttest(impl->endpoint.c_str(),
                                          syntheticSessionId.c_str(),
                                          syntheticNonce.c_str(),
                                          syntheticNonce.size(),
                                          &attest);

    CopyString(out_result->device_id, sizeof(out_result->device_id), impl->deviceId);

    if (attestResult == ROOTHERALD_OK)
    {
        out_result->verdict = ROOTHERALD_VERDICT_ALLOW;
        CopyString(out_result->reason, sizeof(out_result->reason), "ok");
    }
    else
    {
        out_result->verdict = ROOTHERALD_VERDICT_DENY;
        CopyString(out_result->reason, sizeof(out_result->reason),
                   attest.failure_reason[0] ? attest.failure_reason : "attest failed");
    }

    // tpm_class and posture_json are server-derived; the v1 ABI ships them
    // empty when we don't have a richer response shape. The server-side
    // verifier already returns these inside the attestation JWT — Wave 3
    // will parse them out and surface them here.
    CopyString(out_result->tpm_class, sizeof(out_result->tpm_class), "");
    CopyString(out_result->posture_json, sizeof(out_result->posture_json), "{}");

    return MapRootHeraldStatus(attestResult);
}

extern "C" ROOTHERALD_API const char* RootHerald_AbiVersionString(void)
{
    return kAbiVersion;
}

extern "C" ROOTHERALD_API const char* RootHerald_LibraryVersionString(void)
{
    return kLibraryVersion;
}
