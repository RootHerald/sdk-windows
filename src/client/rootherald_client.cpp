/**
 * Root Herald — public C ABI implementation (Windows).
 *
 * The public ABI is declared in common/rootherald.h. This file is the thin
 * facade layer that maps the public RootHeraldClient_* entry points onto the
 * internal rootherald_win infrastructure (keyless TPM enroll begin/complete +
 * Quote + secure-boot collection + AIA fetch).
 *
 * ABI 3.0: the client is KEYLESS and opens NO socket to RootHerald. Create takes
 * no api_key / endpoint; enrollment is the two-leg blob-emitting handshake
 * EnrollBegin/EnrollComplete; per-attestation evidence is CollectEvidence. All
 * RootHerald network I/O lives in the embedder's backend, not here.
 *
 * Wave 6: the library is static — no DLL export decoration is required.
 * The ROOTHERALD_API macro in <rootherald.h> resolves to an empty token,
 * and the public symbols are plain `extern "C"` functions.
 */

#include "rootherald.h"
#include "protocol.h"

#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <memory>
#include <mutex>

// Forward-declare the internal (keyless) entry points from rootherald_win.cpp.
extern "C" RootHeraldResult RootHeraldEnrollBegin(char** out_enroll_json);
extern "C" RootHeraldResult RootHeraldEnrollComplete(const char* challenge_json,
                                                     char** out_activate_json);
extern "C" RootHeraldResult RootHeraldGetStatus(RootHeraldDeviceStatus* out_status);
extern "C" RootHeraldResult RootHeraldCollectLocalPosture(RootHeraldPosture* out_posture);
extern "C" RootHeraldResult RootHeraldCollectEvidence(const char* nonce_b64,
                                                      char** out_evidence_json);
extern "C" void RootHeraldFreeEvidence(char* evidence_json);

namespace {

constexpr const char* kAbiVersion = "3.0";
constexpr const char* kLibraryVersion = "0.2.0";  // bumped when public ABI stabilises

struct RootHeraldClientImpl
{
    std::string applicationId;
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
    case RH_PROTO_ERR_NOT_ENROLLED: return ROOTHERALD_ERR_NOT_ENROLLED;
    case RH_PROTO_ERR_INVALID_PARAM: return ROOTHERALD_ERR_INVALID_ARG;
    case RH_PROTO_ERR_ALREADY_ENROLLED: return ROOTHERALD_OK; // already-enrolled is benign
    case RH_PROTO_ERR_ELEVATION_REQUIRED: return ROOTHERALD_ERR_ELEVATION_REQUIRED;
    default: return ROOTHERALD_ERR_INTERNAL;
    }
}

// Emit a heap-allocated copy of `json` (malloc'd so the caller frees it with
// RootHeraldClient_FreeEvidence — which is free()). Used by the mock paths.
RootHeraldStatus EmitHeapJson(const std::string& json, char** out)
{
    char* buf = (char*)malloc(json.size() + 1);
    if (!buf) return ROOTHERALD_ERR_INTERNAL;
    std::memcpy(buf, json.c_str(), json.size() + 1);
    *out = buf;
    return ROOTHERALD_OK;
}

void FillMockDeviceInfo(RootHeraldDeviceInfo* out)
{
    out->is_enrolled = 1;
    out->has_tpm = 1;
    CopyString(out->device_id, sizeof(out->device_id),
               "00000000-0000-4000-8000-000000000mock");
    CopyString(out->platform_name, sizeof(out->platform_name), "windows");
}

// Canned all-green posture for mock-TPM mode — same convention as the other
// FillMock* helpers: never touch real hardware, never hit the network.
void FillMockPosture(RootHeraldPosture* out)
{
    out->has_tpm = 1;
    out->is_enrolled = 1;
    out->ek_cert_present = 1;
    out->secure_boot = 1;
    out->oem_keyed = 1;
    CopyString(out->oem_name, sizeof(out->oem_name), "MockOEM");
    out->boot_log_measurements = 42;
    out->boot_log_revoked = 0;
    CopyString(out->device_id, sizeof(out->device_id),
               "00000000-0000-4000-8000-000000000mock");
    CopyString(out->detail_json, sizeof(out->detail_json), "{\"mock\":true}");
}

} // namespace

// ------------------------------------------------------------------
// Public ABI implementation
// ------------------------------------------------------------------

extern "C" ROOTHERALD_API RootHeraldClient* RootHeraldClient_Create(void)
{
    auto impl = std::make_unique<RootHeraldClientImpl>();
    return reinterpret_cast<RootHeraldClient*>(impl.release());
}

extern "C" ROOTHERALD_API void RootHeraldClient_Destroy(RootHeraldClient* client)
{
    delete reinterpret_cast<RootHeraldClientImpl*>(client);
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

extern "C" ROOTHERALD_API RootHeraldStatus RootHeraldClient_EnrollBegin(
    RootHeraldClient* client, char** out_request_json)
{
    if (client == nullptr || out_request_json == nullptr) return ROOTHERALD_ERR_INVALID_ARG;
    *out_request_json = nullptr;

    auto* impl = reinterpret_cast<RootHeraldClientImpl*>(client);
    std::lock_guard<std::mutex> g(impl->lock);

    if (impl->mockTpm)
    {
        // Canned /devices/enroll body (base64 of placeholder bytes). CI only.
        return EmitHeapJson(
            "{\"ekPublicKey\":\"bW9jay1lay1wdWI=\","
            "\"akPublicArea\":\"bW9jay1hay1wdWI=\","
            "\"platform\":\"windows\"}",
            out_request_json);
    }

    // Keyless: gen AK + gather EK under one elevation, emit the /enroll body.
    // The provider is held resident for the matching EnrollComplete in THIS
    // process (single elevation spans begin -> complete; see rootherald_win.cpp).
    return MapRootHeraldStatus(RootHeraldEnrollBegin(out_request_json));
}

extern "C" ROOTHERALD_API RootHeraldStatus RootHeraldClient_EnrollComplete(
    RootHeraldClient* client, const char* challenge_json, char** out_activation_json)
{
    if (client == nullptr || out_activation_json == nullptr) return ROOTHERALD_ERR_INVALID_ARG;
    *out_activation_json = nullptr;
    if (challenge_json == nullptr || challenge_json[0] == '\0') return ROOTHERALD_ERR_INVALID_ARG;

    auto* impl = reinterpret_cast<RootHeraldClientImpl*>(client);
    std::lock_guard<std::mutex> g(impl->lock);

    if (impl->mockTpm)
    {
        // Canned /devices/activate body. CI only.
        return EmitHeapJson(
            "{\"deviceId\":\"00000000-0000-4000-8000-000000000mock\","
            "\"decryptedSecret\":\"bW9jay1zZWNyZXQ=\"}",
            out_activation_json);
    }

    // Keyless: TPM2_ActivateCredential over the relayed challenge, emit the
    // /activate body.
    return MapRootHeraldStatus(RootHeraldEnrollComplete(challenge_json, out_activation_json));
}

extern "C" ROOTHERALD_API RootHeraldStatus RootHeraldClient_GetDeviceInfo(
    RootHeraldClient* client, RootHeraldDeviceInfo* out_result)
{
    if (client == nullptr || out_result == nullptr) return ROOTHERALD_ERR_INVALID_ARG;
    std::memset(out_result, 0, sizeof(*out_result));

    auto* impl = reinterpret_cast<RootHeraldClientImpl*>(client);
    std::lock_guard<std::mutex> g(impl->lock);

    if (impl->mockTpm)
    {
        FillMockDeviceInfo(out_result);
        return ROOTHERALD_OK;
    }

    // Local-only: never touches the network.
    RootHeraldDeviceStatus status = {};
    auto result = RootHeraldGetStatus(&status);
    out_result->is_enrolled = status.is_enrolled;
    out_result->has_tpm = status.has_tpm;
    CopyString(out_result->device_id, sizeof(out_result->device_id), status.device_id);
    CopyString(out_result->platform_name, sizeof(out_result->platform_name), status.platform);
    return MapRootHeraldStatus(result);
}

extern "C" ROOTHERALD_API RootHeraldStatus RootHeraldClient_CollectPosture(
    RootHeraldClient* client, RootHeraldPosture* out_result)
{
    if (client == nullptr || out_result == nullptr) return ROOTHERALD_ERR_INVALID_ARG;
    std::memset(out_result, 0, sizeof(*out_result));

    auto* impl = reinterpret_cast<RootHeraldClientImpl*>(client);
    std::lock_guard<std::mutex> g(impl->lock);

    if (impl->mockTpm)
    {
        FillMockPosture(out_result);
        return ROOTHERALD_OK;
    }

    // LOCAL-ONLY: never touches the network.
    // Readiness signals, not a verdict — the verdict is always server-side.
    return MapRootHeraldStatus(RootHeraldCollectLocalPosture(out_result));
}

extern "C" ROOTHERALD_API RootHeraldStatus RootHeraldClient_CollectEvidence(
    const char* nonce_b64, char** out_evidence_json)
{
    // Per-attestation collect (keyless). HANDLE-LESS by design: no
    // RootHeraldClient* is required because no key is consulted and no RootHerald
    // network call is made. The embedder relays the returned blob to the
    // CUSTOMER's server, which appraises it via POST /api/v1/attestations/verify.
    if (out_evidence_json == nullptr) return ROOTHERALD_ERR_INVALID_ARG;
    *out_evidence_json = nullptr;
    if (nonce_b64 == nullptr || nonce_b64[0] == '\0') return ROOTHERALD_ERR_INVALID_ARG;

    return MapRootHeraldStatus(RootHeraldCollectEvidence(nonce_b64, out_evidence_json));
}

extern "C" ROOTHERALD_API void RootHeraldClient_FreeEvidence(char* evidence_json)
{
    RootHeraldFreeEvidence(evidence_json);
}

extern "C" ROOTHERALD_API const char* RootHerald_AbiVersionString(void)
{
    return kAbiVersion;
}

extern "C" ROOTHERALD_API const char* RootHerald_LibraryVersionString(void)
{
    return kLibraryVersion;
}
