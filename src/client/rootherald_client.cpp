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
#include "client_internal.h"

#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <memory>
#include <mutex>

namespace {

/* Derived from the header so the reported version cannot drift from the one
 * consumers compile against. */
#define RH_STR2(x) #x
#define RH_STR(x)  RH_STR2(x)
constexpr const char* kAbiVersion =
    RH_STR(ROOTHERALD_ABI_VERSION_MAJOR) "." RH_STR(ROOTHERALD_ABI_VERSION_MINOR);
constexpr const char* kLibraryVersion = "0.2.0";  // bumped when public ABI stabilises

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

} // namespace

// ------------------------------------------------------------------
// Public ABI implementation
// ------------------------------------------------------------------

extern "C" ROOTHERALD_API RootHeraldClient* RootHeraldClient_Create(void)
{
    auto impl = std::make_unique<RootHeraldClient>();
    return impl.release();
}

extern "C" ROOTHERALD_API void RootHeraldClient_Destroy(RootHeraldClient* client)
{
    delete client;
}

extern "C" ROOTHERALD_API RootHeraldStatus RootHeraldClient_SetApplicationId(
    RootHeraldClient* client, const char* app_id)
{
    if (client == nullptr || app_id == nullptr) return ROOTHERALD_ERR_INVALID_ARG;
    std::lock_guard<std::mutex> g(client->lock);
    client->applicationId = app_id;
    return ROOTHERALD_OK;
}

extern "C" ROOTHERALD_API RootHeraldStatus RootHeraldClient_EnrollBegin(
    RootHeraldClient* client, char** out_request_json)
{
    if (client == nullptr || out_request_json == nullptr) return ROOTHERALD_ERR_INVALID_ARG;
    *out_request_json = nullptr;

    std::lock_guard<std::mutex> g(client->lock);

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

    std::lock_guard<std::mutex> g(client->lock);

    // Keyless: TPM2_ActivateCredential over the relayed challenge, emit the
    // /activate body.
    return MapRootHeraldStatus(RootHeraldEnrollComplete(challenge_json, out_activation_json));
}

extern "C" ROOTHERALD_API RootHeraldStatus RootHeraldClient_GetDeviceInfo(
    RootHeraldClient* client, RootHeraldDeviceInfo* out_result)
{
    if (client == nullptr || out_result == nullptr) return ROOTHERALD_ERR_INVALID_ARG;
    std::memset(out_result, 0, sizeof(*out_result));

    std::lock_guard<std::mutex> g(client->lock);

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

    std::lock_guard<std::mutex> g(client->lock);

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
