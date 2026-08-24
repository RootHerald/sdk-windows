/*
 * The public C ABI declared in common/rootherald.h: argument validation,
 * per-client locking, and the single place internal results are flattened
 * into RootHeraldStatus.
 */

#include "rootherald.h"
#include "protocol.h"
#include "client_internal.h"

#include <sal.h>
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
constexpr const char* ABI_VERSION =
    RH_STR(ROOTHERALD_ABI_VERSION_MAJOR) "." RH_STR(ROOTHERALD_ABI_VERSION_MINOR);
constexpr const char* LIBRARY_VERSION = "0.2.0";

/* Always NUL-terminates; truncates rather than overrunning. */
void CopyString(_Out_writes_z_(capacity) char* destination, size_t capacity, const std::string& source)
{
    if (capacity == 0) return;
    size_t n = source.size() < (capacity - 1) ? source.size() : (capacity - 1);
    std::memcpy(destination, source.data(), n);
    destination[n] = '\0';
}

RootHeraldStatus MapRootHeraldStatus(RootHeraldResult result)
{
    switch (result)
    {
    case RH_PROTO_OK: return ROOTHERALD_OK;
    case RH_PROTO_ERR_NO_TPM: return ROOTHERALD_ERR_TPM_UNAVAILABLE;
    case RH_PROTO_ERR_NETWORK: return ROOTHERALD_ERR_NETWORK;
    case RH_PROTO_ERR_ATTESTATION_FAILED: return ROOTHERALD_ERR_SERVER;
    case RH_PROTO_ERR_ENROLLMENT_FAILED: return ROOTHERALD_ERR_SERVER;
    case RH_PROTO_ERR_NOT_ENROLLED: return ROOTHERALD_ERR_NOT_ENROLLED;
    case RH_PROTO_ERR_INVALID_PARAM: return ROOTHERALD_ERR_INVALID_ARG;
    case RH_PROTO_ERR_ALREADY_ENROLLED: return ROOTHERALD_OK; // benign
    case RH_PROTO_ERR_ELEVATION_REQUIRED: return ROOTHERALD_ERR_ELEVATION_REQUIRED;
    default: return ROOTHERALD_ERR_INTERNAL;
    }
}

} // namespace

extern "C" _Use_decl_annotations_ ROOTHERALD_API RootHeraldClient* RootHeraldClient_Create(void)
{
    auto impl = std::make_unique<RootHeraldClient>();
    return impl.release();
}

extern "C" _Use_decl_annotations_ ROOTHERALD_API void RootHeraldClient_Destroy(RootHeraldClient* client)
{
    delete client;
}

extern "C" _Use_decl_annotations_ ROOTHERALD_API RootHeraldStatus RootHeraldClient_SetApplicationId(
    RootHeraldClient* client, const char* app_id)
{
    if (client == nullptr || app_id == nullptr) return ROOTHERALD_ERR_INVALID_ARG;
    std::lock_guard<std::mutex> guard(client->lock);
    client->applicationId = app_id;
    return ROOTHERALD_OK;
}

extern "C" _Use_decl_annotations_ ROOTHERALD_API RootHeraldStatus RootHeraldClient_EnrollBegin(
    RootHeraldClient* client, char** out_request_json)
{
    if (client == nullptr || out_request_json == nullptr) return ROOTHERALD_ERR_INVALID_ARG;
    *out_request_json = nullptr;

    std::lock_guard<std::mutex> guard(client->lock);
    return MapRootHeraldStatus(RootHeraldEnrollBegin(out_request_json));
}

extern "C" _Use_decl_annotations_ ROOTHERALD_API RootHeraldStatus RootHeraldClient_EnrollComplete(
    RootHeraldClient* client, const char* challenge_json, char** out_activation_json)
{
    if (client == nullptr || out_activation_json == nullptr) return ROOTHERALD_ERR_INVALID_ARG;
    *out_activation_json = nullptr;
    if (challenge_json == nullptr || challenge_json[0] == '\0') return ROOTHERALD_ERR_INVALID_ARG;

    std::lock_guard<std::mutex> guard(client->lock);
    return MapRootHeraldStatus(RootHeraldEnrollComplete(challenge_json, out_activation_json));
}

extern "C" _Use_decl_annotations_ ROOTHERALD_API RootHeraldStatus RootHeraldClient_GetDeviceInfo(
    RootHeraldClient* client, RootHeraldDeviceInfo* out_result)
{
    if (client == nullptr || out_result == nullptr) return ROOTHERALD_ERR_INVALID_ARG;
    std::memset(out_result, 0, sizeof(*out_result));

    std::lock_guard<std::mutex> guard(client->lock);

    RootHeraldDeviceStatus status = {};
    auto result = RootHeraldGetStatus(&status);
    out_result->is_enrolled = status.is_enrolled;
    out_result->has_tpm = status.has_tpm;
    CopyString(out_result->device_id, sizeof(out_result->device_id), status.device_id);
    CopyString(out_result->platform_name, sizeof(out_result->platform_name), status.platform);
    return MapRootHeraldStatus(result);
}

extern "C" _Use_decl_annotations_ ROOTHERALD_API RootHeraldStatus RootHeraldClient_CollectPosture(
    RootHeraldClient* client, RootHeraldPosture* out_result)
{
    if (client == nullptr || out_result == nullptr) return ROOTHERALD_ERR_INVALID_ARG;
    std::memset(out_result, 0, sizeof(*out_result));

    std::lock_guard<std::mutex> guard(client->lock);
    return MapRootHeraldStatus(RootHeraldCollectLocalPosture(out_result));
}

/* Handle-less by design: no key is consulted and no network call is made, so
 * there is nothing for a client object to carry. */
extern "C" _Use_decl_annotations_ ROOTHERALD_API RootHeraldStatus RootHeraldClient_CollectEvidence(
    const char* nonce_b64, char** out_evidence_json)
{
    if (out_evidence_json == nullptr) return ROOTHERALD_ERR_INVALID_ARG;
    *out_evidence_json = nullptr;
    if (nonce_b64 == nullptr || nonce_b64[0] == '\0') return ROOTHERALD_ERR_INVALID_ARG;

    return MapRootHeraldStatus(RootHeraldCollectEvidence(nonce_b64, out_evidence_json));
}

extern "C" _Use_decl_annotations_ ROOTHERALD_API void RootHeraldClient_FreeEvidence(char* evidence_json)
{
    RootHeraldFreeEvidence(evidence_json);
}

extern "C" ROOTHERALD_API const char* RootHerald_AbiVersionString(void)
{
    return ABI_VERSION;
}

extern "C" ROOTHERALD_API const char* RootHerald_LibraryVersionString(void)
{
    return LIBRARY_VERSION;
}
