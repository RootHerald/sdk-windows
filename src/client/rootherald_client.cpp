/*
 * The public C ABI declared in common/rootherald.h: argument validation and
 * per-client locking.
 *
 * ABI 5.0 removed the status-flattening that used to live here. The driver now
 * returns RootHeraldStatus directly, so these wrappers pass it through unchanged
 * rather than collapsing a second time — see client_internal.h for why.
 */

#include "rootherald.h"
#include "protocol.h"
#include "client_internal.h"

#include <sal.h>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <mutex>

namespace {

/* Derived from the header so the reported version cannot drift from the one
 * consumers compile against. */
#define RH_STR2(x) #x
#define RH_STR(x)  RH_STR2(x)
constexpr const char* ABI_VERSION =
    RH_STR(ROOTHERALD_ABI_VERSION_MAJOR) "." RH_STR(ROOTHERALD_ABI_VERSION_MINOR);
constexpr const char* LIBRARY_VERSION = "0.3.0";

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

extern "C" _Use_decl_annotations_ ROOTHERALD_API RootHeraldStatus RootHeraldClient_EnrollBegin(
    RootHeraldClient* client, char** out_request_json)
{
    if (out_request_json == nullptr) return ROOTHERALD_ERR_INVALID_ARG;
    *out_request_json = nullptr;
    if (client == nullptr) return ROOTHERALD_ERR_INVALID_ARG;

    std::lock_guard<std::mutex> guard(client->lock);
    return RootHeraldEnrollBegin(out_request_json);
}

extern "C" _Use_decl_annotations_ ROOTHERALD_API RootHeraldStatus RootHeraldClient_EnrollComplete(
    RootHeraldClient* client, const char* challenge_json, char** out_activation_json)
{
    if (out_activation_json == nullptr) return ROOTHERALD_ERR_INVALID_ARG;
    *out_activation_json = nullptr;
    if (client == nullptr || challenge_json == nullptr || challenge_json[0] == '\0')
        return ROOTHERALD_ERR_INVALID_ARG;

    std::lock_guard<std::mutex> guard(client->lock);
    return RootHeraldEnrollComplete(challenge_json, out_activation_json);
}

extern "C" _Use_decl_annotations_ ROOTHERALD_API RootHeraldStatus RootHeraldClient_CollectPosture(
    RootHeraldClient* client, RootHeraldPosture* out_result)
{
    if (client == nullptr || out_result == nullptr) return ROOTHERALD_ERR_INVALID_ARG;
    std::memset(out_result, 0, sizeof(*out_result));

    std::lock_guard<std::mutex> guard(client->lock);
    return RootHeraldCollectLocalPosture(out_result);
}

/* Handle-less by design: no key is consulted and no network call is made, so
 * there is nothing for a client object to carry. */
extern "C" _Use_decl_annotations_ ROOTHERALD_API RootHeraldStatus RootHeraldClient_CollectEvidence(
    const char* nonce_b64, char** out_evidence_json)
{
    if (out_evidence_json == nullptr) return ROOTHERALD_ERR_INVALID_ARG;
    *out_evidence_json = nullptr;
    if (nonce_b64 == nullptr || nonce_b64[0] == '\0') return ROOTHERALD_ERR_INVALID_ARG;

    return RootHeraldCollectEvidence(nonce_b64, out_evidence_json);
}

extern "C" _Use_decl_annotations_ ROOTHERALD_API void RootHeraldClient_FreeEvidence(char* evidence_json)
{
    RootHeraldFreeEvidence(evidence_json);
}

/*
 * A convenience for a printf during integration and for a CI harness's failure
 * output — deliberately NOT the documentation. Each string says what happened
 * and, where it differs from the obvious, what to do about it; the full
 * cause-and-remedy reference is on the developer portal, keyed by the symbol
 * rather than by the number.
 */
extern "C" ROOTHERALD_API const char* RootHerald_ErrorString(RootHeraldStatus status)
{
    switch (status) {
        case ROOTHERALD_OK:
            return "ok";
        case ROOTHERALD_ERR_INVALID_ARG:
            return "invalid argument";
        case ROOTHERALD_ERR_TPM_UNAVAILABLE:
            return "no TPM 2.0 or secure enclave is reachable on this host";
        case ROOTHERALD_ERR_NOT_ENROLLED:
            return "device is not enrolled";
        case ROOTHERALD_ERR_ELEVATION_REQUIRED:
            return "enrollment requires an elevated process; run EnrollBegin/EnrollComplete in an elevated resident worker (the single elevation spans both), then retry";
        case ROOTHERALD_ERR_EK_READ_FAILED:
            return "a TPM is present but its endorsement key could not be read; check the resource manager, device permissions and driver";
        case ROOTHERALD_ERR_AK_FAILED:
            return "the attestation key could not be created, loaded or persisted; retry enrollment";
        case ROOTHERALD_ERR_ACTIVATION_FAILED:
            return "the enrollment challenge could not be consumed; it is single-use and now spent, so restart from EnrollBegin";
        case ROOTHERALD_ERR_QUOTE_FAILED:
            return "reading PCRs or producing the quote failed; retry the attestation, do not re-enroll";
        case ROOTHERALD_ERR_ENTITLEMENT_MISSING:
            return "the host executable is not signed with a provisioning profile granting data-protection keychain access";
        case ROOTHERALD_ERR_INTERNAL:
            return "internal library error";
        default:
            return "unknown error";
    }
}

extern "C" ROOTHERALD_API const char* RootHerald_AbiVersionString(void)
{
    return ABI_VERSION;
}

extern "C" ROOTHERALD_API const char* RootHerald_LibraryVersionString(void)
{
    return LIBRARY_VERSION;
}
