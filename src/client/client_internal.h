/*
 * Private RootHeraldClient state and the Windows-internal C entry points
 * shared between the ABI facade (rootherald_client.cpp) and the driver
 * (rootherald_win.cpp). Not installed and not part of the public surface.
 *
 * The native messaging host calls these across the C boundary, but they are
 * not something a customer integrates against.
 */

#ifndef ROOTHERALD_CLIENT_INTERNAL_H
#define ROOTHERALD_CLIENT_INTERNAL_H

#include <sal.h>
#include <mutex>
#include <string>

#include "protocol.h"
#include "rootherald.h"

extern "C" {

/* The platform implementations' own vocabulary. rootherald_client.cpp maps it
 * onto the public RootHeraldStatus exactly once. */
typedef enum {
    RH_PROTO_OK = 0,
    RH_PROTO_ERR_NO_TPM = 1,
    RH_PROTO_ERR_ENROLLMENT_FAILED = 2,
    RH_PROTO_ERR_ATTESTATION_FAILED = 3,
    RH_PROTO_ERR_NETWORK = 4,
    RH_PROTO_ERR_INTERNAL = 5,
    RH_PROTO_ERR_NOT_ENROLLED = 6,
    RH_PROTO_ERR_INVALID_PARAM = 7,
    RH_PROTO_ERR_ALREADY_ENROLLED = 8,
    /* Cold enrollment needs an elevated process for raw-TBS AK creation and
     * TPM2_ActivateCredential. The SDK never elevates on the caller's behalf. */
    RH_PROTO_ERR_ELEVATION_REQUIRED = 9
} RootHeraldResult;

typedef struct {
    int is_enrolled;
    char device_id[64];
    char platform[16];         /* always "windows" here */
    int has_tpm;
} RootHeraldDeviceStatus;

ROOTHERALD_API RootHeraldResult RootHeraldGetStatus(_Out_ RootHeraldDeviceStatus* out_status);

/* Binds a caller-supplied device id into collected evidence. NULL clears it,
 * and CollectEvidence then derives the id from the EK. */
ROOTHERALD_API void RootHeraldSetDeviceId(_In_opt_z_ const char* device_id);

/* out_*_json buffers are caller-owned: free with RootHeraldFreeEvidence. Each is
 * set on success and left null otherwise, which is what lets the public wrappers
 * carry the stronger _Outptr_result_z_ contract. */
_Success_(return == RH_PROTO_OK)
ROOTHERALD_API RootHeraldResult RootHeraldEnrollBegin(
    _Outptr_result_z_ char** out_enroll_json);
_Success_(return == RH_PROTO_OK)
ROOTHERALD_API RootHeraldResult RootHeraldEnrollComplete(
    _In_z_ const char* challenge_json,
    _Outptr_result_z_ char** out_activate_json);
_Success_(return == RH_PROTO_OK)
ROOTHERALD_API RootHeraldResult RootHeraldCollectEvidence(
    _In_z_ const char* nonce_b64,
    _Outptr_result_z_ char** out_evidence_json);
ROOTHERALD_API RootHeraldResult RootHeraldCollectLocalPosture(_Out_ RootHeraldPosture* out_posture);
ROOTHERALD_API void RootHeraldFreeEvidence(_In_opt_ char* evidence_json);

} /* extern "C" */

/* The opaque handle the public ABI hands out. */
struct RootHeraldClient {
    std::string applicationId;
    std::mutex lock;
};

#endif /* ROOTHERALD_CLIENT_INTERNAL_H */
