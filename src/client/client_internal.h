/**
 * Private RootHeraldClient state and the Windows-internal entry points, shared
 * between the ABI facade (rootherald_client.cpp) and the keyless driver
 * (rootherald_win.cpp). Not installed; never part of the public surface.
 *
 * RootHeraldDeviceStatus / RootHeraldGetStatus / RootHeraldSetDeviceId were
 * demoted here from protocol.h in ABI 4.0: the native messaging host still
 * calls them across the C boundary, but they are not something a customer
 * integrates against.
 */

#ifndef ROOTHERALD_CLIENT_INTERNAL_H
#define ROOTHERALD_CLIENT_INTERNAL_H

#include <mutex>
#include <string>

#include "protocol.h"
#include "rootherald.h"

extern "C" {

/* Internal result codes. The public surface is RootHeraldStatus in rootherald.h;
 * these are the platform implementations' own vocabulary, mapped at the boundary. */
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
     * TPM2_ActivateCredential. The SDK does not elevate; run the keyless
     * EnrollBegin/EnrollComplete pair in an elevated resident worker. */
    RH_PROTO_ERR_ELEVATION_REQUIRED = 9
} RootHeraldResult;


/* Device status, as reported by RootHeraldGetStatus. */
typedef struct {
    int is_enrolled;
    char device_id[64];
    char platform[16];         /* always "windows" here */
    int has_tpm;
} RootHeraldDeviceStatus;

/* Local enrollment / TPM status. No network. */
ROOTHERALD_API RootHeraldResult RootHeraldGetStatus(RootHeraldDeviceStatus* out_status);

/*
 * Bind a caller-supplied device ID into collected evidence. When left unset
 * (or cleared with NULL) CollectEvidence derives the deviceId from the EK.
 * Host hook; no network.
 */
ROOTHERALD_API void RootHeraldSetDeviceId(const char* device_id);

/* Keyless enrollment, evidence collection and posture — implemented in
 * rootherald_win.cpp, mapped onto the public ABI by rootherald_client.cpp. */
ROOTHERALD_API RootHeraldResult RootHeraldEnrollBegin(char** out_enroll_json);
ROOTHERALD_API RootHeraldResult RootHeraldEnrollComplete(const char* challenge_json,
                                                         char** out_activate_json);
ROOTHERALD_API RootHeraldResult RootHeraldCollectEvidence(const char* nonce_b64,
                                                          char** out_evidence_json);
ROOTHERALD_API RootHeraldResult RootHeraldCollectLocalPosture(RootHeraldPosture* out_posture);
ROOTHERALD_API void RootHeraldFreeEvidence(char* evidence_json);

} /* extern "C" */

/* The opaque handle the public ABI hands out. */
struct RootHeraldClient {
    std::string applicationId;
    std::mutex lock;
};

#endif /* ROOTHERALD_CLIENT_INTERNAL_H */
