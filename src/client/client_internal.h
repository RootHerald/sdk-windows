/*
 * Private RootHeraldClient state and the Windows-internal entry points shared
 * between the ABI facade (rootherald_client.cpp) and the driver
 * (rootherald_win.cpp). Not installed and not part of the public surface.
 *
 * ABI 5.0 removed the RootHeraldResult / RH_PROTO_* vocabulary that used to sit
 * here. It existed so the driver could speak its own error language and the
 * facade could translate exactly once, but the translation was lossy in both
 * directions: the driver had already collapsed an HRESULT into a coarse
 * RH_PROTO_ERR_*, and the facade then collapsed that again into a public status.
 * Nine distinct TPM failures arrived at the caller as "internal library error",
 * and local enrollment and quote faults both arrived as "the server returned an
 * error". The driver now returns RootHeraldStatus directly, so a failure is
 * named once at the point it happens and reaches the caller intact.
 *
 * (The old comment here claimed the native messaging host called these across
 * the C boundary. It does not — windows-host links only the public ABI.)
 */

#ifndef ROOTHERALD_CLIENT_INTERNAL_H
#define ROOTHERALD_CLIENT_INTERNAL_H

#include <sal.h>
#include <mutex>

#include "protocol.h"
#include "rootherald.h"

extern "C" {

/* out_*_json buffers are caller-owned: free with RootHeraldFreeEvidence. Each is
 * set on success and left null otherwise, which is what lets the public wrappers
 * carry the stronger _Outptr_result_z_ contract. */
_Success_(return == ROOTHERALD_OK)
ROOTHERALD_API RootHeraldStatus RootHeraldEnrollBegin(
    _Outptr_result_z_ char** out_enroll_json);
_Success_(return == ROOTHERALD_OK)
ROOTHERALD_API RootHeraldStatus RootHeraldEnrollComplete(
    _In_z_ const char* challenge_json,
    _Outptr_result_z_ char** out_activate_json);
_Success_(return == ROOTHERALD_OK)
ROOTHERALD_API RootHeraldStatus RootHeraldCollectEvidence(
    _In_z_ const char* nonce_b64,
    _Outptr_result_z_ char** out_evidence_json);
ROOTHERALD_API RootHeraldStatus RootHeraldCollectLocalPosture(_Out_ RootHeraldPosture* out_posture);
ROOTHERALD_API void RootHeraldFreeEvidence(_In_opt_ char* evidence_json);

} /* extern "C" */

/* The opaque handle the public ABI hands out. Carries only the lock: 5.0 removed
 * SetApplicationId, whose string was the sole other member and was never read by
 * anything on either side of the wire. */
struct RootHeraldClient {
    std::mutex lock;
};

#endif /* ROOTHERALD_CLIENT_INTERNAL_H */
