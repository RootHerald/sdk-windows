/**
 * Root Herald Test Client — exercises the KEYLESS client verbs against a real TPM.
 *
 * ABI 3.0: the client opens no socket to RootHerald and holds no key. This tool
 * therefore drives only the local, blob-emitting verbs and prints the blobs to
 * stdout; relaying them to RootHerald (POST /devices/enroll, /devices/activate,
 * /attestations/verify) is the customer BACKEND's job and is exercised by the
 * /try e2e gate (WP7), not here.
 *
 * Usage:
 *   test_client.exe                       # device status (RootHeraldGetStatus)
 *   test_client.exe --enroll-begin        # emit the /devices/enroll request blob
 *                                         #   (requires elevation; keeps the AK
 *                                         #    context resident — pair with
 *                                         #    --enroll-complete IN THE SAME RUN)
 *   test_client.exe --enroll-complete <challenge.json>
 *                                         # ActivateCredential over a relayed
 *                                         #   challenge -> /devices/activate blob
 *   test_client.exe --collect <nonce_b64> # emit the evidence blob for /verify
 *
 * --enroll-begin and --enroll-complete must run in the SAME process (the single
 * elevation spans both: the transient EK+AK context lives only in this process).
 */

#include "rootherald_win.h"   // RootHeraldResult, RH_PROTO_OK, RootHeraldGetStatus
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

// Keyless enroll halves + evidence collector — exported from RootHerald.lib but
// not part of the public <rootherald.h> handle ABI (the host calls the handle
// facade; this diagnostic uses the internal globals directly).
extern "C" RootHeraldResult RootHeraldEnrollBegin(char** out_enroll_json);
extern "C" RootHeraldResult RootHeraldEnrollComplete(const char* challenge_json,
                                                     char** out_activate_json);
extern "C" RootHeraldResult RootHeraldCollectEvidence(const char* nonce_b64,
                                                      char** out_evidence_json);
extern "C" void RootHeraldFreeEvidence(char* json);

static int PrintStatus()
{
    RootHeraldDeviceStatus status = {};
    RootHeraldResult r = RootHeraldGetStatus(&status);
    printf("=== Root Herald Test Client (keyless) ===\n");
    printf("  Platform:      %s\n", status.platform);
    printf("  TPM available: %s\n", status.has_tpm ? "yes" : "no");
    printf("  Enrolled:      %s\n", status.is_enrolled ? "yes" : "no");
    printf("  Device ID:     %s\n", status.device_id);
    return (r == RH_PROTO_OK) ? 0 : 1;
}

static int EmitAndFree(const char* label, RootHeraldResult r, char* blob)
{
    if (r != RH_PROTO_OK || blob == nullptr) {
        fprintf(stderr, "%s failed: %d\n", label, (int)r);
        if (blob) RootHeraldFreeEvidence(blob);
        return 1;
    }
    fputs(blob, stdout);
    fputc('\n', stdout);
    RootHeraldFreeEvidence(blob);
    return 0;
}

static std::string ReadFile(const char* path)
{
    FILE* f = nullptr;
    if (fopen_s(&f, path, "rb") != 0 || !f) return std::string();
    std::string out;
    char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) out.append(buf, n);
    fclose(f);
    return out;
}

int main(int argc, char* argv[])
{
    if (argc < 2) {
        return PrintStatus();
    }

    if (strcmp(argv[1], "--enroll-begin") == 0) {
        char* blob = nullptr;
        return EmitAndFree("EnrollBegin", RootHeraldEnrollBegin(&blob), blob);
    }

    if (strcmp(argv[1], "--enroll-complete") == 0) {
        if (argc < 3) { fprintf(stderr, "usage: --enroll-complete <challenge.json>\n"); return 2; }
        std::string challenge = ReadFile(argv[2]);
        if (challenge.empty()) { fprintf(stderr, "could not read challenge: %s\n", argv[2]); return 2; }
        char* blob = nullptr;
        return EmitAndFree("EnrollComplete",
                           RootHeraldEnrollComplete(challenge.c_str(), &blob), blob);
    }

    if (strcmp(argv[1], "--collect") == 0) {
        if (argc < 3) { fprintf(stderr, "usage: --collect <nonce_b64>\n"); return 2; }
        char* blob = nullptr;
        return EmitAndFree("CollectEvidence",
                           RootHeraldCollectEvidence(argv[2], &blob), blob);
    }

    fprintf(stderr, "unknown argument: %s\n", argv[1]);
    return 2;
}
