/**
 * gate_collect — UNPRIVILEGED collect-only gate driver.
 *
 * Takes a server-issued challenge nonce (base64) on argv[1], runs the SDK's
 * Background-Check evidence collector (TPM2_Quote over the nonce against the
 * enrolled persistent-handle AK + PCRs + event log + EK chain + secure-boot
 * chain), and prints the self-contained evidence JSON to stdout. A PowerShell
 * harness relays that to POST /api/v1/attestations/verify and asserts the
 * server's quote/PCR-event-log-replay verdict.
 *
 * Deliberately unprivileged: proves an ordinary-user process can produce a
 * verifiable quote against an AK that was enrolled once under elevation.
 *
 *   gate_collect.exe <nonce_b64>
 */
#include "rootherald_win.h"  // RootHeraldResult, RH_PROTO_OK
#include <cstdio>

// Exported from RootHerald.lib but not header-declared (collect-only ABI).
extern "C" RootHeraldResult RootHeraldCollectEvidence(const char* nonce_b64, char** out_evidence_json);
extern "C" void RootHeraldFreeEvidence(char* evidence_json);

int main(int argc, char** argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: gate_collect <nonce_b64>\n");
        return 2;
    }
    char* evidence = nullptr;
    RootHeraldResult r = RootHeraldCollectEvidence(argv[1], &evidence);
    if (r != RH_PROTO_OK || evidence == nullptr) {
        fprintf(stderr, "collect failed: %d\n", (int)r);
        return 1;
    }
    fputs(evidence, stdout);
    RootHeraldFreeEvidence(evidence);
    return 0;
}
