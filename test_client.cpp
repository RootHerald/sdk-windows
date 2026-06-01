/**
 *  Root Herald Test Client — Exercises the full attestation flow against a real TPM.
 *
 * Usage: test_client.exe [server_url]
 * Default server URL: http://localhost:5000
 */

#include "rootherald_win.h"
#include "http_winhttp.h"
#include "json_helpers.h"

#include <cstdio>
#include <cstring>
#include <string>

int main(int argc, char* argv[])
{
    // Elevated-child entry: `test_client.exe --establish-key <url> <resultpath>`.
    // RootHeraldEnroll spawns this elevated when PCP activation is unavailable;
    // it runs the raw-TBS enroll+activate and writes the deviceId to resultpath.
    if (argc >= 4 && strcmp(argv[1], "--establish-key") == 0) {
        return RootHeraldRunElevatedEstablishKey(argv[2], argv[3]);
    }

    const char* serverUrl = "http://localhost:5000";
    const char* jwtOutPath = nullptr;
    bool forceReenroll = false;
    for (int i = 1; i < argc; ++i) {
        if (strncmp(argv[i], "--jwt-out=", 10) == 0) {
            jwtOutPath = argv[i] + 10;
        } else if (strcmp(argv[i], "--force-reenroll") == 0) {
            // Diagnostic flag — re-creates the persistent AK, which on Windows
            // requires raw TBS commands and therefore a UAC elevation prompt.
            // Don't pass this in the steady-state real-host driver.
            forceReenroll = true;
        } else if (argv[i][0] != '-') {
            serverUrl = argv[i];
        }
    }

    printf("===  Root Herald Test Client ===\n");
    printf("Server: %s\n\n", serverUrl);

    // Step 1: Check device status
    printf("[1/5] Checking device status...\n");
    RootHeraldDeviceStatus status = {};
    auto result = RootHeraldGetStatus(&status);
    printf("  Platform: %s\n", status.platform);
    printf("  TPM available: %s\n", status.has_tpm ? "yes" : "no");
    printf("  Enrolled: %s\n", status.is_enrolled ? "yes" : "no");

    if (!status.has_tpm) {
        printf("\nERROR: No TPM available on this machine.\n");
        return 1;
    }

    // Step 2: Enroll device (only if not already enrolled, unless --force-reenroll)
    printf("\n[2/5] Enrolling device...\n");
    RootHeraldEnrollmentInfo enrollInfo = {};
    std::string deviceIdForChallenge;
    if (status.is_enrolled && !forceReenroll) {
        // Reuse the cached AK + deviceId from previous enrollment. This avoids
        // the UAC elevation prompt the raw-TBS re-enroll path would trigger.
        // Status reported it as already enrolled — trust it.
        deviceIdForChallenge = status.device_id;
        printf("  Device ID: %s (reusing cached enrollment)\n", deviceIdForChallenge.c_str());
        printf("  Enrollment: skipped (already enrolled; pass --force-reenroll to re-create)\n");
    } else {
        result = RootHeraldEnroll(serverUrl, forceReenroll ? 1 : 0, &enrollInfo);
        if (result != RH_PROTO_OK) {
            printf("  ERROR: Enrollment failed (code %d)\n", result);
            return 1;
        }
        deviceIdForChallenge = enrollInfo.device_id;
        printf("  Device ID: %s\n", deviceIdForChallenge.c_str());
        printf("  Enrollment: OK\n");
    }

    // Step 3: Request challenge
    printf("\n[3/5] Requesting attestation challenge...\n");
    // Use the seeded test RP
    std::string challengeUrl = std::string(serverUrl) +
        "/api/v1/challenge?client_id=plat_test_rp&device_id=" + deviceIdForChallenge;
    auto challengeResp = RootHerald::HttpGet(challengeUrl);
    if (challengeResp.statusCode != 200) {
        printf("  ERROR: Challenge request failed (%d): %s\n",
               challengeResp.statusCode, challengeResp.body.c_str());
        return 1;
    }

    auto nonce = RootHerald::JsonGet(challengeResp.body, "nonce");
    auto sessionId = RootHerald::JsonGet(challengeResp.body, "sessionId");
    printf("  Session ID: %s\n", sessionId.c_str());
    printf("  Nonce: %s\n", nonce.c_str());

    // Step 4: Perform attestation
    printf("\n[4/5] Performing attestation...\n");
    // When we skipped enrollment above, the SDK's internal deviceId state is
    // empty. Set it explicitly so /api/v1/attest can resolve the session to
    // the right device. (See protocol.h: RootHeraldSetDeviceId.)
    RootHeraldSetDeviceId(deviceIdForChallenge.c_str());
    RootHeraldAttestationInfo attestInfo = {};
    result = RootHeraldAttest(serverUrl, sessionId.c_str(), nonce.c_str(), nonce.size(), &attestInfo);
    printf("  Status: %s\n", attestInfo.status);
    if (result == RH_PROTO_OK) {
        printf("  Authorization code: %s\n", attestInfo.authorization_code);
    } else {
        printf("  Failure reason: %s\n", attestInfo.failure_reason);
    }

    // Step 5: Exchange token (if attestation succeeded)
    if (result == RH_PROTO_OK && strlen(attestInfo.authorization_code) > 0) {
        printf("\n[5/5] Exchanging authorization code for JWT...\n");
        std::string tokenUrl = std::string(serverUrl) + "/api/v1/token";
        std::string tokenBody =
            "grant_type=authorization_code"
            "&code=" + std::string(attestInfo.authorization_code) +
            "&client_id=plat_test_rp"
            "&client_secret=rootherald_test_secret_do_not_use_in_production"
            "&redirect_uri=http://localhost:3000/callback";

        // Use form-encoded POST
        auto tokenResp = RootHerald::HttpPostForm(tokenUrl, tokenBody);
        if (tokenResp.statusCode == 200) {
            // Token endpoint emits snake_case per OAuth 2.0 (RFC 6749 §4.1.4).
            // TokenResponse DTO uses [JsonPropertyName("access_token")].
            auto jwt = RootHerald::JsonGet(tokenResp.body, "access_token");
            printf("  JWT received (%zu bytes)\n", jwt.size());
            printf("  Token: %.80s...\n", jwt.c_str());
            // Optional machine-readable JWT output for test drivers. Writes the
            // full JWT to the path supplied via --jwt-out=<path>. Used by
            // tests/real-host/topology-b-windows.ps1.
            if (jwtOutPath && !jwt.empty()) {
                FILE* f = nullptr;
                if (fopen_s(&f, jwtOutPath, "wb") == 0 && f) {
                    fwrite(jwt.data(), 1, jwt.size(), f);
                    fclose(f);
                    printf("  Wrote full JWT to %s\n", jwtOutPath);
                } else {
                    fprintf(stderr, "Failed to open --jwt-out path: %s (errno=%d)\n",
                            jwtOutPath, errno);
                }
            }
        } else {
            printf("  Token exchange failed (%d): %s\n",
                   tokenResp.statusCode, tokenResp.body.c_str());
        }
    } else {
        printf("\n[5/5] Skipping token exchange (attestation did not succeed).\n");
    }

    printf("\n=== Done ===\n");
    return (result == RH_PROTO_OK) ? 0 : 1;
}
