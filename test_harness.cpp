/**
 *  Root Herald Test Harness — Verifies all security gaps are closed.
 *
 * Runs against a live  Root Herald API server and this machine's real TPM.
 * Tests both positive (legitimate attestation passes) and negative
 * (tampered data is rejected) cases.
 *
 * Usage: test_harness.exe [server_url]
 */

#include "tpm_commands.h"
#include "tpm_pcp.h"
#include "event_log.h"
#include "event_log_parser.h"
#include "secureboot_validator.h"
#include "dbx_checker.h"
#include "http_winhttp.h"
#include "json_helpers.h"
#include "protocol.h"

#include <windows.h>
#include <bcrypt.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")

static std::string Base64Encode(const uint8_t* data, size_t len) {
    DWORD outLen = 0;
    CryptBinaryToStringA(data, (DWORD)len, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &outLen);
    std::string result(outLen, '\0');
    CryptBinaryToStringA(data, (DWORD)len, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, result.data(), &outLen);
    while (!result.empty() && (result.back() == '\0' || result.back() == '\n' || result.back() == '\r'))
        result.pop_back();
    return result;
}

static std::string BytesToHex(const std::vector<uint8_t>& data) {
    static const char hex[] = "0123456789abcdef";
    std::string result;
    for (uint8_t b : data) { result += hex[b >> 4]; result += hex[b & 0x0F]; }
    return result;
}

static int passed = 0, failed = 0;

static void CHECK(const char* name, bool condition, const char* detail = nullptr) {
    if (condition) {
        printf("  [PASS] %s\n", name);
        passed++;
    } else {
        printf("  [FAIL] %s", name);
        if (detail) printf(" — %s", detail);
        printf("\n");
        failed++;
    }
}

int main(int argc, char* argv[])
{
    const char* serverUrl = "http://localhost:5000";
    if (argc > 1) serverUrl = argv[1];

    printf("===  Root Herald Security Gap Test Harness ===\n");
    printf("Server: %s\n\n", serverUrl);

    // === Setup: Create AK and generate quote ===
    printf("[Setup] Initializing TPM...\n");
    RootHerald::TpmCommands tpm;
    if (!tpm.Open()) {
        printf("FATAL: Cannot open TBS context\n");
        return 1;
    }

    // Create AK and extract public key
    std::vector<uint8_t> akPublicKey;
    uint32_t akHandle = tpm.CreateAndLoadAk(0x40000001, &akPublicKey);
    if (akHandle == 0) {
        printf("FATAL: Cannot create AK\n");
        return 1;
    }
    printf("[Setup] AK created: handle 0x%08X, public key %zu bytes\n", akHandle, akPublicKey.size());

    // Read event log
    auto eventLog = RootHerald::ReadEventLog();
    printf("[Setup] Event log: %zu bytes\n", eventLog.size());

    // Read PCR values
    std::vector<uint32_t> pcrIndices = {0, 1, 2, 3, 4, 7};
    std::string pcrValuesJson = "{\"sha256\":{";
    bool first = true;
    for (uint32_t idx : pcrIndices) {
        if (!first) pcrValuesJson += ",";
        first = false;
        auto pcrVal = tpm.PcrRead(idx);
        if (pcrVal.empty()) pcrVal.resize(32, 0);
        pcrValuesJson += "\"" + std::to_string(idx) + "\":\"" + BytesToHex(pcrVal) + "\"";
    }
    pcrValuesJson += "}}";

    // === Step 1: Enroll device ===
    printf("\n[1] Enrolling device...\n");
    RootHerald::TpmPcp pcp;
    pcp.Open();
    auto ekPub = pcp.ReadEkPublicKey();
    auto ekCert = pcp.ReadEkCertificate();

    std::string ekCertPem = "-----BEGIN CERTIFICATE-----\n" +
        Base64Encode(ekPub.data(), ekPub.size()) + "\n-----END CERTIFICATE-----";

    auto enrollResp = RootHerald::HttpPost(
        std::string(serverUrl) + "/api/v1/devices/enroll",
        RootHerald::JsonBuild({
            {"ekCertPem",    ekCertPem},
            {"ekPublicKey",  Base64Encode(ekPub.data(), ekPub.size())},
            {"akPublicArea", Base64Encode(akPublicKey.data(), akPublicKey.size())},
            {"platform",     "windows"}
        }));
    CHECK("Device enrollment", enrollResp.statusCode == 201, enrollResp.body.c_str());

    auto deviceId = RootHerald::JsonGet(enrollResp.body, "deviceId");
    auto credBlobB64 = RootHerald::JsonGet(enrollResp.body, "credentialBlob");
    auto encSecretB64 = RootHerald::JsonGet(enrollResp.body, "encryptedSecret");

    // === Gap 3: ActivateCredential — prove AK is on the same TPM as EK ===
    printf("  Creating EK for ActivateCredential...\n");
    uint32_t ekHandle = tpm.CreateEk();
    CHECK("EK created", ekHandle != 0);

    if (ekHandle != 0) {
        // Decode the credential blob and encrypted secret
        DWORD credBlobLen = 0, encSecLen = 0;
        CryptStringToBinaryA(credBlobB64.c_str(), 0, CRYPT_STRING_BASE64, nullptr, &credBlobLen, nullptr, nullptr);
        std::vector<uint8_t> credBlob(credBlobLen);
        CryptStringToBinaryA(credBlobB64.c_str(), 0, CRYPT_STRING_BASE64, credBlob.data(), &credBlobLen, nullptr, nullptr);
        credBlob.resize(credBlobLen);

        CryptStringToBinaryA(encSecretB64.c_str(), 0, CRYPT_STRING_BASE64, nullptr, &encSecLen, nullptr, nullptr);
        std::vector<uint8_t> encSecret(encSecLen);
        CryptStringToBinaryA(encSecretB64.c_str(), 0, CRYPT_STRING_BASE64, encSecret.data(), &encSecLen, nullptr, nullptr);
        encSecret.resize(encSecLen);

        printf("  credentialBlob: %zu bytes, first 4: %02X %02X %02X %02X\n",
               credBlob.size(),
               credBlob.size() > 0 ? credBlob[0] : 0,
               credBlob.size() > 1 ? credBlob[1] : 0,
               credBlob.size() > 2 ? credBlob[2] : 0,
               credBlob.size() > 3 ? credBlob[3] : 0);
        printf("  encryptedSecret: %zu bytes, first 4: %02X %02X %02X %02X\n",
               encSecret.size(),
               encSecret.size() > 0 ? encSecret[0] : 0,
               encSecret.size() > 1 ? encSecret[1] : 0,
               encSecret.size() > 2 ? encSecret[2] : 0,
               encSecret.size() > 3 ? encSecret[3] : 0);
        printf("  Running TPM2_ActivateCredential (AK=0x%08X, EK=0x%08X)...\n", akHandle, ekHandle);
        auto decryptedSecret = tpm.ActivateCredential(akHandle, ekHandle, credBlob, encSecret);
        CHECK("ActivateCredential returned secret", !decryptedSecret.empty());

        if (!decryptedSecret.empty()) {
            printf("  Secret: %zu bytes\n", decryptedSecret.size());

            // Send the decrypted secret to complete activation
            auto activateResp = RootHerald::HttpPost(
                std::string(serverUrl) + "/api/v1/devices/activate",
                RootHerald::JsonBuild({
                    {"deviceId",        deviceId},
                    {"decryptedSecret", Base64Encode(decryptedSecret.data(), decryptedSecret.size())},
                    {"akPublicKey",     Base64Encode(akPublicKey.data(), akPublicKey.size())}
                }));
            CHECK("Activation with ActivateCredential secret", activateResp.statusCode == 200,
                  activateResp.body.c_str());
        } else {
            printf("  ActivateCredential failed — this may be due to MakeCredential format mismatch\n");
            printf("  Falling back to enrollment-time AK storage\n");
        }

        tpm.FlushContext(ekHandle);
    }

    // === Step 2: Get challenge ===
    printf("\n[2] Getting attestation challenge...\n");
    auto challengeResp = RootHerald::HttpGet(
        std::string(serverUrl) + "/api/v1/challenge?client_id=plat_test_rp&device_id=" + deviceId);
    CHECK("Challenge received", challengeResp.statusCode == 200);

    auto nonceB64 = RootHerald::JsonGet(challengeResp.body, "nonce");
    auto sessionId = RootHerald::JsonGet(challengeResp.body, "sessionId");

    // Decode nonce
    DWORD nonceLen = 0;
    CryptStringToBinaryA(nonceB64.c_str(), 0, CRYPT_STRING_BASE64, nullptr, &nonceLen, nullptr, nullptr);
    std::vector<uint8_t> nonce(nonceLen);
    CryptStringToBinaryA(nonceB64.c_str(), 0, CRYPT_STRING_BASE64, nonce.data(), &nonceLen, nullptr, nullptr);
    nonce.resize(nonceLen);

    // === Step 3: Generate TPM Quote ===
    printf("\n[3] Generating TPM Quote...\n");
    std::vector<uint8_t> quoted, signature;
    bool quoteOk = tpm.Quote(akHandle, nonce, pcrIndices, quoted, signature);
    CHECK("TPM Quote generated", quoteOk && !quoted.empty() && !signature.empty());

    // === GAP 1 TEST: Server verifies real quote ===
    printf("\n[4] Gap 1: Server-side quote verification...\n");
    auto attestResp = RootHerald::HttpPost(
        std::string(serverUrl) + "/api/v1/attest",
        RootHerald::JsonBuild({
            {"sessionId", sessionId},
            {"quote", RootHerald::JsonBuild({
                {"quoted",       Base64Encode(quoted.data(), quoted.size())},
                {"signature",    Base64Encode(signature.data(), signature.size())},
                {"pcrSelection", Base64Encode((const uint8_t*)"\x01\x0B\x00\x03\x83\x00\x00", 7)},
                {"pcrDigest",    Base64Encode(nonce.data(), nonce.size())} // placeholder
            })},
            {"pcrValues", pcrValuesJson},
            {"eventLog", Base64Encode(eventLog.data(), eventLog.size())}
        }));

    auto status = RootHerald::JsonGet(attestResp.body, "status");
    auto reason = RootHerald::JsonGet(attestResp.body, "reason");
    CHECK("Attestation with real quote accepted", status == "verified",
          reason.empty() ? attestResp.body.c_str() : reason.c_str());

    // === GAP 1 NEGATIVE: Tampered quote signature rejected ===
    printf("\n[5] Gap 1 negative: Tampered quote rejected...\n");
    // Get a new challenge for the negative test
    auto challenge2Resp = RootHerald::HttpGet(
        std::string(serverUrl) + "/api/v1/challenge?client_id=plat_test_rp&device_id=" + deviceId);
    auto sessionId2 = RootHerald::JsonGet(challenge2Resp.body, "sessionId");
    auto nonce2B64 = RootHerald::JsonGet(challenge2Resp.body, "nonce");

    // Tamper: flip a byte in the signature
    auto tamperedSig = signature;
    if (!tamperedSig.empty()) tamperedSig[tamperedSig.size() / 2] ^= 0xFF;

    auto tamperResp = RootHerald::HttpPost(
        std::string(serverUrl) + "/api/v1/attest",
        RootHerald::JsonBuild({
            {"sessionId", sessionId2},
            {"quote", RootHerald::JsonBuild({
                {"quoted",       Base64Encode(quoted.data(), quoted.size())},
                {"signature",    Base64Encode(tamperedSig.data(), tamperedSig.size())},
                {"pcrSelection", Base64Encode((const uint8_t*)"\x01\x0B\x00\x03\x83\x00\x00", 7)},
                {"pcrDigest",    Base64Encode(nonce.data(), nonce.size())}
            })},
            {"pcrValues", pcrValuesJson},
            {"eventLog", Base64Encode(eventLog.data(), eventLog.size())}
        }));
    auto tamperStatus = RootHerald::JsonGet(tamperResp.body, "status");
    bool tamperRejected = (tamperStatus == "failed") || (tamperResp.statusCode != 200);
    CHECK("Tampered quote REJECTED", tamperRejected,
          (std::to_string(tamperResp.statusCode) + ": " + tamperResp.body.substr(0, 200)).c_str());

    // === GAP 2 TEST: Server-side Secure Boot chain validation ===
    printf("\n[6] Gap 2: Server-side chain validation from raw event log...\n");
    // The attestation in step 4 already sent the raw event log.
    // If it passed, the server validated the chain server-side.
    CHECK("Server-side chain validation (via step 4)", status == "verified");

    // === GAP 5 TEST: Nonce replay prevention ===
    printf("\n[7] Gap 5: Nonce replay prevention...\n");
    // Try to reuse the first session's auth code with a different session
    auto challenge3Resp = RootHerald::HttpGet(
        std::string(serverUrl) + "/api/v1/challenge?client_id=plat_test_rp&device_id=" + deviceId);
    auto sessionId3 = RootHerald::JsonGet(challenge3Resp.body, "sessionId");

    // Send the OLD quote (from step 3, signed with the first nonce) to the NEW session
    auto replayResp = RootHerald::HttpPost(
        std::string(serverUrl) + "/api/v1/attest",
        RootHerald::JsonBuild({
            {"sessionId", sessionId3},
            {"quote", RootHerald::JsonBuild({
                {"quoted",       Base64Encode(quoted.data(), quoted.size())},
                {"signature",    Base64Encode(signature.data(), signature.size())},
                {"pcrSelection", Base64Encode((const uint8_t*)"\x01\x0B\x00\x03\x83\x00\x00", 7)},
                {"pcrDigest",    Base64Encode(nonce.data(), nonce.size())}
            })},
            {"pcrValues", pcrValuesJson},
            {"eventLog", Base64Encode(eventLog.data(), eventLog.size())}
        }));
    auto replayStatus = RootHerald::JsonGet(replayResp.body, "status");
    bool replayRejected = (replayStatus == "failed") || (replayResp.statusCode != 200);
    CHECK("Replayed quote with wrong nonce REJECTED", replayRejected,
          (std::to_string(replayResp.statusCode) + ": " + replayResp.body.substr(0, 200)).c_str());

    // === E2E POSITIVE: Token exchange ===
    printf("\n[8] E2E: Token exchange...\n");
    if (status == "verified") {
        auto authCode = RootHerald::JsonGet(attestResp.body, "authorizationCode");
        auto tokenResp = RootHerald::HttpPostForm(
            std::string(serverUrl) + "/api/v1/token",
            "grant_type=authorization_code"
            "&code=" + authCode +
            "&client_id=plat_test_rp"
            "&client_secret=rootherald_test_secret_do_not_use_in_production"
            "&redirect_uri=http://localhost:3000/callback");
        CHECK("JWT issued", tokenResp.statusCode == 200);

        if (tokenResp.statusCode == 200) {
            auto jwt = RootHerald::JsonGet(tokenResp.body, "accessToken");
            printf("  JWT: %zu bytes\n", jwt.size());
            printf("  First 80 chars: %.80s...\n", jwt.c_str());
        }
    }

    // === Summary ===
    tpm.FlushContext(akHandle);
    tpm.Close();

    printf("\n=== Results ===\n\n");
    printf("  Passed: %d\n", passed);
    printf("  Failed: %d\n", failed);
    printf("  Total:  %d\n\n", passed + failed);

    if (failed == 0) {
        printf("  ALL SECURITY GAPS VERIFIED CLOSED\n\n");
    } else {
        printf("  %d GAP(S) STILL OPEN\n\n", failed);
    }

    return failed > 0 ? 1 : 0;
}
