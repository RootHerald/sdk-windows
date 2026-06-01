/**
 * Boot Verification Tool — Reads this machine's TCG event log,
 * parses every measurement, and produces a boot integrity verdict.
 *
 * Usage: boot_verify.exe
 */

#include "event_log_parser.h"
#include "dbx_checker.h"
#include "tpm_commands.h"
#include "secureboot_validator.h"

#include <windows.h>
#include <tbs.h>
#include <cstdio>
#include <string>
#include <vector>

#pragma comment(lib, "tbs.lib")

static std::vector<uint8_t> ReadEventLogDirect() {
    UINT32 logSize = 0;
    TBS_RESULT result = Tbsi_Get_TCG_Log_Ex(TBS_TCGLOG_SRTM_CURRENT, nullptr, &logSize);
    if (result != TBS_SUCCESS || logSize == 0) return {};
    std::vector<uint8_t> log(logSize);
    result = Tbsi_Get_TCG_Log_Ex(TBS_TCGLOG_SRTM_CURRENT, log.data(), &logSize);
    if (result != TBS_SUCCESS) return {};
    log.resize(logSize);
    return log;
}

static std::string BytesToHex(const uint8_t* data, size_t len) {
    static const char hex[] = "0123456789abcdef";
    std::string result;
    result.reserve(len * 2);
    for (size_t i = 0; i < len; i++) {
        result += hex[data[i] >> 4];
        result += hex[data[i] & 0x0F];
    }
    return result;
}

int main()
{
    printf("===  Root Herald Boot Verification ===\n\n");

    // Read the event log
    auto rawLog = ReadEventLogDirect();
    if (rawLog.empty()) {
        printf("ERROR: Failed to read TCG event log\n");
        return 1;
    }
    printf("Event log: %zu bytes\n", rawLog.size());

    // Load UEFI DBX revocation list
    RootHerald::DbxChecker dbx;
    int dbxCount = dbx.LoadFromJson("infra/trust-store/dbx_latest.json");
    if (dbxCount < 0) {
        // Try relative to executable directory
        dbxCount = dbx.LoadFromJson("dbx_latest.json");
    }
    if (dbxCount > 0) {
        printf("UEFI DBX: %d revoked hashes loaded\n", dbxCount);
    } else {
        printf("UEFI DBX: not loaded (place dbx_latest.json in working directory)\n");
    }
    printf("\n");

    // Parse and analyze
    auto analysis = RootHerald::ParseAndAnalyzeEventLog(rawLog);

    // Cross-reference boot measurements against DBX
    if (dbxCount > 0) {
        for (auto& entry : analysis.entries) {
            auto it = entry.digests.find(0x000B); // SHA-256
            if (it != entry.digests.end()) {
                if (dbx.IsRevoked(it->second)) {
                    entry.classification = "REVOKED";
                    entry.description += " *** REVOKED BY UEFI DBX ***";
                    analysis.revokedCount++;
                    // Downgrade from whatever it was
                    if (entry.classification == "verified") analysis.verifiedCount--;
                }
            }
        }

        // Recalculate verdict if DBX matches found
        if (analysis.revokedCount > 0) {
            analysis.verdict = "FAIL";
            analysis.verdictReason = std::to_string(analysis.revokedCount) +
                " component(s) found on UEFI revocation list (DBX) — possible bootkit or vulnerable shim";
        }
    }

    // === Secure Boot Certificate Chain Validation ===
    auto chainReport = RootHerald::ValidateSecureBootChain(rawLog);

    printf("=== Secure Boot Certificate Chain ===\n\n");
    printf("Secure Boot: %s\n", chainReport.secureBootEnabled ? "ENABLED" : "DISABLED");
    printf("\nPlatform Key (PK):\n");
    for (const auto& c : chainReport.pkCerts) {
        printf("  Subject: %s\n", c.subject.c_str());
        printf("  Issuer:  %s\n", c.issuer.c_str());
        printf("  SHA-256: %s\n", c.thumbprintSha256.c_str());
        printf("  Known OEM: %s%s\n", c.isKnownOem ? "YES" : "NO",
               c.isKnownOem ? (" (" + c.oemName + ")").c_str() : "");
    }

    printf("\nKey Exchange Key (KEK):\n");
    for (const auto& c : chainReport.kekCerts) {
        printf("  Subject: %s\n", c.subject.c_str());
        printf("  Microsoft: %s\n", c.isMicrosoftCert ? "YES" : "no");
        printf("  SHA-256: %s\n", c.thumbprintSha256.c_str());
    }

    printf("\nAllowed Signatures Database (db):\n");
    for (const auto& c : chainReport.dbCerts) {
        printf("  Subject: %s\n", c.subject.c_str());
        printf("  Microsoft: %s\n", c.isMicrosoftCert ? "YES" : "no");
        printf("  SHA-256: %s\n", c.thumbprintSha256.c_str());
    }

    printf("\nMicrosoft UEFI CA 2011 in db: %s\n", chainReport.dbHasMicrosoftUefiCa2011 ? "YES" : "NO");
    printf("Microsoft UEFI CA 2023 in db: %s\n", chainReport.dbHasMicrosoftUefiCa2023 ? "YES" : "NO");
    printf("Microsoft Windows PCA 2011 in db: %s\n", chainReport.dbHasWindowsPca2011 ? "YES" : "NO");
    printf("Microsoft KEK in KEK: %s\n", chainReport.kekHasMicrosoft ? "YES" : "NO");
    printf("PK from known OEM: %s\n", chainReport.pkIsKnownOem ? ("YES (" + chainReport.pkOemName + ")").c_str() : "NO");

    printf("\nChain verdict: %s\n", chainReport.verdict.c_str());
    for (const auto& w : chainReport.warnings)
        printf("  WARNING: %s\n", w.c_str());
    for (const auto& e : chainReport.errors)
        printf("  ERROR: %s\n", e.c_str());

    printf("\n=== Measurement Analysis ===\n\n");
    printf("Total measurements: %zu\n", analysis.entries.size());
    printf("  Verified:  %d\n", analysis.verifiedCount);
    printf("  Policy:    %d\n", analysis.policyCount);
    printf("  Unknown:   %d\n", analysis.unknownCount);
    printf("  Revoked:   %d\n", analysis.revokedCount);
    printf("\n");

    // Print each entry
    printf("=== Measurement Log ===\n\n");
    for (size_t i = 0; i < analysis.entries.size(); i++) {
        const auto& e = analysis.entries[i];

        // Get SHA-256 digest if available
        std::string digestHex = "(no SHA-256)";
        auto it = e.digests.find(0x000B); // SHA-256
        if (it != e.digests.end()) {
            digestHex = BytesToHex(it->second.data(), it->second.size());
        }

        const char* classIcon = "?";
        if (e.classification == "verified") classIcon = "+";
        else if (e.classification == "policy") classIcon = "~";
        else if (e.classification == "revoked") classIcon = "!";
        else if (e.classification == "unknown") classIcon = "?";

        printf("[%s] PCR[%2u] %-40s %s\n",
               classIcon, e.pcrIndex, e.eventTypeName.c_str(), e.description.c_str());
        printf("         SHA256: %.64s\n", digestHex.c_str());
    }

    // Verdict
    printf("\n=== VERDICT ===\n\n");
    printf("  %s: %s\n\n", analysis.verdict.c_str(), analysis.verdictReason.c_str());

    // === Generate Real TPM Quote ===
    printf("=== TPM Quote Generation ===\n\n");

    RootHerald::TpmCommands tpm;
    if (!tpm.Open()) {
        printf("  ERROR: Could not open TBS context\n");
        return 1;
    }

    // Create a restricted signing key (AK) for the quote
    printf("  Creating Attestation Key...\n");
    uint32_t akHandle = tpm.CreateAndLoadAk(0x40000001);
    if (akHandle == 0) {
        printf("  ERROR: Failed to create AK (TPM2_CreatePrimary failed)\n");
        tpm.Close();
        return 1;
    }
    printf("  AK handle: 0x%08X\n", akHandle);

    // Generate a nonce (in production this comes from the server)
    uint8_t nonce[32];
    for (int i = 0; i < 32; i++) nonce[i] = (uint8_t)(i + 1); // Simple test nonce
    std::vector<uint8_t> nonceVec(nonce, nonce + 32);

    // Quote PCRs 0, 1, 2, 3, 4, 7
    std::vector<uint32_t> pcrIndices = {0, 1, 2, 3, 4, 7};
    std::vector<uint8_t> quoted, signature;

    printf("  Generating TPM2_Quote for PCRs {0,1,2,3,4,7}...\n");
    bool quoteOk = tpm.Quote(akHandle, nonceVec, pcrIndices, quoted, signature);

    if (quoteOk && !quoted.empty() && !signature.empty()) {
        printf("  Quote:     %zu bytes (TPMS_ATTEST)\n", quoted.size());
        printf("  Signature: %zu bytes (TPMT_SIGNATURE)\n", signature.size());
        size_t showLen = quoted.size() < 32 ? quoted.size() : 32;
        printf("  Quote first 32 bytes: %s\n", BytesToHex(quoted.data(), showLen).c_str());
        printf("\n  *** REAL TPM QUOTE GENERATED SUCCESSFULLY ***\n");
    } else {
        printf("  ERROR: TPM2_Quote failed\n");
    }

    // Cleanup
    tpm.FlushContext(akHandle);
    tpm.Close();

    printf("\n");
    return (analysis.verdict == "PASS") ? 0 : (analysis.verdict == "WARNING") ? 0 : 1;
}
