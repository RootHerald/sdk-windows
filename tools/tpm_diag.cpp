/**
 * TPM Diagnostic — Tests each TPM operation individually.
 * Build: add to CMakeLists or compile standalone.
 */

#include "win_cert_store_intermediates.h"

#include <windows.h>
#include <ncrypt.h>
#include <tbs.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <cstdio>
#include <cstdint>
#include <string>
#include <vector>

#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "tbs.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "bcrypt.lib")

// Render a CERT_NAME_BLOB as a printable string. Returns empty on failure.
static std::string FormatName(const CERT_NAME_BLOB& blob)
{
    DWORD needed = CertNameToStrA(X509_ASN_ENCODING, (PCERT_NAME_BLOB)&blob,
                                  CERT_X500_NAME_STR | CERT_NAME_STR_REVERSE_FLAG,
                                  nullptr, 0);
    if (needed <= 1) return {};
    std::string s(needed, '\0');
    CertNameToStrA(X509_ASN_ENCODING, (PCERT_NAME_BLOB)&blob,
                   CERT_X500_NAME_STR | CERT_NAME_STR_REVERSE_FLAG,
                   s.data(), needed);
    if (!s.empty() && s.back() == '\0') s.pop_back();
    return s;
}

static std::string Sha256Hex(const std::vector<uint8_t>& data)
{
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0)
        return {};
    uint8_t hash[32] = {};
    BCRYPT_HASH_HANDLE hHash = nullptr;
    std::string hex;
    if (BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0) == 0) {
        if (BCryptHashData(hHash, (PUCHAR)data.data(), (ULONG)data.size(), 0) == 0 &&
            BCryptFinishHash(hHash, hash, sizeof(hash), 0) == 0) {
            hex.resize(64);
            static const char* kHex = "0123456789abcdef";
            for (int i = 0; i < 32; ++i) {
                hex[i * 2]     = kHex[hash[i] >> 4];
                hex[i * 2 + 1] = kHex[hash[i] & 0x0F];
            }
        }
        BCryptDestroyHash(hHash);
    }
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return hex;
}

static void PrintTpmIntermediateCache()
{
    printf("\n=== TPM Intermediate Cert Cache ===\n");
    printf("Source: HKLM\\SYSTEM\\CurrentControlSet\\Services\\TPM\\WMI\\"
           "Endorsement\\IntermediateCACertStore\\Certificates\n");

    auto certs = RootHerald::ReadWindowsTpmIntermediateStore();
    printf("Found %zu intermediate(s):\n", certs.size());

    for (size_t i = 0; i < certs.size(); ++i) {
        const auto& der = certs[i];
        PCCERT_CONTEXT ctx = CertCreateCertificateContext(
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            der.data(), (DWORD)der.size());
        if (!ctx) {
            printf("  [%zu] <unparseable, %zu bytes>\n", i + 1, der.size());
            continue;
        }
        std::string subj = FormatName(ctx->pCertInfo->Subject);
        std::string issu = FormatName(ctx->pCertInfo->Issuer);
        std::string fp   = Sha256Hex(der);
        printf("  [%zu] Subject: %s\n", i + 1,
               subj.empty() ? "<unknown>" : subj.c_str());
        printf("      Issuer: %s\n",
               issu.empty() ? "<unknown>" : issu.c_str());
        printf("      SHA-256: %s\n",
               fp.empty() ? "<hash failed>" : fp.c_str());
        CertFreeCertificateContext(ctx);
    }
}

int main()
{
    printf("=== TPM Diagnostic ===\n\n");

    // 1. Try NCrypt PCP provider
    printf("[1] Opening NCrypt Platform Crypto Provider...\n");
    NCRYPT_PROV_HANDLE hProv = 0;
    SECURITY_STATUS status = NCryptOpenStorageProvider(&hProv,
        L"Microsoft Platform Crypto Provider", 0);
    if (FAILED(status)) {
        printf("  FAILED: 0x%08X\n", status);
        return 1;
    }
    printf("  OK (handle: 0x%p)\n", (void*)(uintptr_t)hProv);

    // 2. Read EK cert (try several property names)
    const wchar_t* ekCertProps[] = {
        L"PCP_RSA_EKNVCERT",
        L"PCP_ECC_EKNVCERT",
        L"PCP_EKNVCERT",
        L"PCP_EKPUB",
        nullptr
    };

    for (int i = 0; ekCertProps[i]; i++) {
        printf("[2.%d] NCryptGetProperty(%ls)...\n", i, ekCertProps[i]);
        DWORD cbResult = 0;
        status = NCryptGetProperty(hProv, ekCertProps[i], nullptr, 0, &cbResult, 0);
        if (SUCCEEDED(status) && cbResult > 0) {
            printf("  OK: %u bytes available\n", cbResult);

            uint8_t* buf = new uint8_t[cbResult];
            DWORD cbActual = 0;
            status = NCryptGetProperty(hProv, ekCertProps[i], buf, cbResult, &cbActual, 0);
            if (SUCCEEDED(status)) {
                printf("  Read %u bytes. First 16: ", cbActual);
                for (DWORD j = 0; j < 16 && j < cbActual; j++)
                    printf("%02X ", buf[j]);
                printf("\n");
            }
            delete[] buf;
        } else {
            printf("  FAILED or empty: status=0x%08X, size=%u\n", status, cbResult);
        }
    }

    // 3. Try TBS direct
    printf("\n[3] Opening TBS context...\n");
    TBS_CONTEXT_PARAMS2 params = {};
    params.version = TBS_CONTEXT_VERSION_TWO;
    params.includeTpm20 = 1;
    TBS_HCONTEXT hCtx = 0;
    TBS_RESULT tbsResult = Tbsi_Context_Create((PCTBS_CONTEXT_PARAMS)&params, &hCtx);
    if (tbsResult == TBS_SUCCESS) {
        printf("  TBS context: OK\n");

        // Read PCR[0]
        printf("[4] Reading PCR[0] via raw TBS...\n");
        uint8_t cmd[] = {
            0x80, 0x01,                     // TPM_ST_NO_SESSIONS
            0x00, 0x00, 0x00, 0x14,         // size = 20
            0x00, 0x00, 0x01, 0x7E,         // TPM2_CC_PCR_Read
            0x00, 0x00, 0x00, 0x01,         // count = 1
            0x00, 0x0B,                     // SHA-256
            0x03,                           // sizeOfSelect = 3
            0x01, 0x00, 0x00                // PCR[0]
        };

        uint8_t resp[4096];
        UINT32 respLen = sizeof(resp);
        tbsResult = Tbsip_Submit_Command(hCtx, TBS_COMMAND_LOCALITY_ZERO,
            TBS_COMMAND_PRIORITY_NORMAL, cmd, sizeof(cmd), resp, &respLen);

        if (tbsResult == TBS_SUCCESS) {
            uint32_t rc = ((uint32_t)resp[6] << 24) | ((uint32_t)resp[7] << 16) |
                          ((uint32_t)resp[8] << 8) | resp[9];
            printf("  Response: %u bytes, RC=0x%08X\n", respLen, rc);
            if (rc == 0 && respLen > 20) {
                printf("  PCR data (first 32 bytes after header): ");
                for (UINT32 j = 10; j < respLen && j < 42; j++)
                    printf("%02X", resp[j]);
                printf("\n");
            }
        } else {
            printf("  TBS command failed: 0x%08X\n", tbsResult);
        }

        // Read event log size
        printf("[5] Reading event log size...\n");
        UINT32 logSize = 0;
        tbsResult = Tbsi_Get_TCG_Log_Ex(TBS_TCGLOG_SRTM_CURRENT, nullptr, &logSize);
        if (tbsResult == TBS_SUCCESS) {
            printf("  Event log: %u bytes\n", logSize);
        } else {
            printf("  Event log failed: 0x%08X\n", tbsResult);
        }

        Tbsip_Context_Close(hCtx);
    } else {
        printf("  TBS context FAILED: 0x%08X\n", tbsResult);
    }

    // 4. Try creating a key
    printf("\n[6] Creating test key via NCrypt PCP...\n");
    NCRYPT_KEY_HANDLE hKey = 0;
    status = NCryptCreatePersistedKey(hProv, &hKey,
        BCRYPT_RSA_ALGORITHM, L"RootHeraldDiagKey", 0, NCRYPT_OVERWRITE_KEY_FLAG);
    if (SUCCEEDED(status)) {
        printf("  CreatePersistedKey: OK\n");

        DWORD usagePolicy = 0x8; // identity/attestation
        status = NCryptSetProperty(hKey, L"PCP_KEY_USAGE_POLICY",
            (PBYTE)&usagePolicy, sizeof(usagePolicy), 0);
        printf("  SetProperty(PCP_KEY_USAGE_POLICY): %s (0x%08X)\n",
               SUCCEEDED(status) ? "OK" : "FAILED", status);

        status = NCryptFinalizeKey(hKey, 0);
        printf("  FinalizeKey: %s (0x%08X)\n",
               SUCCEEDED(status) ? "OK" : "FAILED", status);

        if (SUCCEEDED(status)) {
            // Export public key
            DWORD cbResult = 0;
            status = NCryptExportKey(hKey, 0, BCRYPT_RSAPUBLIC_BLOB,
                nullptr, nullptr, 0, &cbResult, 0);
            printf("  ExportKey size: %u bytes (0x%08X)\n", cbResult, status);
        }

        NCryptDeleteKey(hKey, 0);
        printf("  Deleted test key\n");
    } else {
        printf("  CreatePersistedKey FAILED: 0x%08X\n", status);
    }

    NCryptFreeObject(hProv);

    // Print the Windows-cached vendor intermediate CA list. Useful for
    // debugging "why didn't my EK chain validate" — if the chain is missing
    // an intermediate, it usually shows up here once Windows itself has
    // validated the EK once.
    PrintTpmIntermediateCache();

    printf("\n=== Done ===\n");
    return 0;
}
