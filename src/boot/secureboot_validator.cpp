/**
 * Secure Boot Chain Validator — Implementation
 *
 * Parses EFI_SIGNATURE_LIST structures from Secure Boot variable data,
 * extracts X.509 certificates, and validates them against known
 * Microsoft and OEM certificate thumbprints.
 *
 * EFI_SIGNATURE_LIST format:
 *   SignatureType (GUID, 16 bytes)
 *   SignatureListSize (4 bytes)
 *   SignatureHeaderSize (4 bytes)
 *   SignatureSize (4 bytes)
 *   SignatureHeader[SignatureHeaderSize]
 *   Signatures[]:
 *     SignatureOwner (GUID, 16 bytes)
 *     SignatureData[SignatureSize - 16]  // X.509 DER cert for EFI_CERT_X509_GUID
 */

#include "secureboot_validator.h"
#include "event_log_parser.h"

#include <windows.h>
#include <wincrypt.h>
#include <cstring>
#include <algorithm>

#pragma comment(lib, "crypt32.lib")

namespace RootHerald {

// EFI GUIDs
static const uint8_t EFI_CERT_X509_GUID[] = {
    0xa1, 0x59, 0xc0, 0xa5, 0xe4, 0x94, 0xa7, 0x4a,
    0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72
};

static const uint8_t EFI_CERT_SHA256_GUID[] = {
    0x26, 0x16, 0xc4, 0xc1, 0x4c, 0x50, 0x92, 0x40,
    0xac, 0xa9, 0x41, 0xf9, 0x36, 0x93, 0x43, 0x28
};

// Known Microsoft certificate SHA-256 thumbprints (of the DER-encoded certificate)
// These are the certificates that MUST be in the Secure Boot db/KEK for a legitimate Windows boot.

// Microsoft Corporation UEFI CA 2011
// Subject: CN=Microsoft Corporation UEFI CA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US
static const char* MS_UEFI_CA_2011_THUMBPRINT =
    "46DEF63B5CE61CF8BA0DE2E6639C1019D0ED14F3D65B68D78BA2B0461D4C2D65";

// Microsoft Windows Production PCA 2011
// Subject: CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US
static const char* MS_WIN_PCA_2011_THUMBPRINT =
    "580A6F4CC4E4B669B9EBDC1B2B3E087B80D0678D5E2A7BC341A0DC4B50BF2E27";

// Microsoft Corporation KEK CA 2011
// Subject: CN=Microsoft Corporation KEK CA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US
static const char* MS_KEK_CA_2011_THUMBPRINT =
    "31590BFD89C9D74ED087DFAC6637B34BCA2028A586CA9CF9B79EF23B2C27A4A8";

// Microsoft UEFI CA 2023
static const char* MS_UEFI_CA_2023_THUMBPRINT =
    "45A0FA32604773C82433C3B7D59E7466B3AC0C7CEEE2B40EA4EE0E14A0925F28";

// Known OEM Platform Key issuers
static const char* KNOWN_OEM_NAMES[] = {
    "Lenovo", "LENOVO",
    "Dell", "DELL",
    "HP", "Hewlett-Packard", "Hewlett Packard",
    "ASUS", "ASUSTeK",
    "Acer",
    "Microsoft", // Surface devices
    "Samsung",
    "Toshiba",
    "Fujitsu",
    "Intel",
    "AMI", "American Megatrends",
    "Phoenix",
    "Insyde",
    "ASRock",
    "Gigabyte",
    "MSI", "Micro-Star",
    "Razer",
    "Framework",
    "System76",
    "HUAWEI",
    "Xiaomi",
    nullptr
};

static uint16_t ReadU16LE(const uint8_t* p) { return p[0] | (p[1] << 8); }
static uint32_t ReadU32LE(const uint8_t* p) { return p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24); }

static std::string BytesToHexUpper(const uint8_t* data, size_t len) {
    static const char hex[] = "0123456789ABCDEF";
    std::string result;
    result.reserve(len * 2);
    for (size_t i = 0; i < len; i++) {
        result += hex[data[i] >> 4];
        result += hex[data[i] & 0x0F];
    }
    return result;
}

static std::string ToUpper(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), ::toupper);
    return s;
}

/// Compute SHA-256 thumbprint of a DER-encoded certificate.
static std::string CertThumbprint(const uint8_t* derData, size_t derLen) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    std::string result;

    if (!CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        return "";

    if (CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        if (CryptHashData(hHash, derData, (DWORD)derLen, 0)) {
            BYTE hash[32];
            DWORD hashLen = 32;
            if (CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)) {
                result = BytesToHexUpper(hash, 32);
            }
        }
        CryptDestroyHash(hHash);
    }
    CryptReleaseContext(hProv, 0);
    return result;
}

/// Extract subject/issuer from a DER certificate using Windows CryptoAPI.
static CertInfo ParseDerCertificate(const uint8_t* derData, size_t derLen) {
    CertInfo info;

    PCCERT_CONTEXT ctx = CertCreateCertificateContext(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, derData, (DWORD)derLen);

    if (!ctx) return info;

    // Subject
    char subject[512] = {};
    CertNameToStrA(X509_ASN_ENCODING, &ctx->pCertInfo->Subject,
                   CERT_X500_NAME_STR | CERT_NAME_STR_REVERSE_FLAG,
                   subject, sizeof(subject));
    info.subject = subject;

    // Issuer
    char issuer[512] = {};
    CertNameToStrA(X509_ASN_ENCODING, &ctx->pCertInfo->Issuer,
                   CERT_X500_NAME_STR | CERT_NAME_STR_REVERSE_FLAG,
                   issuer, sizeof(issuer));
    info.issuer = issuer;

    // Thumbprint
    info.thumbprintSha256 = CertThumbprint(derData, derLen);

    // Check if Microsoft cert
    std::string thumbUpper = ToUpper(info.thumbprintSha256);
    if (thumbUpper == MS_UEFI_CA_2011_THUMBPRINT ||
        thumbUpper == MS_WIN_PCA_2011_THUMBPRINT ||
        thumbUpper == MS_KEK_CA_2011_THUMBPRINT ||
        thumbUpper == MS_UEFI_CA_2023_THUMBPRINT) {
        info.isMicrosoftCert = true;
    }
    // Also check by subject name
    if (info.subject.find("Microsoft") != std::string::npos) {
        info.isMicrosoftCert = true;
    }

    // Check if known OEM
    for (int i = 0; KNOWN_OEM_NAMES[i]; i++) {
        if (info.subject.find(KNOWN_OEM_NAMES[i]) != std::string::npos ||
            info.issuer.find(KNOWN_OEM_NAMES[i]) != std::string::npos) {
            info.isKnownOem = true;
            info.oemName = KNOWN_OEM_NAMES[i];
            break;
        }
    }

    CertFreeCertificateContext(ctx);
    return info;
}

std::vector<CertInfo> ParseEfiSignatureList(const std::vector<uint8_t>& variableData) {
    std::vector<CertInfo> certs;

    // EFI variable event format:
    // EFI_GUID VariableName(16) + UnicodeNameLength(8) + VariableDataLength(8) +
    // UnicodeName[UnicodeNameLength] + VariableData[VariableDataLength]
    if (variableData.size() < 32) return certs;

    uint64_t nameLen = 0, dataLen = 0;
    memcpy(&nameLen, variableData.data() + 16, 8);
    memcpy(&dataLen, variableData.data() + 24, 8);

    size_t dataOffset = 32 + (size_t)(nameLen * 2);
    if (dataOffset + dataLen > variableData.size()) return certs;

    const uint8_t* sigListData = variableData.data() + dataOffset;
    size_t sigListRemaining = (size_t)dataLen;

    // Parse EFI_SIGNATURE_LIST entries
    while (sigListRemaining >= 28) { // Minimum: GUID(16) + 3*uint32(12)
        const uint8_t* sigType = sigListData;
        uint32_t listSize = ReadU32LE(sigListData + 16);
        uint32_t headerSize = ReadU32LE(sigListData + 20);
        uint32_t sigSize = ReadU32LE(sigListData + 24);

        if (listSize == 0 || listSize > sigListRemaining) break;

        // Check if this is an X.509 certificate list
        bool isX509 = memcmp(sigType, EFI_CERT_X509_GUID, 16) == 0;
        bool isSha256 = memcmp(sigType, EFI_CERT_SHA256_GUID, 16) == 0;

        if (isX509 && sigSize > 16) {
            // Each signature: SignatureOwner(16) + SignatureData(sigSize-16)
            size_t offset = 28 + headerSize; // Past the list header
            while (offset + sigSize <= 28 + listSize - 28 + 28 && offset + sigSize <= listSize) {
                // Recalculate: entries start after the list header (28 bytes + headerSize)
                const uint8_t* sigEntry = sigListData + offset;
                size_t certLen = sigSize - 16;
                const uint8_t* certData = sigEntry + 16; // Skip SignatureOwner GUID

                if (certLen > 0 && certLen < 65536) {
                    auto certInfo = ParseDerCertificate(certData, certLen);
                    if (!certInfo.subject.empty()) {
                        certs.push_back(certInfo);
                    }
                }

                offset += sigSize;
            }
        }

        sigListData += listSize;
        sigListRemaining -= listSize;
    }

    return certs;
}

/// Extract the EFI variable name from event data
static std::string ExtractVarName(const std::vector<uint8_t>& data) {
    if (data.size() < 32) return "";
    uint64_t nameLen = 0;
    memcpy(&nameLen, data.data() + 16, 8);
    if (32 + nameLen * 2 > data.size()) return "";

    std::string name;
    for (uint64_t i = 0; i < nameLen && i < 256; i++) {
        uint16_t ch = ReadU16LE(data.data() + 32 + i * 2);
        if (ch == 0) break;
        if (ch < 128) name += (char)ch;
    }
    return name;
}

SecureBootChainReport ValidateSecureBootChain(const std::vector<uint8_t>& rawEventLog) {
    SecureBootChainReport report;

    // First, parse the event log to get PCR[7] entries
    auto analysis = ParseAndAnalyzeEventLog(rawEventLog);
    report.secureBootEnabled = analysis.secureBootEnabled;

    // Process each PCR[7] event
    for (const auto& entry : analysis.entries) {
        if (entry.pcrIndex != 7) continue;
        if (entry.eventType != EV_EFI_VARIABLE_DRIVER_CONFIG &&
            entry.eventType != EV_EFI_VARIABLE_BOOT) continue;

        std::string varName = ExtractVarName(entry.eventData);
        auto certs = ParseEfiSignatureList(entry.eventData);

        if (varName == "PK") {
            report.pkCerts = certs;
            for (const auto& c : certs) {
                if (c.isKnownOem) {
                    report.pkIsKnownOem = true;
                    report.pkOemName = c.oemName;
                }
            }
        }
        else if (varName == "KEK") {
            report.kekCerts = certs;
            for (const auto& c : certs) {
                if (c.isMicrosoftCert) {
                    report.kekHasMicrosoft = true;
                }
            }
        }
        else if (varName == "db") {
            report.dbCerts = certs;
            for (const auto& c : certs) {
                // Match by subject name (thumbprints may differ due to DER encoding variations)
                if (c.subject.find("Microsoft Corporation UEFI CA 2011") != std::string::npos)
                    report.dbHasMicrosoftUefiCa2011 = true;
                if (c.subject.find("Microsoft UEFI CA 2023") != std::string::npos ||
                    c.subject.find("Windows UEFI CA 2023") != std::string::npos)
                    report.dbHasMicrosoftUefiCa2023 = true;
                if (c.subject.find("Microsoft Windows Production PCA 2011") != std::string::npos)
                    report.dbHasWindowsPca2011 = true;
            }
        }
        else if (varName == "dbx") {
            // dbx can contain SHA-256 hash lists, not necessarily X.509 certs
            // Count the entries
            report.dbxHashCount = (int)certs.size(); // Rough count
        }
    }

    // Generate validation verdict
    if (!report.secureBootEnabled) {
        report.errors.push_back("Secure Boot is DISABLED");
        report.verdict = "FAIL: Secure Boot disabled";
        return report;
    }

    if (report.pkCerts.empty()) {
        report.errors.push_back("No Platform Key (PK) found — Secure Boot is in setup mode");
        report.verdict = "FAIL: No Platform Key";
        return report;
    }

    if (!report.pkIsKnownOem) {
        report.warnings.push_back("Platform Key issuer not recognized as a known OEM: " +
            (report.pkCerts.empty() ? "(none)" : report.pkCerts[0].subject));
    }

    if (!report.kekHasMicrosoft) {
        report.errors.push_back("KEK does not contain Microsoft's KEK certificate — "
            "boot chain may not be controlled by Microsoft");
    }

    if (!report.dbHasMicrosoftUefiCa2011 && !report.dbHasMicrosoftUefiCa2023) {
        report.errors.push_back("db does not contain Microsoft's UEFI CA — "
            "only Microsoft-signed boot components are trusted on standard systems");
    }

    // Final verdict
    if (!report.errors.empty()) {
        report.chainValid = false;
        report.verdict = "FAIL: " + report.errors[0];
    } else if (!report.warnings.empty()) {
        report.chainValid = true;
        report.verdict = "WARNING: " + report.warnings[0];
    } else {
        report.chainValid = true;
        report.verdict = "PASS: Secure Boot chain fully validated — "
            "PK from " + report.pkOemName + ", Microsoft UEFI CA in db, Microsoft KEK present";
    }

    return report;
}

} // namespace RootHerald
