/*
 * EFI_SIGNATURE_LIST layout, as it appears inside a PCR[7] variable event:
 *   SignatureType(GUID,16) SignatureListSize(4) SignatureHeaderSize(4)
 *   SignatureSize(4) SignatureHeader[SignatureHeaderSize]
 *   Signatures[]: SignatureOwner(GUID,16) SignatureData[SignatureSize-16]
 * SignatureData is a DER X.509 certificate when SignatureType is
 * EFI_CERT_X509_GUID.
 */

#include "secureboot_validator.h"
#include "event_log_parser.h"

#include <windows.h>
#include <wincrypt.h>
#include <sal.h>
#include <cstring>
#include <algorithm>

#include "unique_handle.h"

#pragma comment(lib, "crypt32.lib")

namespace RootHerald {

static const uint8_t EFI_CERT_X509_GUID[] = {
    0xa1, 0x59, 0xc0, 0xa5, 0xe4, 0x94, 0xa7, 0x4a,
    0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72
};

/* SHA-256 of the DER-encoded certificate, for the certificates a legitimate
 * Windows boot chain carries in db/KEK. */
static const char* MS_UEFI_CA_2011_THUMBPRINT =
    "46DEF63B5CE61CF8BA0DE2E6639C1019D0ED14F3D65B68D78BA2B0461D4C2D65";
static const char* MS_WIN_PCA_2011_THUMBPRINT =
    "580A6F4CC4E4B669B9EBDC1B2B3E087B80D0678D5E2A7BC341A0DC4B50BF2E27";
static const char* MS_KEK_CA_2011_THUMBPRINT =
    "31590BFD89C9D74ED087DFAC6637B34BCA2028A586CA9CF9B79EF23B2C27A4A8";
static const char* MS_UEFI_CA_2023_THUMBPRINT =
    "45A0FA32604773C82433C3B7D59E7466B3AC0C7CEEE2B40EA4EE0E14A0925F28";

/* Substrings matched against a Platform Key's subject or issuer. */
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

static uint16_t ReadU16LE(_In_reads_bytes_(2) const uint8_t* p) { return p[0] | (p[1] << 8); }
static uint32_t ReadU32LE(_In_reads_bytes_(4) const uint8_t* p) { return p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24); }

static std::string BytesToHexUpper(_In_reads_bytes_(len) const uint8_t* data, size_t len) {
    static const char HEX[] = "0123456789ABCDEF";
    std::string result;
    result.reserve(len * 2);
    for (size_t i = 0; i < len; i++) {
        result += HEX[data[i] >> 4];
        result += HEX[data[i] & 0x0F];
    }
    return result;
}

static std::string ToUpper(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), ::toupper);
    return s;
}

static std::string CertThumbprint(_In_reads_bytes_(derLen) const uint8_t* derData, size_t derLen) {
    UniqueCryptProv provider;
    if (!CryptAcquireContextW(provider.Put(), nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        return "";

    UniqueCryptHash hash;
    if (!CryptCreateHash(provider.Get(), CALG_SHA_256, 0, 0, hash.Put()))
        return "";

    if (!CryptHashData(hash.Get(), derData, (DWORD)derLen, 0)) return "";

    BYTE digest[32];
    DWORD digestLen = 32;
    if (!CryptGetHashParam(hash.Get(), HP_HASHVAL, digest, &digestLen, 0)) return "";

    return BytesToHexUpper(digest, 32);
}

static CertInfo ParseDerCertificate(_In_reads_bytes_(derLen) const uint8_t* derData, size_t derLen) {
    CertInfo info;

    UniqueCertContext ctx(CertCreateCertificateContext(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, derData, (DWORD)derLen));
    if (!ctx) return info;

    char subject[512] = {};
    CertNameToStrA(X509_ASN_ENCODING, &ctx.Get()->pCertInfo->Subject,
                   CERT_X500_NAME_STR | CERT_NAME_STR_REVERSE_FLAG,
                   subject, sizeof(subject));
    info.subject = subject;

    char issuer[512] = {};
    CertNameToStrA(X509_ASN_ENCODING, &ctx.Get()->pCertInfo->Issuer,
                   CERT_X500_NAME_STR | CERT_NAME_STR_REVERSE_FLAG,
                   issuer, sizeof(issuer));
    info.issuer = issuer;

    info.thumbprintSha256 = CertThumbprint(derData, derLen);

    std::string thumbUpper = ToUpper(info.thumbprintSha256);
    if (thumbUpper == MS_UEFI_CA_2011_THUMBPRINT ||
        thumbUpper == MS_WIN_PCA_2011_THUMBPRINT ||
        thumbUpper == MS_KEK_CA_2011_THUMBPRINT ||
        thumbUpper == MS_UEFI_CA_2023_THUMBPRINT) {
        info.isMicrosoftCert = true;
    }
    if (info.subject.find("Microsoft") != std::string::npos) {
        info.isMicrosoftCert = true;
    }

    for (int i = 0; KNOWN_OEM_NAMES[i]; i++) {
        if (info.subject.find(KNOWN_OEM_NAMES[i]) != std::string::npos ||
            info.issuer.find(KNOWN_OEM_NAMES[i]) != std::string::npos) {
            info.isKnownOem = true;
            info.oemName = KNOWN_OEM_NAMES[i];
            break;
        }
    }

    return info;
}

std::vector<CertInfo> ParseEfiSignatureList(const std::vector<uint8_t>& variableData) {
    std::vector<CertInfo> certs;

    if (variableData.size() < 32) return certs;

    uint64_t nameLen = 0, dataLen = 0;
    memcpy(&nameLen, variableData.data() + 16, 8);
    memcpy(&dataLen, variableData.data() + 24, 8);

    size_t dataOffset = 32 + (size_t)(nameLen * 2);
    if (dataOffset + dataLen > variableData.size()) return certs;

    const uint8_t* sigListData = variableData.data() + dataOffset;
    size_t sigListRemaining = (size_t)dataLen;

    while (sigListRemaining >= 28) { // GUID(16) + 3 * uint32
        const uint8_t* sigType = sigListData;
        uint32_t listSize = ReadU32LE(sigListData + 16);
        uint32_t headerSize = ReadU32LE(sigListData + 20);
        uint32_t sigSize = ReadU32LE(sigListData + 24);

        if (listSize == 0 || listSize > sigListRemaining) break;

        bool isX509 = memcmp(sigType, EFI_CERT_X509_GUID, 16) == 0;

        if (isX509 && sigSize > 16) {
            // Entries begin after the list header and its optional extra
            // header; each is SignatureOwner(16) + SignatureData.
            size_t offset = 28 + headerSize;
            while (offset + sigSize <= listSize) {
                const uint8_t* sigEntry = sigListData + offset;
                size_t certLen = sigSize - 16;
                const uint8_t* certData = sigEntry + 16;

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

    auto analysis = ParseAndAnalyzeEventLog(rawEventLog);
    report.secureBootEnabled = analysis.secureBootEnabled;

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
                // Matched by subject: DER encoding variations move thumbprints.
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
            // dbx mostly holds SHA-256 hash lists rather than X.509 certs, so
            // this counts only the parseable certificate entries.
            report.dbxHashCount = (int)certs.size();
        }
    }

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
