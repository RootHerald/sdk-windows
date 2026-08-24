/*
 * EFI_SIGNATURE_LIST layout, as it appears inside a PCR[7] variable event:
 *   SignatureType(GUID,16) SignatureListSize(4) SignatureHeaderSize(4)
 *   SignatureSize(4) SignatureHeader[SignatureHeaderSize]
 *   Signatures[]: SignatureOwner(GUID,16) SignatureData[SignatureSize-16]
 * SignatureData is a DER X.509 certificate when SignatureType is
 * EFI_CERT_X509_GUID, and a bare SHA-256 digest when it is EFI_CERT_SHA256_GUID.
 */

#include "secureboot_validator.h"
#include "efi_variable.h"
#include "event_log_parser.h"

#include <windows.h>
#include <wincrypt.h>
#include <sal.h>
#include <climits>
#include <cstring>
#include <algorithm>

#include "unique_handle.h"

#pragma comment(lib, "crypt32.lib")

namespace RootHerald {

static const uint8_t EFI_CERT_X509_GUID[] = {
    0xa1, 0x59, 0xc0, 0xa5, 0xe4, 0x94, 0xa7, 0x4a,
    0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72
};

static const uint8_t EFI_CERT_SHA256_GUID[] = {
    0x26, 0x16, 0xc4, 0xc1, 0x4c, 0x50, 0x92, 0x40,
    0xac, 0xa9, 0x41, 0xf9, 0x36, 0x93, 0x43, 0x28
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
/* Platform owners. A PK issued to one of these names is the machine's owner
 * asserting control of Secure Boot, which is what oem_keyed reports. */
static const char* PLATFORM_OWNER_NAMES[] = {
    "Lenovo", "Dell", "Hewlett-Packard", "Hewlett Packard", "HP Inc",
    "ASUSTeK", "ASUS", "Acer", "Microsoft", "Samsung", "Toshiba", "Fujitsu",
    "ASRock", "Gigabyte", "MSI", "Micro-Star", "Supermicro", "Panasonic",
    "Sony", "LG Electronics", "Razer", "Framework", "System76",
    nullptr
};

/* Firmware vendors. Their names appear in the PK of many machines whose owner
 * never replaced the default key, so a match here is NOT evidence that a
 * platform owner keyed the machine and must not set oem_keyed. */
static const char* FIRMWARE_VENDOR_NAMES[] = {
    "American Megatrends", "AMI", "Phoenix", "Insyde", "Intel", "Byosoft",
    nullptr
};

/* Default and test Platform Keys that ship enabled on real hardware. Matching
 * one is the opposite of an owner-keyed machine, so it overrides everything
 * else. "DO NOT TRUST" is AMI's own wording on the test PK it ships. */
static const char* UNTRUSTED_PK_MARKERS[] = {
    "DO NOT TRUST", "DO_NOT_TRUST", "Test PK", "TestPK", "Insyde Test",
    "Default PK", "Sample", "Do Not Ship",
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

static bool ContainsNoCase(const std::string& haystack, const std::string& needle) {
    if (needle.empty() || haystack.size() < needle.size()) return false;
    return std::search(haystack.begin(), haystack.end(), needle.begin(), needle.end(),
                       [](char a, char b) {
                           return std::tolower((unsigned char)a) == std::tolower((unsigned char)b);
                       }) != haystack.end();
}

/* One RDN value from the subject, e.g. szOID_ORGANIZATION_NAME. Returns "" when
 * the attribute is absent, which is why every caller treats absence as no match
 * rather than as a wildcard. */
static std::string RdnValue(_In_ PCCERT_CONTEXT ctx, _In_z_ LPCSTR oid) {
    char value[256] = {};
    const DWORD n = CertGetNameStringA(ctx, CERT_NAME_ATTR_TYPE, 0, (void*)oid,
                                       value, sizeof(value));
    return (n > 1) ? std::string(value) : std::string();
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
    } else if (ContainsNoCase(RdnValue(ctx.Get(), szOID_ORGANIZATION_NAME),
                              "Microsoft Corporation")) {
        /* A pinned thumbprint is the real signal; this catches a rotated
         * Microsoft CA. Scoped to the organization RDN, because matching
         * "Microsoft" anywhere in a DN also matches an issuer field, a test
         * key, and anyone who puts the word in a common name. */
        info.isMicrosoftCert = true;
    }

    /* Order matters. A default or test PK often carries a firmware vendor's
     * name, and the AMI test key's subject is literally
     * "CN=DO NOT TRUST - AMI Test PK" — matching "AMI" there and reporting an
     * owner-keyed machine inverts the meaning of the field. */
    const std::string org = RdnValue(ctx.Get(), szOID_ORGANIZATION_NAME);
    const std::string cn  = RdnValue(ctx.Get(), szOID_COMMON_NAME);

    for (int i = 0; UNTRUSTED_PK_MARKERS[i]; i++) {
        if (ContainsNoCase(cn, UNTRUSTED_PK_MARKERS[i]) ||
            ContainsNoCase(org, UNTRUSTED_PK_MARKERS[i])) {
            info.oemName = "untrusted-default-key";
            return info;
        }
    }

    for (int i = 0; FIRMWARE_VENDOR_NAMES[i]; i++) {
        if (ContainsNoCase(org, FIRMWARE_VENDOR_NAMES[i])) {
            info.oemName = "firmware-vendor";
            return info;
        }
    }

    /* Matched against the organization RDN, not the whole distinguished name:
     * the O= field names the entity the certificate was issued to. */
    for (int i = 0; PLATFORM_OWNER_NAMES[i]; i++) {
        if (ContainsNoCase(org, PLATFORM_OWNER_NAMES[i])) {
            info.isKnownOem = true;
            info.oemName = PLATFORM_OWNER_NAMES[i];
            break;
        }
    }

    return info;
}

std::vector<CertInfo> ParseEfiSignatureList(const std::vector<uint8_t>& variableData,
                                            int* out_sha256Count) {
    std::vector<CertInfo> certs;
    size_t sha256Entries = 0;
    if (out_sha256Count) *out_sha256Count = 0;

    EfiVariableData var;
    if (!TryParseEfiVariableData(variableData, &var)) return certs;

    const uint8_t* sigListData = var.data;
    size_t sigListRemaining = var.dataBytes;

    while (sigListRemaining >= 28) { // GUID(16) + 3 * uint32
        const uint8_t* sigType = sigListData;
        uint32_t listSize = ReadU32LE(sigListData + 16);
        uint32_t headerSize = ReadU32LE(sigListData + 20);
        uint32_t sigSize = ReadU32LE(sigListData + 24);

        if (listSize == 0 || listSize > sigListRemaining) break;

        bool isX509 = memcmp(sigType, EFI_CERT_X509_GUID, 16) == 0;
        bool isSha256 = memcmp(sigType, EFI_CERT_SHA256_GUID, 16) == 0;

        // Entries begin after the list header and its optional extra header;
        // each is SignatureOwner(16) + SignatureData. headerSize is widened to
        // size_t so the offset cannot wrap before it is compared.
        const size_t entriesOffset = 28 + (size_t)headerSize;

        if (isX509 && sigSize > 16) {
            size_t offset = entriesOffset;
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
        else if (isSha256 && sigSize > 16 && entriesOffset < listSize) {
            // Fixed-size entries, so the count is arithmetic rather than a
            // walk. This is what a revocation list actually holds: dbx is a few
            // hundred digests and typically no certificate at all.
            sha256Entries += (listSize - entriesOffset) / sigSize;
        }

        sigListData += listSize;
        sigListRemaining -= listSize;
    }

    if (out_sha256Count)
        *out_sha256Count = (sha256Entries > (size_t)INT_MAX) ? INT_MAX : (int)sha256Entries;
    return certs;
}

static std::string ExtractVarName(const std::vector<uint8_t>& data) {
    EfiVariableData var;
    if (!TryParseEfiVariableData(data, &var)) return "";
    return EfiVariableName(var);
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
        int sha256Count = 0;
        auto certs = ParseEfiSignatureList(entry.eventData, &sha256Count);

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
            report.dbxHashCount = sha256Count;
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
