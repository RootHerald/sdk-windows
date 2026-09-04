/*
 * Windows driver behind the public ABI: enrollment, evidence collection and
 * local posture.
 *
 * ELEVATION: enrollment needs one elevated process for raw-TBS AK creation and
 * TPM2_ActivateCredential. Every later attestation runs unprivileged against
 * the persistent AK handle.
 *
 * The SDK opens no socket to Root Herald. Its one outbound request is the
 * best-effort AMD AIA EK-certificate fetch during enrollment.
 */

#include "client_internal.h"
#include "rootherald.h"
#include "tpm_pcp.h"
#include "tpm_commands.h"
#include "tbs_key_provider.h"
#include "amd_aia_fetch.h"
#include "event_log.h"
#include "event_log_parser.h"
#include "secureboot_validator.h"
#include "json_helpers.h"
#include "unique_handle.h"
#include "win_cert_store_intermediates.h"

#include <windows.h>
#include <bcrypt.h>
#include <sal.h>
#include <shellapi.h>
#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <string>
#include <vector>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")

/* Owner-persistent NV slot for the AK. Chosen away from the canonical
 * 0x81010001 so vendor tooling cannot collide with it. */
static const uint32_t TBS_AK_PERSISTENT_HANDLE = 0x81029301u;

static std::string Base64Encode(_In_reads_bytes_(len) const uint8_t* data, size_t len)
{
    DWORD outLen = 0;
    CryptBinaryToStringA(data, (DWORD)len, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
                          nullptr, &outLen);
    std::string result(outLen, '\0');
    CryptBinaryToStringA(data, (DWORD)len, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
                          result.data(), &outLen);
    result.resize(outLen);
    while (!result.empty() && (result.back() == '\0' || result.back() == '\n' || result.back() == '\r'))
        result.pop_back();
    return result;
}

static std::vector<uint8_t> Base64Decode(const std::string& encoded)
{
    DWORD outLen = 0;
    CryptStringToBinaryA(encoded.c_str(), 0, CRYPT_STRING_BASE64,
                          nullptr, &outLen, nullptr, nullptr);
    std::vector<uint8_t> result(outLen);
    CryptStringToBinaryA(encoded.c_str(), 0, CRYPT_STRING_BASE64,
                          result.data(), &outLen, nullptr, nullptr);
    result.resize(outLen);
    return result;
}

static std::string BytesToHex(const std::vector<uint8_t>& data)
{
    static const char HEX[] = "0123456789abcdef";
    std::string result;
    result.reserve(data.size() * 2);
    for (uint8_t b : data) {
        result += HEX[b >> 4];
        result += HEX[b & 0x0F];
    }
    return result;
}

static std::string DerToPem(const std::vector<uint8_t>& der)
{
    std::string b64 = Base64Encode(der.data(), der.size());
    return "-----BEGIN CERTIFICATE-----\n" + b64 + "\n-----END CERTIFICATE-----";
}

static std::vector<uint8_t> BcryptDigest(_In_z_ LPCWSTR algorithmId,
                                         _In_reads_bytes_(len) const uint8_t* data,
                                         size_t len)
{
    std::vector<uint8_t> out;

    RootHerald::UniqueBcryptAlg algorithm;
    if (BCryptOpenAlgorithmProvider(algorithm.Put(), algorithmId, nullptr, 0) != 0)
        return out;

    DWORD digestLen = 0, resultLen = 0;
    if (BCryptGetProperty(algorithm.Get(), BCRYPT_HASH_LENGTH,
                          (PUCHAR)&digestLen, sizeof(digestLen), &resultLen, 0) != 0)
        return out;
    if (digestLen == 0) return out;

    RootHerald::UniqueBcryptHash hash;
    if (BCryptCreateHash(algorithm.Get(), hash.Put(), nullptr, 0, nullptr, 0, 0) != 0)
        return out;
    if (BCryptHashData(hash.Get(), (PUCHAR)data, (ULONG)len, 0) != 0)
        return out;

    /* An empty vector is the only signal a caller gets, so a failed finish must
     * clear it: a zeroed buffer of the right length is indistinguishable from a
     * real digest and would feed device-id derivation and the certificate
     * dedupe as if it were one. */
    out.resize(digestLen);
    if (BCryptFinishHash(hash.Get(), out.data(), digestLen, 0) != 0)
        out.clear();
    return out;
}

static std::vector<uint8_t> Sha256(const std::vector<uint8_t>& data)
{
    return BcryptDigest(BCRYPT_SHA256_ALGORITHM, data.data(), data.size());
}

static std::vector<uint8_t> Sha1(_In_reads_bytes_(len) const uint8_t* data, size_t len)
{
    return BcryptDigest(BCRYPT_SHA1_ALGORITHM, data, len);
}

static std::string ComputeDeviceIdFromFingerprint(const std::vector<uint8_t>& fingerprint);
static std::vector<uint8_t> ReadEkCertFromWindowsStore();

/* Mirrors DeviceController.Enroll: the fingerprint is SHA-256 of the EK
 * certificate DER when one exists, else of the EK public key. Diverging from
 * the server here silently breaks unbound-session self-binding, because the
 * server looks the id up and finds nothing. */
static std::string DeriveLocalDeviceId()
{
    auto ekCertDer = ReadEkCertFromWindowsStore();
    if (ekCertDer.size() > 32)
        return ComputeDeviceIdFromFingerprint(Sha256(ekCertDer));

    RootHerald::TpmPcp ekProvider;
    if (FAILED(ekProvider.Open())) return {};

    std::vector<uint8_t> ekPub;
    if (FAILED(ekProvider.ReadEkPublicKey(&ekPub)) || ekPub.empty()) return {};
    return ComputeDeviceIdFromFingerprint(Sha256(ekPub));
}

/* Must match RootHerald.Core Device.IdFromEkFingerprint byte for byte:
 *   id16   = SHA-1(namespace || fingerprint)[:16], v5 + RFC 4122 variant
 *   string = .NET Guid formatting, first three groups byte-swapped */
static std::string ComputeDeviceIdFromFingerprint(const std::vector<uint8_t>& fingerprint)
{
    static const uint8_t DEVICE_ID_NAMESPACE[16] = {
        0x52, 0x6F, 0x6F, 0x74, 0x48, 0x65, 0x72, 0x61,
        0x6C, 0x64, 0x44, 0x65, 0x76, 0x49, 0x44, 0x76,
    };
    if (fingerprint.size() != 32) return {};

    std::vector<uint8_t> input;
    input.reserve(16 + fingerprint.size());
    input.insert(input.end(), DEVICE_ID_NAMESPACE, DEVICE_ID_NAMESPACE + 16);
    input.insert(input.end(), fingerprint.begin(), fingerprint.end());

    auto sha1 = Sha1(input.data(), input.size());
    if (sha1.size() < 16) return {};
    uint8_t b[16];
    memcpy(b, sha1.data(), 16);
    b[6] = (uint8_t)((b[6] & 0x0F) | 0x50); // version 5
    b[8] = (uint8_t)((b[8] & 0x3F) | 0x80); // RFC 4122 variant

    static const char* HEX = "0123456789abcdef";
    auto hexByte = [&](std::string& s, uint8_t v) { s += HEX[v >> 4]; s += HEX[v & 0x0F]; };
    std::string s;
    for (int i : {3, 2, 1, 0}) hexByte(s, b[i]); s += '-';
    for (int i : {5, 4})       hexByte(s, b[i]); s += '-';
    for (int i : {7, 6})       hexByte(s, b[i]); s += '-';
    for (int i : {8, 9})       hexByte(s, b[i]); s += '-';
    for (int i = 10; i < 16; i++) hexByte(s, b[i]);
    return s;
}

static bool IsProcessElevated()
{
    RootHerald::UniqueKernelHandle token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, token.Put())) return false;

    TOKEN_ELEVATION elevation = {};
    DWORD size = 0;
    if (!GetTokenInformation(token.Get(), TokenElevation, &elevation, sizeof(elevation), &size))
        return false;
    return elevation.TokenIsElevated != 0;
}

/* EK material and cert chain the server needs. Every read here is
 * unprivileged. */
struct EkEnrollData {
    std::vector<uint8_t> ekPub;       // BCRYPT_RSAPUBLIC_BLOB (PCP_EKPUB)
    std::string ekCertPem;            // empty on a firmware TPM with no NV cert
    std::vector<std::vector<uint8_t>> intermediates;
};

/* The Windows EKCertStore "Blob" value is the DER cert, sometimes behind a
 * small header, so scan for the SEQUENCE framing and return exactly the cert. */
static std::vector<uint8_t> ExtractDerCertificate(const std::vector<uint8_t>& blob)
{
    for (size_t i = 0; i + 4 < blob.size(); ++i) {
        if (blob[i] == 0x30 && blob[i + 1] == 0x82) {
            size_t len = (static_cast<size_t>(blob[i + 2]) << 8) | blob[i + 3];
            size_t total = 4 + len;
            if (total > 64 && i + total <= blob.size())
                return std::vector<uint8_t>(blob.begin() + i, blob.begin() + i + total);
        }
    }
    return {};
}

/* The vendor-signed EK certificate Windows caches during TPM provisioning.
 * This is the load-bearing proof of genuine hardware: it chains to a seeded
 * vendor root, and a software TPM has no such cert. Firmware TPMs (Intel PTT /
 * On-Die CA) expose nothing usable via PCP_RSA_EKNVCERT but do land here, and
 * the read is unprivileged. */
static std::vector<uint8_t> ReadEkCertFromWindowsStore()
{
    RootHerald::UniqueRegKey certificatesKey;
    const wchar_t* path =
        L"SYSTEM\\CurrentControlSet\\Services\\TPM\\WMI\\Endorsement\\EKCertStore\\Certificates";
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_READ, certificatesKey.Put()) != ERROR_SUCCESS)
        return {};

    wchar_t subName[256];
    for (DWORD idx = 0;; ++idx) {
        DWORD subLen = 256;
        if (RegEnumKeyExW(certificatesKey.Get(), idx, subName, &subLen,
                          nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
            break;

        RootHerald::UniqueRegKey certificateKey;
        if (RegOpenKeyExW(certificatesKey.Get(), subName, 0, KEY_READ, certificateKey.Put()) != ERROR_SUCCESS)
            continue;

        DWORD type = 0, size = 0;
        if (RegQueryValueExW(certificateKey.Get(), L"Blob", nullptr, &type, nullptr, &size) == ERROR_SUCCESS
            && size > 0) {
            std::vector<uint8_t> blob(size);
            if (RegQueryValueExW(certificateKey.Get(), L"Blob", nullptr, &type, blob.data(), &size)
                == ERROR_SUCCESS) {
                blob.resize(size);
                auto certificate = ExtractDerCertificate(blob);
                if (!certificate.empty()) return certificate;
            }
        }
    }
    return {};
}

static bool GatherEkEnrollData(_Inout_ EkEnrollData* out)
{
    RootHerald::TpmPcp pcp;
    HRESULT hr = pcp.Open();
    if (FAILED(hr)) {
        return false;
    }

    hr = pcp.ReadEkPublicKey(&out->ekPub);
    if (FAILED(hr) || out->ekPub.empty()) {
        return false;
    }

    // Windows' cached cert first — it is the real vendor-signed one and works
    // for firmware TPMs. Then the PCP NV read, then AMD's AIA endpoint.
    auto ekCert = ReadEkCertFromWindowsStore();
    if (ekCert.size() <= 32) {
        std::vector<uint8_t> nvCert;
        if (SUCCEEDED(pcp.ReadEkCertificate(&nvCert))) ekCert = std::move(nvCert);
    }
    if (ekCert.size() > 32) {
        out->ekCertPem = DerToPem(ekCert);
    } else {
        auto modulus = RootHerald::ExtractRsaModulusFromEkPub(out->ekPub);
        if (!modulus.empty()) {
            auto amdCert = RootHerald::FetchAmdAiaEkCert(modulus);
            if (!amdCert.empty()) out->ekCertPem = DerToPem(amdCert);
        }
    }

    RootHerald::TpmCommands tpm;
    if (SUCCEEDED(tpm.Open())) {
        tpm.ReadIntelOdcaIntermediates(&out->intermediates);

        // Merge the Windows-cached vendor intermediates, deduped by SHA-256 of
        // the DER and capped at 8; real chains are 2-3 deep.
        constexpr size_t MAX_INTERMEDIATES = 8;
        std::vector<std::vector<uint8_t>> seen;
        for (const auto& c : out->intermediates) {
            auto fingerprint = Sha256(c);
            if (!fingerprint.empty()) seen.push_back(std::move(fingerprint));
        }
        auto winStore = RootHerald::ReadWindowsTpmIntermediateStore();
        for (auto& certificate : winStore) {
            if (out->intermediates.size() >= MAX_INTERMEDIATES) break;
            auto fingerprint = Sha256(certificate);
            bool duplicate = false;
            for (const auto& s : seen) {
                if (s.size() == fingerprint.size() &&
                    memcmp(s.data(), fingerprint.data(), s.size()) == 0) { duplicate = true; break; }
            }
            if (duplicate) continue;
            if (!fingerprint.empty()) seen.push_back(std::move(fingerprint));
            out->intermediates.push_back(std::move(certificate));
        }
        if (out->intermediates.size() > MAX_INTERMEDIATES) out->intermediates.resize(MAX_INTERMEDIATES);
    }
    return true;
}

/* The server's EK validation, AkTemplateValidator and MakeCredential all run
 * on these exact bytes. ekCertificateChain is embedded as a raw JSON array —
 * JsonBuild passes a value starting with '[' through verbatim. */
static std::map<std::string, std::string> BuildEnrollFields(
    const EkEnrollData& ek, const std::vector<uint8_t>& akPublicArea)
{
    std::map<std::string, std::string> fields = {
        {"ekPublicKey",  Base64Encode(ek.ekPub.data(), ek.ekPub.size())},
        {"akPublicArea", Base64Encode(akPublicArea.data(), akPublicArea.size())},
        {"platform",     "windows"}
    };
    if (!ek.ekCertPem.empty()) fields["ekCertPem"] = ek.ekCertPem;
    if (!ek.intermediates.empty()) {
        std::string array = "[";
        for (size_t i = 0; i < ek.intermediates.size(); ++i) {
            if (i) array += ",";
            std::string pem = DerToPem(ek.intermediates[i]);
            std::string escaped;
            for (char c : pem) {
                if (c == '"') escaped += "\\\"";
                else if (c == '\\') escaped += "\\\\";
                else if (c == '\n') escaped += "\\n";
                else escaped += c;
            }
            array += "\"" + escaped + "\"";
        }
        array += "]";
        fields["ekCertificateChain"] = array;
    }
    return fields;
}

/* The persistent-handle AK is a TPM NV object, so it survives reboots,
 * uninstalls and disk scrubs — which makes it the only source of truth for
 * "already enrolled". */
static bool IsAkPersisted()
{
    RootHerald::TbsKeyProvider tbs(TBS_AK_PERSISTENT_HANDLE);
    return SUCCEEDED(tbs.Open()) && tbs.AkExists();
}

/* In-flight enrollment, held between EnrollBegin and EnrollComplete. It owns
 * the open TBS context and the transient EK/AK handles ActivateCredential
 * needs, so the SAME elevated process must stay resident across the relayed
 * round-trip. */
static std::unique_ptr<RootHerald::TbsKeyProvider> g_enrollProvider;

extern "C" _Use_decl_annotations_ ROOTHERALD_API RootHeraldStatus RootHeraldEnrollBegin(
    char** out_enroll_json)
{
    if (!out_enroll_json) return ROOTHERALD_ERR_INVALID_ARG;
    *out_enroll_json = nullptr;

    // AK creation here and TPM2_ActivateCredential in EnrollComplete are both
    // blocked for a non-elevated caller (TPM_E_COMMAND_BLOCKED). Report it
    // rather than elevate; the host also has to keep this process resident.
    if (!IsProcessElevated()) {
        return ROOTHERALD_ERR_ELEVATION_REQUIRED;
    }

    EkEnrollData ek;
    if (!GatherEkEnrollData(&ek)) {
        return ROOTHERALD_ERR_EK_READ_FAILED;
    }

    auto provider = std::make_unique<RootHerald::TbsKeyProvider>(TBS_AK_PERSISTENT_HANDLE);
    HRESULT hr = provider->Open();
    if (FAILED(hr)) {
        return ROOTHERALD_ERR_TPM_UNAVAILABLE;
    }
    hr = provider->CreateAk();
    if (FAILED(hr)) {
        return ROOTHERALD_ERR_AK_FAILED;
    }
    auto akPublicArea = provider->GetAkPublicArea();
    if (akPublicArea.empty()) {
        provider->DeleteAk();
        return ROOTHERALD_ERR_AK_FAILED;
    }

    std::string json = RootHerald::JsonBuild(BuildEnrollFields(ek, akPublicArea));
    char* buffer = (char*)malloc(json.size() + 1);
    if (!buffer) { provider->DeleteAk(); return ROOTHERALD_ERR_INTERNAL; }
    memcpy(buffer, json.c_str(), json.size() + 1);
    *out_enroll_json = buffer;

    g_enrollProvider = std::move(provider);
    return ROOTHERALD_OK;
}

extern "C" _Use_decl_annotations_ ROOTHERALD_API RootHeraldStatus RootHeraldEnrollComplete(
    const char* challenge_json, char** out_activate_json)
{
    if (!challenge_json || !out_activate_json) return ROOTHERALD_ERR_INVALID_ARG;
    *out_activate_json = nullptr;

    if (!g_enrollProvider) {
        return ROOTHERALD_ERR_NOT_ENROLLED;
    }

    std::string challenge(challenge_json);
    auto deviceId  = RootHerald::JsonGet(challenge, "deviceId");
    auto credBlob  = RootHerald::JsonGet(challenge, "credentialBlob");
    auto encSecret = RootHerald::JsonGet(challenge, "encryptedSecret");
    if (deviceId.empty() || credBlob.empty() || encSecret.empty()) {
        return ROOTHERALD_ERR_INVALID_ARG;
    }

    std::vector<uint8_t> secret;
    HRESULT hr = g_enrollProvider->ActivateCredential(
        Base64Decode(credBlob), Base64Decode(encSecret), &secret);
    if (FAILED(hr) || secret.empty()) {
        g_enrollProvider->DeleteAk();
        g_enrollProvider.reset();
        return ROOTHERALD_ERR_ACTIVATION_FAILED;
    }

    // Activation proved; evict to the persistent handle so later unprivileged
    // attestations can Quote against it.
    hr = g_enrollProvider->PersistAk();
    if (FAILED(hr)) {
        SecureZeroMemory(secret.data(), secret.size());
        g_enrollProvider.reset();
        return ROOTHERALD_ERR_AK_FAILED;
    }
    g_enrollProvider.reset();

    // No akPublicKey travels here: the server verifies against the AK Name
    // MakeCredential already bound at enroll.
    std::string json = RootHerald::JsonBuild({
        {"deviceId",        deviceId},
        {"decryptedSecret", Base64Encode(secret.data(), secret.size())}
    });
    SecureZeroMemory(secret.data(), secret.size());

    char* buffer = (char*)malloc(json.size() + 1);
    if (!buffer) return ROOTHERALD_ERR_INTERNAL;
    memcpy(buffer, json.c_str(), json.size() + 1);
    *out_activate_json = buffer;
    return ROOTHERALD_OK;
}

/* Null unless a persisted AK is present. The AK lives at a persistent handle
 * valid across TBS contexts and in an unprivileged process, so one load
 * suffices — no backend probing, no cache. */
static std::unique_ptr<RootHerald::TbsKeyProvider> SelectEnrolledProvider()
{
    auto provider = std::make_unique<RootHerald::TbsKeyProvider>(TBS_AK_PERSISTENT_HANDLE);
    if (SUCCEEDED(provider->Open()) && SUCCEEDED(provider->LoadAk())) return provider;
    return nullptr;
}

/* Produces exactly the object POST /api/v1/attest/verify expects in its
 * `evidence` field. No network call, no key. On failure out_reason carries a
 * short human-readable cause. */
static RootHeraldStatus CollectEvidenceFields(
    _In_z_ const char* nonce_b64,
    _Inout_ std::map<std::string, std::string>* out_fields,
    _Inout_ std::string* out_reason)
{
    out_fields->clear();
    out_reason->clear();

    // NOT_ENROLLED (rather than a hard failure) is what lets the native host's
    // eviction-tolerant auto-recovery re-enroll and retry.
    auto provider = SelectEnrolledProvider();
    if (!provider) {
        *out_reason = "Not enrolled";
        return ROOTHERALD_ERR_NOT_ENROLLED;
    }
    uint32_t akHandle = provider->GetQuoteHandle();
    if (!akHandle) {
        *out_reason = "AK handle unavailable";
        return ROOTHERALD_ERR_AK_FAILED;
    }

    RootHerald::TpmCommands tpmCmd;
    HRESULT hr = tpmCmd.Open();
    if (FAILED(hr)) {
        *out_reason = "TPM unavailable";
        return ROOTHERALD_ERR_TPM_UNAVAILABLE;
    }

    auto nonce = Base64Decode(std::string(nonce_b64));
    if (nonce.empty()) {
        *out_reason = "Invalid nonce";
        return ROOTHERALD_ERR_INVALID_ARG;
    }

    std::vector<uint32_t> pcrs = {0, 1, 2, 3, 4, 7};
    std::string pcrValuesJson = "{\"sha256\":{";
    bool first = true;
    for (uint32_t index : pcrs) {
        std::vector<uint8_t> pcrValue;
        hr = tpmCmd.PcrRead(index, &pcrValue);
        if (FAILED(hr) || pcrValue.empty()) {
            *out_reason = "PCR read failed";
            return ROOTHERALD_ERR_QUOTE_FAILED;
        }
        if (!first) pcrValuesJson += ",";
        first = false;
        pcrValuesJson += "\"" + std::to_string(index) + "\":\"" + BytesToHex(pcrValue) + "\"";
    }
    pcrValuesJson += "}}";

    // Freshness is bound INSIDE the signature: the quote is taken over the
    // caller's nonce, so relaying the blob through the customer's server
    // preserves the binding exactly.
    std::vector<uint8_t> quoted, signature;
    hr = tpmCmd.Quote(akHandle, nonce, pcrs, &quoted, &signature);
    if (FAILED(hr)) {
        *out_reason = "Quote failed";
        return ROOTHERALD_ERR_QUOTE_FAILED;
    }
    std::string quoteJson = RootHerald::JsonBuild({
        {"quoted",    Base64Encode(quoted.data(), quoted.size())},
        {"signature", Base64Encode(signature.data(), signature.size())},
        {"nonce",     Base64Encode(nonce.data(), nonce.size())}
    });

    auto eventLog = RootHerald::ReadEventLog();
    std::string secureBootJson = "null";
    if (!eventLog.empty()) {
        auto chainReport = RootHerald::ValidateSecureBootChain(eventLog);
        auto eventAnalysis = RootHerald::ParseAndAnalyzeEventLog(eventLog);
        secureBootJson = RootHerald::JsonBuild({
            {"secureBootEnabled",       chainReport.secureBootEnabled ? "true" : "false"},
            {"pkSubject",               chainReport.pkCerts.empty() ? "" : chainReport.pkCerts[0].subject},
            {"pkIssuer",                chainReport.pkCerts.empty() ? "" : chainReport.pkCerts[0].issuer},
            {"pkIsKnownOem",            chainReport.pkIsKnownOem ? "true" : "false"},
            {"pkOemName",               chainReport.pkOemName},
            {"kekHasMicrosoft",         chainReport.kekHasMicrosoft ? "true" : "false"},
            {"dbHasMicrosoftUefiCa",    (chainReport.dbHasMicrosoftUefiCa2011 || chainReport.dbHasMicrosoftUefiCa2023) ? "true" : "false"},
            {"dbHasMicrosoftWindowsPca", chainReport.dbHasWindowsPca2011 ? "true" : "false"},
            {"dbxHashCount",            std::to_string(chainReport.dbxHashCount)},
            {"totalMeasurements",       std::to_string(eventAnalysis.entries.size())},
            {"verifiedCount",           std::to_string(eventAnalysis.verifiedCount)},
            {"unknownCount",            std::to_string(eventAnalysis.unknownCount)},
            {"verdict",                 chainReport.verdict}
        });
    }

    *out_fields = {
        {"pcrValues", pcrValuesJson},
        {"quote", quoteJson},
        {"secureBootChain", secureBootJson}
    };

    // The raw log lets the server do its OWN Secure Boot parse and bind it to
    // the signed quote (replayed PCRs must match the quoted PCRs). Without it
    // the server cannot trust any boot-state posture, because secureBootChain
    // above is client-computed and advisory.
    if (!eventLog.empty())
        (*out_fields)["eventLog"] = Base64Encode(eventLog.data(), eventLog.size());

    // The EK cert plus On-Die CA intermediates let the server reclassify this
    // device's root of trust from a chain terminating at a seeded vendor root
    // — which is what separates real hardware from an emulator, and lets an
    // enrolled device self-heal its classification without re-enrolling.
    {
        auto ekCertDer = ReadEkCertFromWindowsStore();
        if (ekCertDer.size() > 32)
            (*out_fields)["ekCertPem"] = DerToPem(ekCertDer);

        std::vector<std::vector<uint8_t>> ekChain;
        tpmCmd.ReadIntelOdcaIntermediates(&ekChain);
        if (!ekChain.empty()) {
            std::string array = "[";
            for (size_t i = 0; i < ekChain.size(); ++i) {
                if (i) array += ",";
                std::string pem = DerToPem(ekChain[i]);
                std::string escaped;
                for (char c : pem) {
                    if (c == '"') escaped += "\\\"";
                    else if (c == '\\') escaped += "\\\\";
                    else if (c == '\n') escaped += "\\n";
                    else escaped += c;
                }
                array += "\"" + escaped + "\"";
            }
            array += "]";
            (*out_fields)["ekCertificateChain"] = array;
        }
    }

    // An unbound session leaves DeviceId null at challenge time, so derive it
    // from the EK the same way the server does and let it resolve to this
    // device. /verify requires a DeviceId naming an enrolled device.
    std::string deviceId = DeriveLocalDeviceId();
    if (!deviceId.empty()) (*out_fields)["deviceId"] = deviceId;

    return ROOTHERALD_OK;
}

extern "C" _Use_decl_annotations_ ROOTHERALD_API RootHeraldStatus RootHeraldCollectEvidence(
    const char* nonce_b64, char** out_evidence_json)
{
    if (!nonce_b64 || !out_evidence_json)
        return ROOTHERALD_ERR_INVALID_ARG;
    *out_evidence_json = nullptr;

    std::map<std::string, std::string> fields;
    std::string reason;
    RootHeraldStatus result = CollectEvidenceFields(nonce_b64, &fields, &reason);
    if (result != ROOTHERALD_OK) {
        return result;
    }

    std::string json = RootHerald::JsonBuild(fields);
    char* buffer = (char*)malloc(json.size() + 1);
    if (!buffer) return ROOTHERALD_ERR_INTERNAL;
    memcpy(buffer, json.c_str(), json.size() + 1);
    *out_evidence_json = buffer;
    return ROOTHERALD_OK;
}

extern "C" _Use_decl_annotations_ ROOTHERALD_API void RootHeraldFreeEvidence(char* evidence_json)
{
    free(evidence_json);
}

/* Local-only posture snapshot. Never touches the network; detail_json mirrors
 * the secureBootChain fields the collect flow serializes, minus anything
 * network-derived. */
extern "C" _Use_decl_annotations_ RootHeraldStatus RootHeraldCollectLocalPosture(RootHeraldPosture* out_posture)
{
    if (!out_posture)
        return ROOTHERALD_ERR_INVALID_ARG;
    memset(out_posture, 0, sizeof(RootHeraldPosture));
    strncpy_s(out_posture->platform_name, "windows", _TRUNCATE);

    // -1 is "undetermined"/"unavailable" until the event log says otherwise.
    out_posture->secure_boot = -1;
    out_posture->oem_keyed = -1;
    out_posture->boot_log_measurements = -1;
    // Stays -1: nothing cross-references measured digests against dbx yet.
    // See the field comment in rootherald.h.
    out_posture->boot_log_revoked = -1;

    RootHerald::TpmPcp pcp;
    out_posture->has_tpm = pcp.IsAvailable() ? 1 : 0;
    out_posture->is_enrolled = IsAkPersisted() ? 1 : 0;

    auto ekCertDer = ReadEkCertFromWindowsStore();
    out_posture->ek_cert_present = (ekCertDer.size() > 32) ? 1 : 0;

    if (out_posture->has_tpm) {
        try {
            auto deviceId = DeriveLocalDeviceId();
            if (!deviceId.empty())
                strncpy_s(out_posture->device_id, deviceId.c_str(), _TRUNCATE);

        } catch (...) {
        }
    }

    std::map<std::string, std::string> detail = {
        {"hasTpm",        out_posture->has_tpm ? "true" : "false"},
        {"isEnrolled",    out_posture->is_enrolled ? "true" : "false"},
        {"ekCertPresent", out_posture->ek_cert_present ? "true" : "false"},
        {"deviceId",      out_posture->device_id},
        {"platform",      "windows"}
    };

    auto eventLog = RootHerald::ReadEventLog();
    if (!eventLog.empty()) {
        auto chainReport = RootHerald::ValidateSecureBootChain(eventLog);
        auto eventAnalysis = RootHerald::ParseAndAnalyzeEventLog(eventLog);

        out_posture->secure_boot = chainReport.secureBootEnabled ? 1 : 0;
        out_posture->oem_keyed = chainReport.pkIsKnownOem ? 1 : 0;
        strncpy_s(out_posture->oem_name, chainReport.pkOemName.c_str(), _TRUNCATE);
        out_posture->boot_log_measurements = (int)eventAnalysis.entries.size();

        detail["secureBootEnabled"] = chainReport.secureBootEnabled ? "true" : "false";
        detail["pkIsKnownOem"]      = chainReport.pkIsKnownOem ? "true" : "false";
        detail["pkOemName"]         = chainReport.pkOemName;
        detail["kekHasMicrosoft"]   = chainReport.kekHasMicrosoft ? "true" : "false";
        detail["dbxHashCount"]      = std::to_string(chainReport.dbxHashCount);
        detail["totalMeasurements"] = std::to_string(eventAnalysis.entries.size());
        detail["verifiedCount"]     = std::to_string(eventAnalysis.verifiedCount);
        detail["unknownCount"]      = std::to_string(eventAnalysis.unknownCount);
        detail["verdict"]           = chainReport.verdict;
    } else {
        detail["eventLog"] = "unavailable";
    }

    auto detailJson = RootHerald::JsonBuild(detail);
    strncpy_s(out_posture->detail_json, detailJson.c_str(), _TRUNCATE);
    return ROOTHERALD_OK;
}
