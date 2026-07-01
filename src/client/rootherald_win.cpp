/**
 *  Root Herald Windows Client SDK -- Full Implementation
 *
 * Enrollment establishes the device's attestation key (AK) exactly once, under
 * a single elevation (the "Establish hardware key" UAC): raw TPM 2.0 over TBS
 * creates the AK (RSASSA-SHA256 template), runs TPM2_ActivateCredential to bind
 * it to the EK, and evicts it to a PERSISTENT handle. Every subsequent
 * attestation (TPM2_Quote + PCR/event-log collection) runs UNPRIVILEGED against
 * that persistent handle — no further UAC, ever.
 *
 * There is one AK backend (TbsKeyProvider). The earlier dual-path design
 * (PCP-first, elevated-TBS fallback) was removed once it was proven that raw-TBS
 * activation succeeds under elevation: PCP's only value was dodging the UAC, but
 * its AIK is locked to a SHA-1 signing scheme and its quote handle is bound to
 * PCP's TBS context. TpmPcp is retained solely for the unprivileged EK
 * public-key / cert read. EK gathering and TPM2_Quote are mode-agnostic.
 *
 * Uses WinHTTP for server communication.
 */

#include "rootherald_win.h"
#include "rootherald.h"
#include "tpm_pcp.h"
#include "tpm_commands.h"
#include "attestation_key_provider.h"
#include "tbs_key_provider.h"
#include "amd_aia_fetch.h"
#include "event_log.h"
#include "event_log_parser.h"
#include "secureboot_validator.h"
#include "http_winhttp.h"
#include "json_helpers.h"
#include "win_cert_store_intermediates.h"
#include "log.h"

#include <windows.h>
#include <bcrypt.h>
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

// --- Backend identity -----------------------------------------------------

// Persistent NV slot for the TBS-managed AK (owner persistent range). Survives
// reboots and is reachable from any TBS context for Quote. Chosen away from
// the canonical 0x81010001 to avoid colliding with vendor tooling.
static const uint32_t kTbsAkPersistentHandle = 0x81029301u;

// Global device ID override, optionally set by the host before evidence
// collection to bind a user-owned device. When empty, CollectEvidenceFields
// derives the deviceId from the EK (see DeriveLocalDeviceId).
static std::string g_deviceId;

// ===========================================================================
// Encoding / hashing primitives (base64, hex, PEM, SHA-1, SHA-256).
// ===========================================================================

static std::string Base64Encode(const uint8_t* data, size_t len)
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
    static const char hex[] = "0123456789abcdef";
    std::string result;
    result.reserve(data.size() * 2);
    for (uint8_t b : data) {
        result += hex[b >> 4];
        result += hex[b & 0x0F];
    }
    return result;
}

static std::string DerToPem(const std::vector<uint8_t>& der)
{
    std::string b64 = Base64Encode(der.data(), der.size());
    return "-----BEGIN CERTIFICATE-----\n" + b64 + "\n-----END CERTIFICATE-----";
}

static std::vector<uint8_t> Sha256(const std::vector<uint8_t>& data)
{
    std::vector<uint8_t> out;
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0)
        return out;

    DWORD cbHash = 0, cbResult = 0;
    BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PUCHAR)&cbHash, sizeof(cbHash), &cbResult, 0);
    if (cbHash == 0) { BCryptCloseAlgorithmProvider(hAlg, 0); return out; }

    BCRYPT_HASH_HANDLE hHash = nullptr;
    if (BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0) == 0) {
        if (BCryptHashData(hHash, (PUCHAR)data.data(), (ULONG)data.size(), 0) == 0) {
            out.resize(cbHash);
            BCryptFinishHash(hHash, out.data(), cbHash, 0);
        }
        BCryptDestroyHash(hHash);
    }
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return out;
}

static std::vector<uint8_t> Sha1(const uint8_t* data, size_t len)
{
    std::vector<uint8_t> out;
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA1_ALGORITHM, nullptr, 0) != 0)
        return out;
    DWORD cbHash = 0, cbResult = 0;
    BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PUCHAR)&cbHash, sizeof(cbHash), &cbResult, 0);
    if (cbHash == 0) { BCryptCloseAlgorithmProvider(hAlg, 0); return out; }
    BCRYPT_HASH_HANDLE hHash = nullptr;
    if (BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0) == 0) {
        if (BCryptHashData(hHash, (PUCHAR)data, (ULONG)len, 0) == 0) {
            out.resize(cbHash);
            BCryptFinishHash(hHash, out.data(), cbHash, 0);
        }
        BCryptDestroyHash(hHash);
    }
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return out;
}

// Format the deterministic deviceId from an EK fingerprint, so an attest can
// self-bind a /try session without the deviceId having to flow from the
// (possibly no-op) enroll step. The cert-first choice of which fingerprint to
// hash lives in DeriveLocalDeviceId; this helper only does the formatting.
//
// Must match RootHerald.Core Device.IdFromEkFingerprint exactly:
//   id16   = SHA-1(namespace || fingerprint)[:16], v5 + RFC4122 variant
//   string = .NET Guid formatting (first three groups byte-swapped)
static std::string ComputeDeviceIdFromFingerprint(const std::vector<uint8_t>& fingerprint);

// Forward declaration — defined with the enroll helpers below.
static std::vector<uint8_t> ReadEkCertFromWindowsStore();

// Derive the deviceId exactly as the server does (DeviceController.Enroll):
// fingerprint = SHA-256(EK certificate DER) when the device has an EK cert,
// else SHA-256(EK public key). Getting this wrong silently breaks unbound-
// session self-binding — the server looks the id up and finds nothing.
static std::string DeriveLocalDeviceId()
{
    auto ekCertDer = ReadEkCertFromWindowsStore();
    if (ekCertDer.size() > 32)
        return ComputeDeviceIdFromFingerprint(Sha256(ekCertDer));

    RootHerald::TpmPcp ekProv;
    if (!ekProv.Open()) return {};
    auto ekPub = ekProv.ReadEkPublicKey();
    if (ekPub.empty()) return {};
    return ComputeDeviceIdFromFingerprint(Sha256(ekPub));
}

static std::string ComputeDeviceIdFromFingerprint(const std::vector<uint8_t>& fingerprint)
{
    static const uint8_t kNamespace[16] = {
        0x52, 0x6F, 0x6F, 0x74, 0x48, 0x65, 0x72, 0x61,
        0x6C, 0x64, 0x44, 0x65, 0x76, 0x49, 0x44, 0x76,
    };
    if (fingerprint.size() != 32) return {};

    std::vector<uint8_t> input;
    input.reserve(16 + fingerprint.size());
    input.insert(input.end(), kNamespace, kNamespace + 16);
    input.insert(input.end(), fingerprint.begin(), fingerprint.end());

    auto sha1 = Sha1(input.data(), input.size());
    if (sha1.size() < 16) return {};
    uint8_t b[16];
    memcpy(b, sha1.data(), 16);
    b[6] = (uint8_t)((b[6] & 0x0F) | 0x50); // version 5
    b[8] = (uint8_t)((b[8] & 0x3F) | 0x80); // RFC 4122 variant

    // .NET Guid string: first 3 groups are little-endian (byte-swapped).
    static const char* hx = "0123456789abcdef";
    auto hexByte = [&](std::string& s, uint8_t v) { s += hx[v >> 4]; s += hx[v & 0x0F]; };
    std::string s;
    for (int i : {3, 2, 1, 0}) hexByte(s, b[i]); s += '-';
    for (int i : {5, 4})       hexByte(s, b[i]); s += '-';
    for (int i : {7, 6})       hexByte(s, b[i]); s += '-';
    for (int i : {8, 9})       hexByte(s, b[i]); s += '-';
    for (int i = 10; i < 16; i++) hexByte(s, b[i]);
    return s;
}

// ===========================================================================
// Process elevation.
// ===========================================================================

static bool IsProcessElevated()
{
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    TOKEN_ELEVATION elev = {};
    DWORD sz = 0;
    bool elevated = false;
    if (GetTokenInformation(token, TokenElevation, &elev, sizeof(elev), &sz))
        elevated = (elev.TokenIsElevated != 0);
    CloseHandle(token);
    return elevated;
}

// ===========================================================================
// Shared, mode-agnostic enrollment building blocks.
// ===========================================================================

// EK material + cert chain the server needs, gathered the same way regardless
// of which AK backend is in use (all reads are unprivileged).
struct EkEnrollData {
    std::vector<uint8_t> ekPub;       // BCRYPT_RSAPUBLIC_BLOB (PCP_EKPUB)
    std::string ekCertPem;            // may be empty (firmware TPM)
    std::vector<std::vector<uint8_t>> intermediates;
};

// Locate the embedded X.509 DER certificate within a blob (the Windows
// EKCertStore "Blob" value is the DER cert, sometimes behind a small header).
// Scans for the SEQUENCE header (0x30 0x82 len-hi len-lo) and returns exactly
// that cert's bytes.
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

// Read the genuine EK certificate that Windows caches during TPM provisioning.
// Firmware TPMs (Intel PTT / On-Die CA) don't expose a usable cert via
// PCP_RSA_EKNVCERT, but the real vendor-signed EK cert lives here and is
// readable unprivileged. This is the load-bearing source for proving genuine
// hardware (it chains to the seeded vendor root; a software TPM has no such cert).
static std::vector<uint8_t> ReadEkCertFromWindowsStore()
{
    HKEY hCerts = nullptr;
    const wchar_t* path =
        L"SYSTEM\\CurrentControlSet\\Services\\TPM\\WMI\\Endorsement\\EKCertStore\\Certificates";
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_READ, &hCerts) != ERROR_SUCCESS)
        return {};

    std::vector<uint8_t> result;
    wchar_t subName[256];
    for (DWORD idx = 0;; ++idx) {
        DWORD subLen = 256;
        if (RegEnumKeyExW(hCerts, idx, subName, &subLen, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
            break;
        HKEY hSub = nullptr;
        if (RegOpenKeyExW(hCerts, subName, 0, KEY_READ, &hSub) != ERROR_SUCCESS)
            continue;
        DWORD type = 0, cb = 0;
        if (RegQueryValueExW(hSub, L"Blob", nullptr, &type, nullptr, &cb) == ERROR_SUCCESS && cb > 0) {
            std::vector<uint8_t> blob(cb);
            if (RegQueryValueExW(hSub, L"Blob", nullptr, &type, blob.data(), &cb) == ERROR_SUCCESS) {
                blob.resize(cb);
                auto cert = ExtractDerCertificate(blob);
                if (!cert.empty()) { RegCloseKey(hSub); RegCloseKey(hCerts); return cert; }
            }
        }
        RegCloseKey(hSub);
    }
    RegCloseKey(hCerts);
    return result;
}

static bool GatherEkEnrollData(EkEnrollData& out)
{
    RootHerald::TpmPcp pcp;
    if (!pcp.Open()) {
        RH_LOG_WARN("[enroll] PCP open failed (EK extraction)\n");
        return false;
    }
    out.ekPub = pcp.ReadEkPublicKey();
    if (out.ekPub.empty()) {
        RH_LOG_WARN("[enroll] EK pub read failed\n");
        return false;
    }
    RH_LOG_WARN("[enroll] EK pub: %zu bytes\n", out.ekPub.size());

    // Prefer Windows' cached EK cert (the real vendor-signed cert — works for
    // firmware TPMs that don't surface it via PCP). Fall back to the PCP NV
    // read, then the AMD AIA fetch.
    auto ekCert = ReadEkCertFromWindowsStore();
    if (ekCert.size() <= 32) ekCert = pcp.ReadEkCertificate();
    if (ekCert.size() > 32) {
        RH_LOG_WARN("[enroll] EK cert: %zu bytes\n", ekCert.size());
        out.ekCertPem = DerToPem(ekCert);
    } else {
        // Firmware TPM (Intel PTT / AMD fTPM): no NV EK cert. Try AMD's AIA
        // endpoint; otherwise rely on ekCertificateChain + server leniency.
        auto modulus = RootHerald::ExtractRsaModulusFromEkPub(out.ekPub);
        if (!modulus.empty()) {
            auto amdCert = RootHerald::FetchAmdAiaEkCert(modulus);
            if (!amdCert.empty()) out.ekCertPem = DerToPem(amdCert);
        }
    }

    RootHerald::TpmCommands tpm;
    if (tpm.Open()) {
        tpm.ReadIntelOdcaIntermediates(out.intermediates);
        // Merge Windows-cached vendor intermediates, deduped by SHA-256(DER),
        // capped at 8 (real chains are 2-3 deep).
        constexpr size_t kMaxIntermediates = 8;
        std::vector<std::vector<uint8_t>> seen;
        for (const auto& c : out.intermediates) { auto fp = Sha256(c); if (!fp.empty()) seen.push_back(std::move(fp)); }
        auto winStore = RootHerald::ReadWindowsTpmIntermediateStore();
        for (auto& cert : winStore) {
            if (out.intermediates.size() >= kMaxIntermediates) break;
            auto fp = Sha256(cert);
            bool dup = false;
            for (const auto& s : seen)
                if (s.size() == fp.size() && memcmp(s.data(), fp.data(), s.size()) == 0) { dup = true; break; }
            if (dup) continue;
            if (!fp.empty()) seen.push_back(std::move(fp));
            out.intermediates.push_back(std::move(cert));
        }
        if (out.intermediates.size() > kMaxIntermediates) out.intermediates.resize(kMaxIntermediates);
    }
    RH_LOG_WARN("[enroll] EK cert chain: %zu intermediate(s)\n", out.intermediates.size());
    return true;
}

// Assemble the exact field map for POST /api/v1/devices/enroll from the gathered
// EK data and the AK public area. Used by the (elevated) RunEnrollFlow — the
// server's EK validation + AkTemplateValidator + MakeCredential run on these
// exact bytes.
// The ekCertificateChain value is a raw JSON array string (JsonBuild embeds it
// verbatim via its '[' detection); every other value is a plain string.
static std::map<std::string, std::string> BuildEnrollFields(
    const EkEnrollData& ek, const std::vector<uint8_t>& akPub)
{
    std::map<std::string, std::string> fields = {
        {"ekPublicKey",  Base64Encode(ek.ekPub.data(), ek.ekPub.size())},
        {"akPublicArea", Base64Encode(akPub.data(), akPub.size())},
        {"platform",     "windows"}
    };
    if (!ek.ekCertPem.empty()) fields["ekCertPem"] = ek.ekCertPem;
    if (!ek.intermediates.empty()) {
        std::string arr = "[";
        for (size_t i = 0; i < ek.intermediates.size(); ++i) {
            if (i) arr += ",";
            std::string pem = DerToPem(ek.intermediates[i]);
            std::string esc;
            for (char c : pem) { if (c=='"') esc+="\\\""; else if (c=='\\') esc+="\\\\"; else if (c=='\n') esc+="\\n"; else esc+=c; }
            arr += "\"" + esc + "\"";
        }
        arr += "]";
        fields["ekCertificateChain"] = arr;
    }
    return fields;
}

// ===========================================================================
// Keyless, backend-relayed enrollment (ABI 3.0): EnrollBegin / EnrollComplete.
//
// The enroll ceremony is irreducibly two server round-trips with a TPM op
// between them:
//   1. EnrollBegin  — gather EK pub + EK cert chain + create an AK (raw-TBS,
//                     elevated) -> emit the verbatim POST /devices/enroll body.
//   2. [backend relays it; RootHerald validates the EK chain + AkTemplate,
//      MakeCredential-seals a secret to the EK, returns the challenge.]
//   3. EnrollComplete(challenge) — TPM2_ActivateCredential decrypts the secret
//                     -> emit the verbatim POST /devices/activate body.
//   4. [backend relays it; RootHerald constant-time compares + Name-match
//      guards -> enrolled.]
//
// These two halves make NO network call and consult NO key — the embedder's
// BACKEND relays the bytes (WP4 Option A). This only moves the network boundary:
// the server-side EK-chain validation, AkTemplateValidator (closes the
// software-AK spoof), MakeCredential sealing, constant-time secret compare, and
// activate Name-match guard ALL still run on the relayed bytes, byte-for-byte —
// it weakens nothing.
//
// SINGLE ELEVATION SPANS BEGIN -> COMPLETE. Raw-TBS AK creation (begin) and
// TPM2_ActivateCredential (complete) both require an elevated process. Crucially,
// TbsKeyProvider::ActivateCredential needs the *transient* EK+AK handles that
// CreateAk established in begin (LoadAk over the persistent handle does NOT
// restore them) — so the provider, with its open TBS context, is held resident
// in this process across the relayed round-trip via g_enrollProvider. The
// embedder must therefore keep the SAME (elevated) process alive from EnrollBegin
// through EnrollComplete (e.g. an elevated worker that emits the begin blob over
// IPC, waits for the relayed challenge, then calls complete). This is the
// keyless relay shape ABI 1.4 had, now on the TBS/single-elevation base (no PCP).
// ===========================================================================

// True if the device already has a persisted AK. The persistent-handle AK
// survives reboots, uninstalls, and test hard-scrubs (it's a TPM NV object), so
// this is the sole source of truth for "already enrolled".
static bool AnyAkPresent()
{
    RootHerald::TbsKeyProvider tbs(kTbsAkPersistentHandle);
    return tbs.Open() && tbs.AkExists();
}

// In-flight enrollment state held BETWEEN EnrollBegin and EnrollComplete within a
// single (elevated) process. Holds the open TBS context + transient EK/AK handles
// that ActivateCredential requires; must outlive the relayed network round-trip.
static std::unique_ptr<RootHerald::TbsKeyProvider> g_enrollProvider;

// Begin enrollment (keyless): gather EK + create an AK under elevation; emit the
// /devices/enroll request body. Caller owns the buffer; free it with
// RootHeraldFreeEvidence. Holds the provider open for the matching EnrollComplete.
extern "C" ROOTHERALD_API RootHeraldResult RootHeraldEnrollBegin(
    char** out_enroll_json)
{
    if (!out_enroll_json) return RH_PROTO_ERR_INVALID_PARAM;
    *out_enroll_json = nullptr;

    // Raw-TBS AK creation here, and TPM2_ActivateCredential in EnrollComplete,
    // both require elevation (TPM_E_COMMAND_BLOCKED otherwise). Report it; the
    // host arranges elevation AND keeps this process resident across the relay.
    if (!IsProcessElevated()) {
        RH_LOG_WARN("[enroll-begin] not elevated; raw-TBS activation will be blocked\n");
        return RH_PROTO_ERR_ELEVATION_REQUIRED;
    }

    EkEnrollData ek;
    if (!GatherEkEnrollData(ek)) {
        RH_LOG_WARN("[enroll-begin] EK gather failed\n");
        return RH_PROTO_ERR_ENROLLMENT_FAILED;
    }

    auto provider = std::make_unique<RootHerald::TbsKeyProvider>(kTbsAkPersistentHandle);
    if (!provider->Open()) {
        RH_LOG_WARN("[enroll-begin] provider open failed\n");
        return RH_PROTO_ERR_ENROLLMENT_FAILED;
    }
    if (!provider->CreateAk()) {
        RH_LOG_WARN("[enroll-begin] CreateAk failed\n");
        return RH_PROTO_ERR_ENROLLMENT_FAILED;
    }
    auto akPub = provider->GetAkPublicArea();
    if (akPub.empty()) {
        RH_LOG_WARN("[enroll-begin] GetAkPublicArea failed\n");
        provider->DeleteAk();
        return RH_PROTO_ERR_ENROLLMENT_FAILED;
    }
    RH_LOG_WARN("[enroll-begin] AK created, pub area %zu bytes\n", akPub.size());

    // Byte-identical to the (removed) direct path's enroll body, via the shared
    // assembler — the server's EK validation + AkTemplateValidator + MakeCredential
    // run on these exact bytes.
    std::string json = RootHerald::JsonBuild(BuildEnrollFields(ek, akPub));
    char* buf = (char*)malloc(json.size() + 1);
    if (!buf) { provider->DeleteAk(); return RH_PROTO_ERR_INTERNAL; }
    memcpy(buf, json.c_str(), json.size() + 1);
    *out_enroll_json = buf;

    // Hold the provider (open context + transient EK/AK) for EnrollComplete.
    g_enrollProvider = std::move(provider);
    return RH_PROTO_OK;
}

// Complete enrollment (keyless): TPM2_ActivateCredential over the server's
// MakeCredential challenge; emit the /devices/activate request body, persist the
// activated AK. Caller owns the buffer; free it with RootHeraldFreeEvidence.
extern "C" ROOTHERALD_API RootHeraldResult RootHeraldEnrollComplete(
    const char* challenge_json, char** out_activate_json)
{
    if (!challenge_json || !out_activate_json) return RH_PROTO_ERR_INVALID_PARAM;
    *out_activate_json = nullptr;

    if (!g_enrollProvider) {
        RH_LOG_WARN("[enroll-complete] no in-flight enrollment — call EnrollBegin "
                    "first in THIS (resident, elevated) process\n");
        return RH_PROTO_ERR_NOT_ENROLLED;
    }

    std::string challenge(challenge_json);
    auto deviceId  = RootHerald::JsonGet(challenge, "deviceId");
    auto credBlob  = RootHerald::JsonGet(challenge, "credentialBlob");
    auto encSecret = RootHerald::JsonGet(challenge, "encryptedSecret");
    if (deviceId.empty() || credBlob.empty() || encSecret.empty()) {
        RH_LOG_WARN("[enroll-complete] challenge missing deviceId/credentialBlob/encryptedSecret\n");
        return RH_PROTO_ERR_INVALID_PARAM;
    }

    // The mode-defining TPM op, against the transient AK+EK from EnrollBegin.
    auto secret = g_enrollProvider->ActivateCredential(
        Base64Decode(credBlob), Base64Decode(encSecret));
    if (secret.empty()) {
        RH_LOG_WARN("[enroll-complete] ActivateCredential failed\n");
        g_enrollProvider->DeleteAk();
        g_enrollProvider.reset();
        return RH_PROTO_ERR_ATTESTATION_FAILED;
    }
    RH_LOG_WARN("[enroll-complete] ActivateCredential OK (%zu bytes)\n", secret.size());

    // Activation proved; evict the AK to the persistent handle so later
    // (unprivileged) attestation can Quote against it.
    if (!g_enrollProvider->PersistAk()) {
        RH_LOG_WARN("[enroll-complete] PersistAk failed\n");
        g_enrollProvider.reset();
        return RH_PROTO_ERR_ENROLLMENT_FAILED;
    }
    g_enrollProvider.reset();

    // Exact POST /api/v1/devices/activate body. The genuine client sends NO
    // akPublicKey here (only the decrypted secret) — the server verifies against
    // the AK Name MakeCredential already bound at enroll.
    std::string json = RootHerald::JsonBuild({
        {"deviceId",        deviceId},
        {"decryptedSecret", Base64Encode(secret.data(), secret.size())}
    });
    char* buf = (char*)malloc(json.size() + 1);
    if (!buf) return RH_PROTO_ERR_INTERNAL;
    memcpy(buf, json.c_str(), json.size() + 1);
    *out_activate_json = buf;
    RH_LOG_WARN("[enroll-complete] complete (deviceId=%s)\n", deviceId.c_str());
    return RH_PROTO_OK;
}

// Return an opened provider whose AK is loaded, or null if not enrolled. The AK
// lives at a persistent handle (valid across TBS contexts and in an unprivileged
// process), so a single load suffices — no backend probing, no cache.
static std::unique_ptr<RootHerald::IAttestationKeyProvider> SelectEnrolledProvider()
{
    auto p = std::make_unique<RootHerald::TbsKeyProvider>(kTbsAkPersistentHandle);
    if (p->Open() && p->LoadAk()) return p;
    return nullptr;
}

// ===========================================================================
// Shared evidence collection (Background-Check WP6).
//
// CollectEvidenceFields runs the on-device collection portion that was
// previously fused inline into RootHeraldAttest — find the enrolled AK, open a
// TBS context, read PCRs, TPM2_Quote over the caller's nonce, parse the TCG
// event log + Secure Boot chain, and gather the EK cert + intermediate chain —
// and returns the assembled evidence as a key/value map. It performs NO network
// call and requires NO API/site key. Both the Passport direct-POST path
// (RootHeraldAttest) and the dumb-client collect-only path
// (RootHeraldCollectEvidence) build on this so the evidence shape is identical.
//
// The map it produces is exactly the AttestationRequest-shaped evidence object
// the server's background-check POST /api/v1/attestations/verify expects in its
// `evidence` field (and the same the Passport POST /api/v1/attest expects),
// MINUS the Passport-only `sessionId` / `linkToken` fields, which the caller
// adds afterward (RootHeraldAttest does; the dumb-client collect must NOT).
//
// On failure it writes a short reason into out_reason and returns the matching
// RootHeraldResult; on success it returns RH_PROTO_OK with out_fields populated.
// ===========================================================================
static RootHeraldResult CollectEvidenceFields(
    const char* nonce_b64,
    std::map<std::string, std::string>& out_fields,
    std::string& out_reason)
{
    out_fields.clear();
    out_reason.clear();

    // 1. Find the backend holding the enrolled AK. NOT_ENROLLED lets the
    //    native host's eviction-tolerant auto-recovery kick in (re-enroll +
    //    retry) instead of a hard failure.
    auto provider = SelectEnrolledProvider();
    if (!provider) {
        RH_LOG_WARN("[collect] no enrolled AK on any backend -- not enrolled\n");
        out_reason = "Not enrolled";
        return RH_PROTO_ERR_NOT_ENROLLED;
    }
    RH_LOG_WARN("[collect] using %s backend\n", provider->ModeName());
    uint32_t akHandle = provider->GetQuoteHandle();
    if (!akHandle) {
        RH_LOG_WARN("[collect] could not resolve AK quote handle (mode=%s)\n", provider->ModeName());
        out_reason = "AK handle unavailable";
        return RH_PROTO_ERR_ATTESTATION_FAILED;
    }

    // 2. Open a TBS context for the shared PCR-read + Quote. For TBS mode the
    //    quote handle is a persistent handle, valid in this context. For PCP
    //    mode it is the PCP_PLATFORMHANDLE; cross-context validity is firmware
    //    dependent (PCP mode is not reachable on firmwares where activation
    //    falls back to TBS, which is where this is exercised today).
    RootHerald::TpmCommands tpmCmd;
    if (!tpmCmd.Open()) {
        out_reason = "TPM unavailable";
        return RH_PROTO_ERR_NO_TPM;
    }

    auto nonce = Base64Decode(std::string(nonce_b64));
    if (nonce.empty()) {
        out_reason = "Invalid nonce";
        return RH_PROTO_ERR_INVALID_PARAM;
    }

    // 3. Read PCR values (fail loudly).
    std::vector<uint32_t> pcrs = {0, 1, 2, 3, 4, 7};
    std::string pcrValuesJson = "{\"sha256\":{";
    bool first = true;
    for (uint32_t idx : pcrs) {
        auto pcrVal = tpmCmd.PcrRead(idx);
        if (pcrVal.empty()) {
            RH_LOG_WARN("[collect] PcrRead(%u) failed -- aborting\n", idx);
            out_reason = "PCR read failed";
            return RH_PROTO_ERR_ATTESTATION_FAILED;
        }
        if (!first) pcrValuesJson += ",";
        first = false;
        pcrValuesJson += "\"" + std::to_string(idx) + "\":\"" + BytesToHex(pcrVal) + "\"";
    }
    pcrValuesJson += "}}";

    // 4. TPM2_Quote against the loaded AK — bound to the CALLER'S nonce. This is
    //    the freshness/anti-replay binding: the nonce is signed inside the quote,
    //    so it is transport-agnostic (relaying the blob through the customer's
    //    server preserves the binding exactly).
    std::vector<uint8_t> quoted, signature;
    if (!tpmCmd.Quote(akHandle, nonce, pcrs, quoted, signature)) {
        RH_LOG_WARN("[collect] TPM2_Quote failed\n");
        out_reason = "Quote failed";
        return RH_PROTO_ERR_ATTESTATION_FAILED;
    }
    std::string quoteJson = RootHerald::JsonBuild({
        {"quoted",    Base64Encode(quoted.data(), quoted.size())},
        {"signature", Base64Encode(signature.data(), signature.size())},
        {"nonce",     Base64Encode(nonce.data(), nonce.size())}
    });

    // 5. Event log + Secure Boot chain validation.
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
            {"revokedCount",            std::to_string(eventAnalysis.revokedCount)},
            {"verdict",                 chainReport.verdict}
        });
    }

    // 6. Assemble the evidence map. NOTE: the Passport-only `sessionId` /
    //    `linkToken` fields are deliberately NOT added here — RootHeraldAttest
    //    adds them for the direct-POST path; the dumb-client collect path leaves
    //    them out (the freshness nonce comes from the customer's challenge).
    out_fields = {
        {"pcrValues", pcrValuesJson},
        {"quote", quoteJson},
        {"secureBootChain", secureBootJson}
    };
    // Send the raw TCG event log so the server can do its OWN Secure Boot chain
    // parse and bind it to the signed quote (replayed PCRs must match the quoted
    // PCRs). Without this the server can't trust any boot-state posture.
    if (!eventLog.empty())
        out_fields["eventLog"] = Base64Encode(eventLog.data(), eventLog.size());

    // EK evidence: the genuine vendor-signed EK certificate (+ On-Die CA
    // intermediates from NV) so the server can (re)classify this device's TPM
    // root of trust from a chain that validates to a seeded vendor root. This
    // is what proves "real hardware TPM" vs a software emulator, and lets an
    // already-enrolled device self-heal its classification without re-enrolling.
    {
        auto ekCertDer = ReadEkCertFromWindowsStore();
        if (ekCertDer.size() > 32)
            out_fields["ekCertPem"] = DerToPem(ekCertDer);
        std::vector<std::vector<uint8_t>> ekChain;
        tpmCmd.ReadIntelOdcaIntermediates(ekChain);
        if (!ekChain.empty()) {
            std::string arr = "[";
            for (size_t i = 0; i < ekChain.size(); ++i) {
                if (i) arr += ",";
                std::string pem = DerToPem(ekChain[i]);
                std::string esc;
                for (char c : pem) { if (c == '"') esc += "\\\""; else if (c == '\\') esc += "\\\\"; else if (c == '\n') esc += "\\n"; else esc += c; }
                arr += "\"" + esc + "\"";
            }
            arr += "]";
            out_fields["ekCertificateChain"] = arr;
        }
    }
    // Bind the device to the evidence. The tray sets g_deviceId for user-bound
    // flows; otherwise derive it from the EK so an unbound session
    // (DeviceId left null at challenge time) resolves to this device — the
    // server recomputes the same id from the stored EK fingerprint. The server's
    // /verify requires DeviceId to identify an enrolled device in the tenant.
    std::string deviceId = g_deviceId;
    if (deviceId.empty()) deviceId = DeriveLocalDeviceId();
    if (!deviceId.empty()) out_fields["deviceId"] = deviceId;

    return RH_PROTO_OK;
}

// ===========================================================================
// Per-attestation collect-only entry (keyless).
//
// Backs the public RootHeraldClient_CollectEvidence. Collects the self-contained
// evidence blob (quote over the caller's nonce, EK pub cert + chain, PCRs, event
// log, secure-boot chain) and returns it as a heap-allocated JSON string to the
// embedder, who hands it to the CUSTOMER's server for relay to
// POST /api/v1/attestations/verify.
//
// NO network call. NO key required. The returned buffer is caller-owned; free it
// with RootHeraldFreeEvidence. (The earlier Passport direct-POST RootHeraldAttest
// was removed in ABI 3.0 — the client never POSTs to RootHerald or holds a key.)
// ===========================================================================
extern "C" ROOTHERALD_API RootHeraldResult RootHeraldCollectEvidence(
    const char* nonce_b64, char** out_evidence_json)
{
    if (!nonce_b64 || !out_evidence_json)
        return RH_PROTO_ERR_INVALID_PARAM;
    *out_evidence_json = nullptr;

    std::map<std::string, std::string> fields;
    std::string reason;
    RootHeraldResult r = CollectEvidenceFields(nonce_b64, fields, reason);
    if (r != RH_PROTO_OK) {
        RH_LOG_WARN("[collect-evidence] failed: %s\n", reason.c_str());
        return r;
    }

    std::string json = RootHerald::JsonBuild(fields);
    char* buf = (char*)malloc(json.size() + 1);
    if (!buf) return RH_PROTO_ERR_INTERNAL;
    memcpy(buf, json.c_str(), json.size() + 1);
    *out_evidence_json = buf;
    return RH_PROTO_OK;
}

// Free a buffer returned by RootHeraldCollectEvidence. Safe to call with NULL.
extern "C" ROOTHERALD_API void RootHeraldFreeEvidence(char* evidence_json)
{
    free(evidence_json);
}

void RootHeraldSetDeviceId(const char* device_id)
{
    if (device_id) g_deviceId = device_id;
    else g_deviceId.clear();
}

RootHeraldResult RootHeraldGetStatus(RootHeraldDeviceStatus* out_status)
{
    if (!out_status)
        return RH_PROTO_ERR_INVALID_PARAM;
    memset(out_status, 0, sizeof(RootHeraldDeviceStatus));
    strncpy_s(out_status->platform, "windows", _TRUNCATE);

    RootHerald::TpmPcp pcp;
    out_status->has_tpm = pcp.IsAvailable() ? 1 : 0;

    // Enrolled iff the persistent-handle AK is present.
    out_status->is_enrolled = AnyAkPresent() ? 1 : 0;

    // Populate device_id when we have a TPM. The deviceId is a deterministic
    // hash over the EK identity (cert when present, else pubkey — mirroring
    // the server's derivation), so we can compute it from the live TPM
    // without having performed an enroll. This matches the API contract —
    // the RootHeraldDeviceStatus struct declares device_id, so callers
    // expect it to be populated when has_tpm=1.
    if (out_status->has_tpm) {
        try {
            auto did = DeriveLocalDeviceId();
            if (!did.empty())
                strncpy_s(out_status->device_id, did.c_str(), _TRUNCATE);
        } catch (...) {
            // Best-effort — leave device_id empty rather than fail the status call.
        }
    }
    return RH_PROTO_OK;
}

// LOCAL-ONLY posture snapshot for RootHeraldClient_CollectPosture (contract
// C5, ABI 1.2). Reuses the same internals the status / attest flows already
// exercise — TPM probe, AK presence, EK cert store, deviceId derivation, and
// the TCG event log + Secure Boot chain analysis — and NEVER touches the
// network. detail_json mirrors the secureBootChain fields the attest flow
// serializes, minus anything network-derived.
extern "C" RootHeraldResult RootHeraldCollectLocalPosture(RootHeraldPosture* out_posture)
{
    if (!out_posture)
        return RH_PROTO_ERR_INVALID_PARAM;
    memset(out_posture, 0, sizeof(RootHeraldPosture));

    // Event-log-derived signals default to "undetermined"/"unavailable".
    out_posture->secure_boot = -1;
    out_posture->oem_keyed = -1;
    out_posture->boot_log_measurements = -1;
    out_posture->boot_log_revoked = -1;

    // TPM reachability (same probe as RootHeraldGetStatus).
    RootHerald::TpmPcp pcp;
    out_posture->has_tpm = pcp.IsAvailable() ? 1 : 0;

    // Local enrollment: the persistent-handle AK is present.
    out_posture->is_enrolled = AnyAkPresent() ? 1 : 0;

    // Vendor EK certificate cached by Windows during TPM provisioning.
    auto ekCertDer = ReadEkCertFromWindowsStore();
    out_posture->ek_cert_present = (ekCertDer.size() > 32) ? 1 : 0;

    // Deterministic local device id (cert-first, mirroring the server's
    // derivation). Best-effort — leave empty rather than fail the call.
    if (out_posture->has_tpm) {
        try {
            auto did = DeriveLocalDeviceId();
            if (!did.empty())
                strncpy_s(out_posture->device_id, did.c_str(), _TRUNCATE);
        } catch (...) {
        }
    }

    // Measured-boot signals from the TCG event log. An empty/unreadable log
    // leaves the -1 "undetermined" defaults in place.
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
        out_posture->boot_log_revoked = eventAnalysis.revokedCount;

        detail["secureBootEnabled"] = chainReport.secureBootEnabled ? "true" : "false";
        detail["pkIsKnownOem"]      = chainReport.pkIsKnownOem ? "true" : "false";
        detail["pkOemName"]         = chainReport.pkOemName;
        detail["kekHasMicrosoft"]   = chainReport.kekHasMicrosoft ? "true" : "false";
        detail["dbxHashCount"]      = std::to_string(chainReport.dbxHashCount);
        detail["totalMeasurements"] = std::to_string(eventAnalysis.entries.size());
        detail["verifiedCount"]     = std::to_string(eventAnalysis.verifiedCount);
        detail["unknownCount"]      = std::to_string(eventAnalysis.unknownCount);
        detail["revokedCount"]      = std::to_string(eventAnalysis.revokedCount);
        detail["verdict"]           = chainReport.verdict;
    } else {
        detail["eventLog"] = "unavailable";
    }

    auto detailJson = RootHerald::JsonBuild(detail);
    strncpy_s(out_posture->detail_json, detailJson.c_str(), _TRUNCATE);
    return RH_PROTO_OK;
}
