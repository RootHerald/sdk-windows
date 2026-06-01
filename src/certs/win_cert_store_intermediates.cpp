/**
 * Windows TPM Intermediate CA Certificate Store reader (impl).
 *
 * See win_cert_store_intermediates.h for the contract. We deliberately keep
 * this dependency-free of the rest of the SDK — it only needs the Win32
 * crypto APIs (`crypt32.lib`) plus the registry APIs (advapi32 — pulled in
 * by default).
 */

#include "win_cert_store_intermediates.h"

#include <windows.h>
#include <wincrypt.h>

#include <cstdio>
#include <string>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")

namespace RootHerald {

namespace {

constexpr const wchar_t* kStoreSubKey =
    L"SYSTEM\\CurrentControlSet\\Services\\TPM\\WMI\\Endorsement\\"
    L"IntermediateCACertStore\\Certificates";

// Strip an optional 20-byte CRYPT_DATA_BLOB-style header that some Windows
// versions prepend to the registry blob. In practice the blob is the raw DER
// cert — bytes 0..1 == 0x30 0x82 (ASN.1 SEQUENCE with 2-byte length). If we
// see DER framing at offset 0 we return the blob unchanged; otherwise we scan
// for the first SEQUENCE start within the first ~64 bytes and trim. If we
// find nothing recognizable we return empty (caller filters on parse failure
// anyway).
std::vector<uint8_t> NormalizeBlobToDer(const std::vector<uint8_t>& blob)
{
    if (blob.size() < 4) return {};

    // Fast path: already starts with ASN.1 SEQUENCE.
    if (blob[0] == 0x30 && (blob[1] == 0x82 || blob[1] == 0x81)) {
        return blob;
    }

    // Slow path: look for SEQUENCE + long-form length within first 64 bytes.
    const size_t scanLimit = blob.size() < 64 ? blob.size() : 64;
    for (size_t i = 1; i + 4 < scanLimit; ++i) {
        if (blob[i] == 0x30 && blob[i + 1] == 0x82) {
            return std::vector<uint8_t>(blob.begin() + i, blob.end());
        }
    }
    return {};
}

// Inspect the BasicConstraints extension to determine whether `ctx` is a CA
// cert. Returns true only if BasicConstraints is present AND cA=TRUE. We
// deliberately err on the side of including certs: if the extension is
// absent we still accept the cert (some older intermediates omit it). The
// server is the source of truth for chain validation; we just avoid sending
// obviously non-CA junk.
bool LooksLikeCaCert(PCCERT_CONTEXT ctx)
{
    if (!ctx) return false;

    PCERT_EXTENSION ext = CertFindExtension(
        szOID_BASIC_CONSTRAINTS2,
        ctx->pCertInfo->cExtension,
        ctx->pCertInfo->rgExtension);

    if (!ext) {
        // Extension not present — accept (legacy intermediates).
        return true;
    }

    CERT_BASIC_CONSTRAINTS2_INFO info = {};
    DWORD cbInfo = sizeof(info);
    BOOL ok = CryptDecodeObjectEx(
        X509_ASN_ENCODING,
        szOID_BASIC_CONSTRAINTS2,
        ext->Value.pbData,
        ext->Value.cbData,
        0,
        nullptr,
        &info,
        &cbInfo);

    if (!ok) {
        // Decode failure — be conservative and skip.
        return false;
    }
    return info.fCA == TRUE;
}

} // namespace

std::vector<std::vector<uint8_t>> ReadWindowsTpmIntermediateStore()
{
    std::vector<std::vector<uint8_t>> out;

    HKEY hRoot = nullptr;
    LONG lr = RegOpenKeyExW(HKEY_LOCAL_MACHINE, kStoreSubKey, 0,
                            KEY_READ, &hRoot);
    if (lr != ERROR_SUCCESS) {
        // Key absent (no Windows-cached intermediates yet) is the common
        // case — not an error.
        return out;
    }

    DWORD subKeyCount = 0;
    DWORD maxSubKeyLen = 0;
    lr = RegQueryInfoKeyW(hRoot, nullptr, nullptr, nullptr,
                          &subKeyCount, &maxSubKeyLen,
                          nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
    if (lr != ERROR_SUCCESS || subKeyCount == 0) {
        RegCloseKey(hRoot);
        return out;
    }

    // Each subkey is named by the cert's SHA-1 thumbprint (40 hex chars), but
    // size with slack to be safe.
    std::wstring nameBuf;
    nameBuf.resize(maxSubKeyLen + 1);

    for (DWORD idx = 0; idx < subKeyCount; ++idx) {
        DWORD nameLen = (DWORD)nameBuf.size();
        lr = RegEnumKeyExW(hRoot, idx, nameBuf.data(), &nameLen,
                           nullptr, nullptr, nullptr, nullptr);
        if (lr != ERROR_SUCCESS) continue;

        HKEY hChild = nullptr;
        lr = RegOpenKeyExW(hRoot, nameBuf.c_str(), 0, KEY_READ, &hChild);
        if (lr != ERROR_SUCCESS) continue;

        DWORD valueType = 0;
        DWORD blobLen = 0;
        lr = RegQueryValueExW(hChild, L"Blob", nullptr, &valueType,
                              nullptr, &blobLen);
        if (lr != ERROR_SUCCESS || blobLen == 0 ||
            (valueType != REG_BINARY && valueType != REG_NONE)) {
            RegCloseKey(hChild);
            continue;
        }

        std::vector<uint8_t> blob(blobLen);
        lr = RegQueryValueExW(hChild, L"Blob", nullptr, &valueType,
                              blob.data(), &blobLen);
        RegCloseKey(hChild);
        if (lr != ERROR_SUCCESS) continue;
        blob.resize(blobLen);

        std::vector<uint8_t> der = NormalizeBlobToDer(blob);
        if (der.empty()) continue;

        PCCERT_CONTEXT ctx = CertCreateCertificateContext(
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            der.data(), (DWORD)der.size());
        if (!ctx) continue;

        bool keep = LooksLikeCaCert(ctx);
        CertFreeCertificateContext(ctx);

        if (keep) {
            out.push_back(std::move(der));
        }
    }

    RegCloseKey(hRoot);
    return out;
}

} // namespace RootHerald
