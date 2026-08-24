#include "win_cert_store_intermediates.h"

#include <windows.h>
#include <wincrypt.h>
#include <sal.h>

#include <string>

#include "unique_handle.h"

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")

namespace RootHerald {

namespace {

constexpr const wchar_t* STORE_SUBKEY =
    L"SYSTEM\\CurrentControlSet\\Services\\TPM\\WMI\\Endorsement\\"
    L"IntermediateCACertStore\\Certificates";

/* Some Windows versions prepend a small header to the registry blob. DER
 * framing at offset 0 means it is already the raw cert; otherwise scan the
 * first 64 bytes for the SEQUENCE start and trim. */
std::vector<uint8_t> NormalizeBlobToDer(const std::vector<uint8_t>& blob)
{
    if (blob.size() < 4) return {};

    if (blob[0] == 0x30 && (blob[1] == 0x82 || blob[1] == 0x81)) {
        return blob;
    }

    const size_t scanLimit = blob.size() < 64 ? blob.size() : 64;
    for (size_t i = 1; i + 4 < scanLimit; ++i) {
        if (blob[i] == 0x30 && blob[i + 1] == 0x82) {
            return std::vector<uint8_t>(blob.begin() + i, blob.end());
        }
    }
    return {};
}

/* An absent BasicConstraints extension is accepted, because some legacy
 * intermediates omit it; a present-but-undecodable one is not. */
bool IsLikelyCaCert(_In_opt_ PCCERT_CONTEXT ctx)
{
    if (!ctx) return false;

    PCERT_EXTENSION ext = CertFindExtension(
        szOID_BASIC_CONSTRAINTS2,
        ctx->pCertInfo->cExtension,
        ctx->pCertInfo->rgExtension);

    if (!ext) return true;

    CERT_BASIC_CONSTRAINTS2_INFO info = {};
    DWORD infoSize = sizeof(info);
    BOOL decoded = CryptDecodeObjectEx(
        X509_ASN_ENCODING,
        szOID_BASIC_CONSTRAINTS2,
        ext->Value.pbData,
        ext->Value.cbData,
        0,
        nullptr,
        &info,
        &infoSize);

    if (!decoded) return false;
    return info.fCA != FALSE;
}

} // namespace

std::vector<std::vector<uint8_t>> ReadWindowsTpmIntermediateStore()
{
    std::vector<std::vector<uint8_t>> out;

    UniqueRegKey root;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, STORE_SUBKEY, 0, KEY_READ, root.Put()) != ERROR_SUCCESS)
        return out;

    DWORD subKeyCount = 0;
    DWORD maxSubKeyLen = 0;
    LONG status = RegQueryInfoKeyW(root.Get(), nullptr, nullptr, nullptr,
                                   &subKeyCount, &maxSubKeyLen,
                                   nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
    if (status != ERROR_SUCCESS || subKeyCount == 0) return out;

    // Subkeys are named by SHA-1 thumbprint (40 hex chars), but size from the
    // key itself rather than assuming.
    std::wstring nameBuf;
    nameBuf.resize(maxSubKeyLen + 1);

    for (DWORD idx = 0; idx < subKeyCount; ++idx) {
        DWORD nameLen = (DWORD)nameBuf.size();
        if (RegEnumKeyExW(root.Get(), idx, nameBuf.data(), &nameLen,
                          nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
            continue;

        UniqueRegKey child;
        if (RegOpenKeyExW(root.Get(), nameBuf.c_str(), 0, KEY_READ, child.Put()) != ERROR_SUCCESS)
            continue;

        DWORD valueType = 0;
        DWORD blobLen = 0;
        status = RegQueryValueExW(child.Get(), L"Blob", nullptr, &valueType, nullptr, &blobLen);
        if (status != ERROR_SUCCESS || blobLen == 0 ||
            (valueType != REG_BINARY && valueType != REG_NONE)) {
            continue;
        }

        std::vector<uint8_t> blob(blobLen);
        status = RegQueryValueExW(child.Get(), L"Blob", nullptr, &valueType, blob.data(), &blobLen);
        if (status != ERROR_SUCCESS) continue;
        blob.resize(blobLen);

        std::vector<uint8_t> der = NormalizeBlobToDer(blob);
        if (der.empty()) continue;

        UniqueCertContext ctx(CertCreateCertificateContext(
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            der.data(), (DWORD)der.size()));
        if (!ctx) continue;

        if (IsLikelyCaCert(ctx.Get())) {
            out.push_back(std::move(der));
        }
    }

    return out;
}

} // namespace RootHerald
