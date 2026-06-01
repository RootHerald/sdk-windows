/**
 * NCrypt Platform Crypto Provider wrapper.
 *
 * Implements the full AK lifecycle (create / load / activate / quote-handle)
 * over NCrypt, because Windows TBS blocks raw TPM2_ActivateCredential for
 * user-mode callers. See tpm_pcp.h for the design rationale.
 */

#include "tpm_pcp.h"
#include <winerror.h>
#include <cstdio>

// PCP provider name
static const wchar_t* PCP_PROVIDER = L"Microsoft Platform Crypto Provider";

// PCP key-usage bit for an attestation/identity key (restricted signing).
// Matches NCRYPT_PCP_GENERIC_KEY ... NCRYPT_TPM12_PROVIDER usage flag 0x8
// used by the Windows attestation stack for AIKs.
static constexpr DWORD kPcpIdentityKeyUsage = 0x00000008;

namespace RootHerald {

TpmPcp::TpmPcp() = default;

TpmPcp::~TpmPcp() { Close(); }

bool TpmPcp::IsAvailable() const
{
    NCRYPT_PROV_HANDLE hProv = 0;
    SECURITY_STATUS status = NCryptOpenStorageProvider(&hProv, PCP_PROVIDER, 0);
    if (SUCCEEDED(status)) {
        NCryptFreeObject(hProv);
        return true;
    }
    return false;
}

bool TpmPcp::Open()
{
    if (_isOpen) return true;

    SECURITY_STATUS status = NCryptOpenStorageProvider(&_hProvider, PCP_PROVIDER, 0);
    if (FAILED(status)) return false;

    _isOpen = true;
    return true;
}

void TpmPcp::CloseAk()
{
    if (_hAk) { NCryptFreeObject(_hAk); _hAk = 0; }
}

void TpmPcp::Close()
{
    CloseAk();
    if (_hProvider) { NCryptFreeObject(_hProvider); _hProvider = 0; }
    _isOpen = false;
}

std::vector<uint8_t> TpmPcp::ReadEkCertificate()
{
    if (!_isOpen) return {};

    DWORD cbResult = 0;
    SECURITY_STATUS status = NCryptGetProperty(
        _hProvider, L"PCP_RSA_EKNVCERT", nullptr, 0, &cbResult, 0);

    if (FAILED(status) || cbResult == 0) return {};

    std::vector<uint8_t> cert(cbResult);
    status = NCryptGetProperty(
        _hProvider, L"PCP_RSA_EKNVCERT", cert.data(), cbResult, &cbResult, 0);

    if (FAILED(status)) return {};
    cert.resize(cbResult);
    return cert;
}

std::vector<uint8_t> TpmPcp::ReadEkPublicKey()
{
    if (!_isOpen) return {};

    DWORD cbResult = 0;
    SECURITY_STATUS status = NCryptGetProperty(
        _hProvider, L"PCP_EKPUB", nullptr, 0, &cbResult, 0);

    if (FAILED(status) || cbResult == 0) return {};

    std::vector<uint8_t> pubKey(cbResult);
    status = NCryptGetProperty(
        _hProvider, L"PCP_EKPUB", pubKey.data(), cbResult, &cbResult, 0);

    if (FAILED(status)) return {};
    pubKey.resize(cbResult);
    return pubKey;
}

bool TpmPcp::AkExists(const wchar_t* keyName)
{
    if (!_isOpen) return false;
    NCRYPT_KEY_HANDLE hKey = 0;
    SECURITY_STATUS status = NCryptOpenKey(_hProvider, &hKey, keyName, 0, 0);
    if (SUCCEEDED(status)) {
        NCryptFreeObject(hKey);
        return true;
    }
    return false;
}

bool TpmPcp::CreateAk(const wchar_t* keyName)
{
    if (!_isOpen) return false;
    CloseAk();

    // Match go-attestation's NewAK sequence exactly (known-working on
    // Windows): create without the overwrite flag (delete any stale key
    // first), set Length, then PCP_KEY_USAGE_POLICY = identity, finalize.
    DeleteAk(keyName);

    SECURITY_STATUS status = NCryptCreatePersistedKey(
        _hProvider, &_hAk, BCRYPT_RSA_ALGORITHM, keyName, 0, 0);
    if (FAILED(status)) {
        fprintf(stderr, "[pcp] NCryptCreatePersistedKey failed: 0x%08X\n", status);
        return false;
    }

    // RSA-2048 attestation key (set Length first, as go-attestation does).
    DWORD length = 2048;
    status = NCryptSetProperty(_hAk, NCRYPT_LENGTH_PROPERTY,
                               (PBYTE)&length, sizeof(length), 0);
    if (FAILED(status)) {
        fprintf(stderr, "[pcp] SetProperty(NCRYPT_LENGTH_PROPERTY) failed: 0x%08X\n", status);
        CloseAk();
        return false;
    }

    DWORD usage = kPcpIdentityKeyUsage;
    status = NCryptSetProperty(_hAk, L"PCP_KEY_USAGE_POLICY",
                               (PBYTE)&usage, sizeof(usage), 0);
    if (FAILED(status)) {
        fprintf(stderr, "[pcp] SetProperty(PCP_KEY_USAGE_POLICY) failed: 0x%08X\n", status);
        CloseAk();
        return false;
    }

    status = NCryptFinalizeKey(_hAk, 0);
    if (FAILED(status)) {
        fprintf(stderr, "[pcp] NCryptFinalizeKey failed: 0x%08X\n", status);
        CloseAk();
        return false;
    }
    return true;
}

bool TpmPcp::LoadAk(const wchar_t* keyName)
{
    if (!_isOpen) return false;
    CloseAk();
    SECURITY_STATUS status = NCryptOpenKey(_hProvider, &_hAk, keyName, 0, 0);
    if (FAILED(status)) {
        _hAk = 0;
        return false;
    }
    return true;
}

bool TpmPcp::DeleteAk(const wchar_t* keyName)
{
    if (!_isOpen) return false;
    NCRYPT_KEY_HANDLE hKey = 0;
    SECURITY_STATUS status = NCryptOpenKey(_hProvider, &hKey, keyName, 0, 0);
    if (FAILED(status)) {
        // Not present == already deleted.
        if (_hAk) CloseAk();
        return true;
    }
    if (_hAk == hKey) _hAk = 0;
    status = NCryptDeleteKey(hKey, 0); // also frees the handle
    return SUCCEEDED(status);
}

std::vector<uint8_t> TpmPcp::GetAkPublicArea()
{
    if (!_hAk) return {};

    // PCP_TPM12_IDBINDING for a TPM 2.0 key is:
    //   TPM2B_PUBLIC || TPM2B_CREATION_DATA || TPM2B_ATTEST || TPMT_SIGNATURE
    // (each TPM2B is a 2-byte big-endian size followed by that many bytes).
    // The first TPM2B is the AK's public area — exactly what the server
    // needs to compute the AK Name.
    DWORD cb = 0;
    SECURITY_STATUS status = NCryptGetProperty(
        _hAk, L"PCP_TPM12_IDBINDING", nullptr, 0, &cb, 0);
    if (FAILED(status) || cb < 2) {
        fprintf(stderr, "[pcp] GetProperty(PCP_TPM12_IDBINDING) size failed: 0x%08X\n", status);
        return {};
    }
    std::vector<uint8_t> idBinding(cb);
    status = NCryptGetProperty(
        _hAk, L"PCP_TPM12_IDBINDING", idBinding.data(), cb, &cb, 0);
    if (FAILED(status)) {
        fprintf(stderr, "[pcp] GetProperty(PCP_TPM12_IDBINDING) read failed: 0x%08X\n", status);
        return {};
    }

    // First field: TPM2B_PUBLIC. Big-endian size prefix.
    if (idBinding.size() < 2) return {};
    uint16_t pubSize = (uint16_t)((idBinding[0] << 8) | idBinding[1]);
    if ((size_t)2 + pubSize > idBinding.size()) {
        fprintf(stderr, "[pcp] IDBINDING TPM2B_PUBLIC size %u overruns blob %u\n",
                pubSize, (unsigned)idBinding.size());
        return {};
    }

    // Return the full TPM2B_PUBLIC (size prefix included) so the server's
    // existing parser (which accepts TPM2B_PUBLIC or raw TPMT_PUBLIC) gets
    // identical bytes to the prior raw-TBS path.
    return std::vector<uint8_t>(idBinding.begin(), idBinding.begin() + 2 + pubSize);
}

std::vector<uint8_t> TpmPcp::ActivateCredential(
    const std::vector<uint8_t>& credBlob,
    const std::vector<uint8_t>& encSecret)
{
    if (!_hAk) return {};

    // PCP expects the two TPM2B blobs concatenated: full TPM2B_ID_OBJECT
    // followed by full TPM2B_ENCRYPTED_SECRET (both size-prefixed, exactly
    // as the server emits them). No header, no version field.
    std::vector<uint8_t> blob;
    blob.reserve(credBlob.size() + encSecret.size());
    blob.insert(blob.end(), credBlob.begin(), credBlob.end());
    blob.insert(blob.end(), encSecret.begin(), encSecret.end());

    SECURITY_STATUS status = NCryptSetProperty(
        _hAk, L"PCP_TPM12_IDACTIVATION", blob.data(), (DWORD)blob.size(), 0);
    if (FAILED(status)) {
        fprintf(stderr, "[pcp] SetProperty(PCP_TPM12_IDACTIVATION) failed: 0x%08X%s\n",
                status,
                status == 0x80280400 ? " (TPM_E_COMMAND_BLOCKED)" : "");
        return {};
    }

    DWORD cb = 0;
    status = NCryptGetProperty(_hAk, L"PCP_TPM12_IDACTIVATION", nullptr, 0, &cb, 0);
    if (FAILED(status) || cb == 0) {
        fprintf(stderr, "[pcp] GetProperty(PCP_TPM12_IDACTIVATION) size failed: 0x%08X\n", status);
        return {};
    }
    std::vector<uint8_t> secret(cb);
    status = NCryptGetProperty(_hAk, L"PCP_TPM12_IDACTIVATION",
                               secret.data(), cb, &cb, 0);
    if (FAILED(status)) {
        fprintf(stderr, "[pcp] GetProperty(PCP_TPM12_IDACTIVATION) read failed: 0x%08X\n", status);
        return {};
    }
    secret.resize(cb);
    return secret;
}

uint32_t TpmPcp::GetAkTpmHandle()
{
    if (!_hAk) return 0;
    uint32_t handle = 0;
    DWORD cb = 0;
    SECURITY_STATUS status = NCryptGetProperty(
        _hAk, L"PCP_PLATFORMHANDLE", (PBYTE)&handle, sizeof(handle), &cb, 0);
    if (FAILED(status) || cb != sizeof(handle)) {
        fprintf(stderr, "[pcp] GetProperty(PCP_PLATFORMHANDLE) failed: 0x%08X (cb=%u)\n",
                status, cb);
        return 0;
    }
    return handle;
}

} // namespace RootHerald
