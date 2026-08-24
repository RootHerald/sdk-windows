/**
 * NCrypt Platform Crypto Provider wrapper — EK reads. See tpm_pcp.h.
 */

#include "tpm_pcp.h"
#include <winerror.h>

// PCP provider name
static const wchar_t* PCP_PROVIDER = L"Microsoft Platform Crypto Provider";

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

void TpmPcp::Close()
{
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

} // namespace RootHerald
