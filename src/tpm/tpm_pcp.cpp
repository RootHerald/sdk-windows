#include "tpm_pcp.h"

#include "win_status.h"

namespace RootHerald {

namespace {
constexpr PCWSTR PCP_PROVIDER = L"Microsoft Platform Crypto Provider";
}

bool TpmPcp::IsAvailable() const
{
    UniqueNcryptProvider probe;
    SECURITY_STATUS status = NCryptOpenStorageProvider(probe.Put(), PCP_PROVIDER, 0);
    if (FAILED(status)) {
        return false;
    }
    return true;
}

HRESULT TpmPcp::Open()
{
    if (_provider) return S_OK;

    SECURITY_STATUS status = NCryptOpenStorageProvider(_provider.Put(), PCP_PROVIDER, 0);
    if (FAILED(status)) {
        return HrFromSecurityStatus(status);
    }
    return S_OK;
}

void TpmPcp::Close()
{
    _provider.Reset();
}

_Use_decl_annotations_
HRESULT TpmPcp::ReadProperty(PCWSTR property, std::vector<uint8_t>* out_value)
{
    out_value->clear();
    if (!_provider) return RH_E_NOT_OPEN;

    DWORD size = 0;
    SECURITY_STATUS status =
        NCryptGetProperty(_provider.Get(), property, nullptr, 0, &size, 0);
    if (FAILED(status)) {
        return HrFromSecurityStatus(status);
    }
    if (size == 0) return RH_E_MALFORMED_RESPONSE;

    std::vector<uint8_t> value(size);
    status = NCryptGetProperty(_provider.Get(), property, value.data(), size, &size, 0);
    if (FAILED(status)) {
        return HrFromSecurityStatus(status);
    }

    value.resize(size);
    *out_value = std::move(value);
    return S_OK;
}

_Use_decl_annotations_
HRESULT TpmPcp::ReadEkCertificate(std::vector<uint8_t>* out_certificate)
{
    return ReadProperty(L"PCP_RSA_EKNVCERT", out_certificate);
}

_Use_decl_annotations_
HRESULT TpmPcp::ReadEkPublicKey(std::vector<uint8_t>* out_publicKey)
{
    return ReadProperty(L"PCP_EKPUB", out_publicKey);
}

} // namespace RootHerald
