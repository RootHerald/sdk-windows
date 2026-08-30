#include "tbs_key_provider.h"

#include "win_status.h"

namespace RootHerald {

namespace {
constexpr uint32_t TPM_RH_OWNER = 0x40000001u;
}

TbsKeyProvider::~TbsKeyProvider() { Close(); }

HRESULT TbsKeyProvider::Open() { return _tpm.Open(); }

void TbsKeyProvider::FlushTransients()
{
    /* Best-effort on both. A failed flush leaks a transient handle until the
     * TPM context is torn down, and there is nothing a caller could do about
     * it — which is why the only handling this ever had was a debug log. */
    if (_akHandle) {
        (void)_tpm.FlushContext(_akHandle);
        _akHandle = 0;
    }
    if (_ekHandle) {
        (void)_tpm.FlushContext(_ekHandle);
        _ekHandle = 0;
    }
}

void TbsKeyProvider::Close()
{
    FlushTransients();
    _tpm.Close();
}

bool TbsKeyProvider::AkExists()
{
    return _tpm.IsPersistentPresent(_persistentHandle);
}

HRESULT TbsKeyProvider::CreateAk()
{
    FlushTransients();
    _akPublicArea.clear();

    // The EK is the decrypt key for activation: its key is deterministic and
    // matches PCP_EKPUB, so a seed the server sealed to PCP_EKPUB opens here.
    HRESULT hr = _tpm.CreateEk(&_ekHandle);
    if (FAILED(hr) || !_ekHandle) {
        return FAILED(hr) ? hr : E_FAIL;
    }

    hr = _tpm.CreateAndLoadAk(TPM_RH_OWNER, &_akHandle, &_akPublicArea);
    if (FAILED(hr) || !_akHandle || _akPublicArea.empty()) {
        FlushTransients();
        return FAILED(hr) ? hr : E_FAIL;
    }
    return S_OK;
}

HRESULT TbsKeyProvider::LoadAk()
{
    return _tpm.IsPersistentPresent(_persistentHandle) ? S_OK : E_FAIL;
}

HRESULT TbsKeyProvider::DeleteAk()
{
    FlushTransients();
    return S_OK;
}

std::vector<uint8_t> TbsKeyProvider::GetAkPublicArea() const
{
    return _akPublicArea;
}

_Use_decl_annotations_
HRESULT TbsKeyProvider::ActivateCredential(const std::vector<uint8_t>& credentialBlob,
                                           const std::vector<uint8_t>& encryptedSecret,
                                           std::vector<uint8_t>* out_secret)
{
    out_secret->clear();
    if (!_akHandle || !_ekHandle) {
        return RH_E_NOT_OPEN;
    }
    return _tpm.ActivateCredential(_akHandle, _ekHandle, credentialBlob, encryptedSecret, out_secret);
}

HRESULT TbsKeyProvider::PersistAk()
{
    if (!_akHandle) return RH_E_NOT_OPEN;

    HRESULT hr = _tpm.EvictControl(_akHandle, _persistentHandle);
    if (FAILED(hr)) {
        return hr;
    }

    // Quote uses the persistent handle from here on, so the transients are dead.
    FlushTransients();
    return S_OK;
}

uint32_t TbsKeyProvider::GetQuoteHandle() const
{
    return _persistentHandle;
}

} // namespace RootHerald
