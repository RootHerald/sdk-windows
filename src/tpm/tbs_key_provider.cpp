#include "tbs_key_provider.h"

#include "log.h"
#include "win_status.h"

namespace RootHerald {

namespace {
constexpr uint32_t TPM_RH_OWNER = 0x40000001u;
}

TbsKeyProvider::~TbsKeyProvider() { Close(); }

HRESULT TbsKeyProvider::Open() { return _tpm.Open(); }

void TbsKeyProvider::FlushTransients()
{
    if (_akHandle) {
        HRESULT hr = _tpm.FlushContext(_akHandle);
        if (FAILED(hr)) RH_LOG_DEBUG("[tbs] FlushContext(AK): 0x%08X\n", (unsigned)hr);
        _akHandle = 0;
    }
    if (_ekHandle) {
        HRESULT hr = _tpm.FlushContext(_ekHandle);
        if (FAILED(hr)) RH_LOG_DEBUG("[tbs] FlushContext(EK): 0x%08X\n", (unsigned)hr);
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
        RH_LOG_WARN("[tbs] CreateEk failed: 0x%08X\n", (unsigned)hr);
        return FAILED(hr) ? hr : E_FAIL;
    }

    hr = _tpm.CreateAndLoadAk(TPM_RH_OWNER, &_akHandle, &_akPublicArea);
    if (FAILED(hr) || !_akHandle || _akPublicArea.empty()) {
        RH_LOG_WARN("[tbs] CreateAndLoadAk failed: 0x%08X\n", (unsigned)hr);
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
        RH_LOG_WARN("[tbs] ActivateCredential called before CreateAk\n");
        return RH_E_NOT_OPEN;
    }
    return _tpm.ActivateCredential(_akHandle, _ekHandle, credentialBlob, encryptedSecret, out_secret);
}

HRESULT TbsKeyProvider::PersistAk()
{
    if (!_akHandle) return RH_E_NOT_OPEN;

    HRESULT hr = _tpm.EvictControl(_akHandle, _persistentHandle);
    if (FAILED(hr)) {
        RH_LOG_WARN("[tbs] EvictControl(AK -> 0x%08X) failed: 0x%08X\n",
                    _persistentHandle, (unsigned)hr);
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
