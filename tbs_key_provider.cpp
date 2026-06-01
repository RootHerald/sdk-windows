/**
 * TbsKeyProvider implementation. See tbs_key_provider.h.
 */

#include "tbs_key_provider.h"
#include <cstdio>

namespace RootHerald {

static constexpr uint32_t kTpmRhOwner = 0x40000001u;

TbsKeyProvider::~TbsKeyProvider() { Close(); }

bool TbsKeyProvider::Open() { return _tpm.Open(); }

void TbsKeyProvider::FlushTransients()
{
    if (_akHandle) { _tpm.FlushContext(_akHandle); _akHandle = 0; }
    if (_ekHandle) { _tpm.FlushContext(_ekHandle); _ekHandle = 0; }
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

bool TbsKeyProvider::CreateAk()
{
    FlushTransients();
    _akPubArea.clear();

    // EK (transient, L-1 template) — used as the decrypt key for activation.
    // Its key is deterministic and matches PCP_EKPUB, so the server can
    // encrypt the seed to PCP_EKPUB and this handle will decrypt it.
    _ekHandle = _tpm.CreateEk();
    if (!_ekHandle) {
        fprintf(stderr, "[tbs] CreateEk failed\n");
        return false;
    }

    // AK (transient, restricted RSA signing key under the owner hierarchy).
    _akHandle = _tpm.CreateAndLoadAk(kTpmRhOwner, &_akPubArea);
    if (!_akHandle || _akPubArea.empty()) {
        fprintf(stderr, "[tbs] CreateAndLoadAk failed\n");
        FlushTransients();
        return false;
    }
    return true;
}

bool TbsKeyProvider::LoadAk()
{
    // The AK lives at the persistent handle; nothing to load into a transient
    // slot. Presence at the handle is sufficient for Quote.
    return _tpm.IsPersistentPresent(_persistentHandle);
}

bool TbsKeyProvider::DeleteAk()
{
    // Drop any transient handles. The persistent slot is overwritten on the
    // next PersistAk (EvictControl clears an occupied slot first), so a stale
    // persistent AK does not block a fresh enrollment / rotation.
    FlushTransients();
    return true;
}

std::vector<uint8_t> TbsKeyProvider::GetAkPublicArea()
{
    return _akPubArea;
}

std::vector<uint8_t> TbsKeyProvider::ActivateCredential(
    const std::vector<uint8_t>& credentialBlob,
    const std::vector<uint8_t>& encryptedSecret)
{
    if (!_akHandle || !_ekHandle) {
        fprintf(stderr, "[tbs] ActivateCredential called before CreateAk\n");
        return {};
    }
    return _tpm.ActivateCredential(_akHandle, _ekHandle, credentialBlob, encryptedSecret);
}

bool TbsKeyProvider::PersistAk()
{
    if (!_akHandle) return false;
    if (!_tpm.EvictControl(_akHandle, _persistentHandle)) {
        fprintf(stderr, "[tbs] EvictControl(AK -> 0x%08X) failed\n", _persistentHandle);
        return false;
    }
    // The persistent copy is now the durable AK; transients are no longer
    // needed (and Quote uses the persistent handle, valid across contexts).
    FlushTransients();
    return true;
}

uint32_t TbsKeyProvider::GetQuoteHandle()
{
    return _persistentHandle;
}

} // namespace RootHerald
