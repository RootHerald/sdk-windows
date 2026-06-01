/**
 * PcpKeyProvider — IAttestationKeyProvider backed by the Microsoft Platform
 * Crypto Provider (NCrypt). Fully unprivileged. Credential activation uses
 * NCRYPT_PCP_TPM12_IDACTIVATION; the quote handle comes from
 * PCP_PLATFORMHANDLE. See tpm_pcp.h for the low-level wrapper.
 */

#ifndef ROOTHERALD_PCP_KEY_PROVIDER_H
#define ROOTHERALD_PCP_KEY_PROVIDER_H

#include "attestation_key_provider.h"
#include "tpm_pcp.h"

namespace RootHerald {

class PcpKeyProvider : public IAttestationKeyProvider {
public:
    explicit PcpKeyProvider(const wchar_t* keyName) : _keyName(keyName) {}

    const char* ModeName() const override { return "pcp"; }
    bool RequiresElevationForActivate() const override { return false; }

    bool Open() override { return _pcp.Open(); }
    void Close() override { _pcp.Close(); }

    bool AkExists() override { return _pcp.AkExists(_keyName); }
    bool CreateAk() override { return _pcp.CreateAk(_keyName); }
    bool LoadAk() override { return _pcp.LoadAk(_keyName); }
    bool DeleteAk() override { return _pcp.DeleteAk(_keyName); }
    std::vector<uint8_t> GetAkPublicArea() override { return _pcp.GetAkPublicArea(); }

    std::vector<uint8_t> ActivateCredential(
        const std::vector<uint8_t>& credentialBlob,
        const std::vector<uint8_t>& encryptedSecret) override
    {
        return _pcp.ActivateCredential(credentialBlob, encryptedSecret);
    }

    // PCP persists the key by name as part of CreateAk/Finalize — nothing to do.
    bool PersistAk() override { return true; }

    uint32_t GetQuoteHandle() override { return _pcp.GetAkTpmHandle(); }

private:
    TpmPcp _pcp;
    const wchar_t* _keyName;
};

} // namespace RootHerald

#endif /* ROOTHERALD_PCP_KEY_PROVIDER_H */
