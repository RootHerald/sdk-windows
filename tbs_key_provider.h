/**
 * TbsKeyProvider — IAttestationKeyProvider backed by raw TPM 2.0 commands
 * over TBS. Credential activation uses TPM2_ActivateCredential directly,
 * which Windows TBS only permits for an elevated caller, so
 * RequiresElevationForActivate() is true. The AK is evicted to a persistent
 * handle so it survives reboots and is reachable from any TBS context (incl.
 * the unprivileged attestation process) for TPM2_Quote.
 */

#ifndef ROOTHERALD_TBS_KEY_PROVIDER_H
#define ROOTHERALD_TBS_KEY_PROVIDER_H

#include "attestation_key_provider.h"
#include "tpm_commands.h"

namespace RootHerald {

class TbsKeyProvider : public IAttestationKeyProvider {
public:
    explicit TbsKeyProvider(uint32_t persistentHandle)
        : _persistentHandle(persistentHandle) {}
    ~TbsKeyProvider() override;

    const char* ModeName() const override { return "tbs"; }
    bool RequiresElevationForActivate() const override { return true; }

    bool Open() override;
    void Close() override;

    bool AkExists() override;
    bool CreateAk() override;
    bool LoadAk() override;
    bool DeleteAk() override;
    std::vector<uint8_t> GetAkPublicArea() override;

    std::vector<uint8_t> ActivateCredential(
        const std::vector<uint8_t>& credentialBlob,
        const std::vector<uint8_t>& encryptedSecret) override;

    bool PersistAk() override;
    uint32_t GetQuoteHandle() override;

private:
    void FlushTransients();

    TpmCommands _tpm;
    uint32_t _persistentHandle;
    uint32_t _ekHandle = 0;       // transient, set by CreateAk
    uint32_t _akHandle = 0;       // transient, set by CreateAk
    std::vector<uint8_t> _akPubArea;
};

} // namespace RootHerald

#endif /* ROOTHERALD_TBS_KEY_PROVIDER_H */
