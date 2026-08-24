/**
 * TbsKeyProvider — the attestation key (AK) lifecycle and credential
 * activation, backed by raw TPM 2.0 commands over TBS. It is the only AK
 * backend on Windows, so it is a concrete class rather than an implementation
 * of an interface.
 *
 * Credential activation uses TPM2_ActivateCredential directly, which
 * Windows TBS only permits for an elevated caller, so enrollment runs under one
 * UAC. The AK is evicted to a persistent handle so it survives reboots and is
 * reachable from any TBS context (incl. the unprivileged attestation process)
 * for TPM2_Quote.
 */

#ifndef ROOTHERALD_TBS_KEY_PROVIDER_H
#define ROOTHERALD_TBS_KEY_PROVIDER_H

#include <cstdint>
#include <vector>

#include "tpm_commands.h"

namespace RootHerald {

class TbsKeyProvider {
public:
    explicit TbsKeyProvider(uint32_t persistentHandle)
        : _persistentHandle(persistentHandle) {}
    ~TbsKeyProvider();

    /// Short identifier ("tbs"), used for logging.
    const char* ModeName() const { return "tbs"; }

    /// Acquire the TBS context. False if the backend is unavailable.
    bool Open();
    void Close();

    /// True if a persisted AK already exists for this device.
    bool AkExists();

    /// Create a fresh attestation key, replacing any existing one. The new key
    /// is held open for the subsequent GetAkPublicArea / ActivateCredential /
    /// PersistAk calls.
    bool CreateAk();

    /// Open the already-persisted AK for attestation. False if absent.
    bool LoadAk();

    /// Drop the transient handles left by a failed enrollment. Idempotent.
    bool DeleteAk();

    /// The created AK's TPM2B_PUBLIC (size-prefixed), for the server to compute
    /// the AK Name. Empty on error.
    std::vector<uint8_t> GetAkPublicArea();

    /// Recover the credential secret from the server's MakeCredential output
    /// (full TPM2B_ID_OBJECT and TPM2B_ENCRYPTED_SECRET) via
    /// TPM2_ActivateCredential, which needs elevation. Empty on failure.
    std::vector<uint8_t> ActivateCredential(
        const std::vector<uint8_t>& credentialBlob,
        const std::vector<uint8_t>& encryptedSecret);

    /// Evict the freshly-activated AK to the persistent handle so future
    /// attestations can load it.
    bool PersistAk();

    /// The raw TPM handle to feed TpmCommands::Quote — the persistent handle,
    /// valid across TBS contexts.
    uint32_t GetQuoteHandle();

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
