/**
 * IAttestationKeyProvider — the attestation key (AK) lifecycle + credential
 * activation contract.
 *
 * The sole Windows backend is TbsKeyProvider (raw TPM 2.0 over TBS): the AK is
 * created with an RSASSA-SHA256 template, TPM2_ActivateCredential binds it to
 * the EK (which Windows TBS permits only for an *elevated* caller, so enrollment
 * runs under one UAC), and the AK is evicted to a persistent handle so later
 * TPM2_Quote runs unprivileged. The interface is retained as a thin seam for the
 * per-platform backends (macOS Secure Enclave, etc.) that will implement the
 * same contract; the enroll / attest flows are written once against it.
 */

#ifndef ROOTHERALD_ATTESTATION_KEY_PROVIDER_H
#define ROOTHERALD_ATTESTATION_KEY_PROVIDER_H

#include <cstdint>
#include <vector>

namespace RootHerald {

class IAttestationKeyProvider {
public:
    virtual ~IAttestationKeyProvider() = default;

    /// Short identifier ("tbs"), used for logging.
    virtual const char* ModeName() const = 0;

    /// Acquire backend resources (open the provider / TBS context). Returns
    /// false if the backend is unavailable.
    virtual bool Open() = 0;
    virtual void Close() = 0;

    // --- AK lifecycle ---

    /// True if a persisted AK already exists for this provider/device.
    virtual bool AkExists() = 0;

    /// Create a fresh attestation key, replacing any existing one. Used for
    /// first enrollment and for key rotation. The new key is held open for
    /// the subsequent GetAkPublicArea / ActivateCredential / PersistAk calls.
    virtual bool CreateAk() = 0;

    /// Open the already-persisted AK for attestation. Returns false if absent.
    virtual bool LoadAk() = 0;

    /// Remove the persisted AK (used to clean up a failed enrollment before
    /// falling back to another mode). Idempotent.
    virtual bool DeleteAk() = 0;

    /// The created/loaded AK's TPM2B_PUBLIC (size-prefixed), for the server to
    /// compute the AK Name. Empty on error.
    virtual std::vector<uint8_t> GetAkPublicArea() = 0;

    // --- Credential activation (the mode-defining operation) ---

    /// Recover the credential secret from the server's MakeCredential output
    /// (full TPM2B_ID_OBJECT and TPM2B_ENCRYPTED_SECRET). Empty on failure.
    /// For TBS this is TPM2_ActivateCredential (needs elevation); for PCP it
    /// is NCRYPT_PCP_TPM12_IDACTIVATION.
    virtual std::vector<uint8_t> ActivateCredential(
        const std::vector<uint8_t>& credentialBlob,
        const std::vector<uint8_t>& encryptedSecret) = 0;

    /// Persist the freshly-activated AK so future attestations can load it.
    /// PCP persists by key name (no-op here); TBS evicts to a persistent
    /// handle. Returns true on success.
    virtual bool PersistAk() = 0;

    // --- Quote support ---

    /// The raw TPM handle to feed TpmCommands::Quote for the loaded AK. For
    /// TBS this is the persistent handle (valid across TBS contexts); for PCP
    /// it is the PCP_PLATFORMHANDLE of the loaded key. 0 on failure.
    virtual uint32_t GetQuoteHandle() = 0;
};

} // namespace RootHerald

#endif /* ROOTHERALD_ATTESTATION_KEY_PROVIDER_H */
