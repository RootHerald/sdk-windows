/**
 * IAttestationKeyProvider — a mode-agnostic strategy for the attestation
 * key (AK) lifecycle and credential activation.
 *
 * Windows has two viable backends for the same underlying service:
 *
 *   - PCP   (Microsoft Platform Crypto Provider, via NCrypt): runs entirely
 *           unprivileged. Credential activation goes through
 *           PCP_TPM12_IDACTIVATION. Works on firmwares where PCP cooperates.
 *
 *   - TBS   (raw TPM 2.0 command marshaling): credential activation uses
 *           TPM2_ActivateCredential directly, which Windows TBS only permits
 *           for an *elevated* caller. Works everywhere, but the activation
 *           step needs admin.
 *
 * Both backends provide the identical service contract below, so the
 * enrollment / attestation / rotation flows are written once against this
 * interface and the concrete backend is selected at run time (PCP-first,
 * elevated-TBS fallback). Callers must never branch on the concrete type —
 * only on the capability flags exposed here.
 */

#ifndef ROOTHERALD_ATTESTATION_KEY_PROVIDER_H
#define ROOTHERALD_ATTESTATION_KEY_PROVIDER_H

#include <cstdint>
#include <vector>

namespace RootHerald {

class IAttestationKeyProvider {
public:
    virtual ~IAttestationKeyProvider() = default;

    /// Short identifier ("pcp" / "tbs"), used for logging and for caching the
    /// winning method per machine. Stable — used as a persisted cache key.
    virtual const char* ModeName() const = 0;

    /// True if ActivateCredential() requires the process to be elevated.
    /// Drives the PCP-first / elevated-fallback orchestration.
    virtual bool RequiresElevationForActivate() const = 0;

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
