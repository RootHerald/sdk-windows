/**
 * NCrypt Platform Crypto Provider wrapper for TPM 2.0 operations.
 *
 * The Windows attestation key (AK) is managed entirely through PCP:
 * creation, credential activation, and persistence are all NCrypt calls.
 * This is mandatory on Windows because TBS blocks raw
 * TPM2_ActivateCredential for user-mode callers (TPM_E_COMMAND_BLOCKED,
 * 0x80280400); PCP brokers that command through a privileged path.
 *
 * The raw-TBS path in `TpmCommands` is still used for PCR reads and
 * TPM2_Quote — those commands are on the user-mode allow-list. The AK's
 * underlying TPM handle is recovered from PCP via PCP_PLATFORMHANDLE and
 * handed to TpmCommands::Quote, so the quote is bound to the same AK the
 * server activated.
 */

#ifndef ROOTHERALD_TPM_PCP_H
#define ROOTHERALD_TPM_PCP_H

#include <windows.h>
#include <ncrypt.h>
#include <vector>
#include <string>
#include <cstdint>

namespace RootHerald {

class TpmPcp {
public:
    TpmPcp();
    ~TpmPcp();

    bool IsAvailable() const;
    bool Open();
    void Close();

    // EK operations (NCrypt is fine for cert/pub extraction)
    std::vector<uint8_t> ReadEkCertificate();
    std::vector<uint8_t> ReadEkPublicKey();

    // --- Attestation key (AK) lifecycle, all PCP-managed ---

    /// True if a persisted PCP AK with the given name already exists.
    bool AkExists(const wchar_t* keyName);

    /// Create a fresh PCP attestation key (restricted RSA-2048 signing,
    /// PCP_KEY_USAGE_POLICY = identity). Overwrites any existing key of
    /// the same name. On success the key is finalized and held open
    /// internally for subsequent GetAkPublicArea / ActivateCredential /
    /// GetAkTpmHandle calls. Returns true on success.
    bool CreateAk(const wchar_t* keyName);

    /// Open an already-persisted PCP AK by name and hold it open
    /// internally. Returns false if the key does not exist.
    bool LoadAk(const wchar_t* keyName);

    /// Delete the persisted PCP AK by name. Returns true on success or if
    /// the key did not exist.
    bool DeleteAk(const wchar_t* keyName);

    /// Return the loaded AK's TPM2B_PUBLIC (size-prefixed), extracted from
    /// the PCP_TPM12_IDBINDING property. This is the exact public area the
    /// TPM uses to compute the AK Name, so the server-computed Name will
    /// match what the TPM expects during ActivateCredential. Empty on error.
    std::vector<uint8_t> GetAkPublicArea();

    /// Perform credential activation through PCP. Takes the server's
    /// MakeCredential outputs (full TPM2B_ID_OBJECT and
    /// TPM2B_ENCRYPTED_SECRET, size-prefixed) and returns the decrypted
    /// 32-byte secret. Empty on failure. Internally this concatenates the
    /// two blobs and round-trips them through
    /// NCRYPT_PCP_TPM12_IDACTIVATION (set + get).
    std::vector<uint8_t> ActivateCredential(const std::vector<uint8_t>& credBlob,
                                            const std::vector<uint8_t>& encSecret);

    /// Recover the raw TPM (TBS) handle for the loaded AK via
    /// PCP_PLATFORMHANDLE, for use with TpmCommands::Quote. 0 on failure.
    uint32_t GetAkTpmHandle();

private:
    NCRYPT_PROV_HANDLE _hProvider = 0;
    NCRYPT_KEY_HANDLE _hAk = 0;
    bool _isOpen = false;

    void CloseAk();
};

} // namespace RootHerald

#endif /* ROOTHERALD_TPM_PCP_H */
