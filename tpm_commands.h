/**
 * Raw TPM 2.0 command marshaling via TBS (TPM Base Services).
 *
 * Builds TPM command byte streams and submits them through
 * Tbsip_Submit_Command, covering the operations the attestation flow needs:
 * EK/AK creation, credential activation, persistence, Quote, PCR and NV reads.
 * Doing the marshaling by hand avoids vendoring TSS.CPP.
 */

#ifndef ROOTHERALD_TPM_COMMANDS_H
#define ROOTHERALD_TPM_COMMANDS_H

#include <windows.h>
#include <tbs.h>
#include <vector>
#include <cstdint>

namespace RootHerald {

class TpmCommands {
public:
    TpmCommands();
    ~TpmCommands();

    bool Open();
    void Close();

    /// Create and load an attestation key under a parent.
    /// If outPublicKey is provided, fills it with the TPM2B_PUBLIC of the created key.
    uint32_t CreateAndLoadAk(uint32_t parentHandle, std::vector<uint8_t>* outPublicKey = nullptr);

    /// Generate a TPM2_Quote: returns the serialized TPMS_ATTEST and TPMT_SIGNATURE.
    bool Quote(uint32_t akHandle,
               const std::vector<uint8_t>& nonce,
               const std::vector<uint32_t>& pcrIndices,
               std::vector<uint8_t>& outQuoted,
               std::vector<uint8_t>& outSignature);

    /// Read PCR values (SHA-256 bank).
    std::vector<uint8_t> PcrRead(uint32_t pcrIndex);

    /// Create an EK (Endorsement Key) and return the handle.
    uint32_t CreateEk();

    /// Activate a credential: proves AK is on the same TPM as EK.
    /// Takes the server's MakeCredential outputs and returns the decrypted secret.
    std::vector<uint8_t> ActivateCredential(
        uint32_t akHandle, uint32_t ekHandle,
        const std::vector<uint8_t>& credentialBlob,
        const std::vector<uint8_t>& encryptedSecret);

    /// Flush a transient handle.
    void FlushContext(uint32_t handle);

    /// Evicts a transient handle to a persistent handle in the OWNER hierarchy.
    /// Use persistentHandle in range 0x81000000-0x817FFFFF (owner persistent).
    /// If a key already lives at persistentHandle, it is cleared first.
    /// Returns true on success.
    bool EvictControl(uint32_t transientHandle, uint32_t persistentHandle);

    /// True if the persistent handle is populated.
    bool IsPersistentPresent(uint32_t persistentHandle);

    /// Reads an NV-stored certificate (TPM2_NV_ReadPublic + TPM2_NV_Read).
    /// `nvIndex` must be a defined NV handle (range 0x01xxxxxx). On success
    /// fills `outCert` with the NV contents and returns true. Returns false
    /// if the index is undefined or the read fails for any other reason.
    bool ReadNvCertificate(uint32_t nvIndex, std::vector<uint8_t>& outCert);

    /// Iterates the standard Intel PTT ODCA intermediate CA NV range
    /// (0x01C00100 .. 0x01C0010F — RSA chain) and appends each present
    /// DER-encoded certificate to `outCerts`, in NV-handle order. Empty
    /// (undefined) handles are skipped silently.
    void ReadIntelOdcaIntermediates(std::vector<std::vector<uint8_t>>& outCerts);

private:
    TBS_HCONTEXT _hContext = 0;
    bool _isOpen = false;

    std::vector<uint8_t> SendCommand(std::vector<uint8_t>& cmd);
};

} // namespace RootHerald

#endif /* ROOTHERALD_TPM_COMMANDS_H */
