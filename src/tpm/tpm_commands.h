/*
 * Raw TPM 2.0 command marshaling over TBS.
 *
 * Builds TPM command byte streams by hand and submits them through
 * Tbsip_Submit_Command, which avoids vendoring TSS.CPP for the handful of
 * operations the attestation flow needs.
 *
 * ELEVATION: TPM2_ActivateCredential is blocked by TBS for a non-elevated
 * caller (TPM_E_COMMAND_BLOCKED). Every other command here is unprivileged.
 */

#pragma once

#include <windows.h>
#include <tbs.h>
#include <sal.h>
#include <vector>
#include <cstdint>

#include "unique_handle.h"

namespace RootHerald {

class TpmCommands {
public:
    TpmCommands() = default;
    ~TpmCommands() = default;

    TpmCommands(const TpmCommands&) = delete;
    TpmCommands& operator=(const TpmCommands&) = delete;

    HRESULT Open();
    void Close();

    /* Creates a restricted signing key as a primary under parentHandle. The
     * handle is transient: flush it or evict it before dropping the context. */
    _Success_(return == S_OK)
    HRESULT CreateAndLoadAk(uint32_t parentHandle,
                            _Out_ uint32_t* out_handle,
                            _Out_opt_ std::vector<uint8_t>* out_publicArea);

    /* Transient EK under the endorsement hierarchy, deterministic and matching
     * PCP_EKPUB, so the seed the server sealed to PCP_EKPUB decrypts here. */
    _Success_(return == S_OK)
    HRESULT CreateEk(_Out_ uint32_t* out_handle);

    _Success_(return == S_OK)
    HRESULT Quote(uint32_t akHandle,
                  const std::vector<uint8_t>& nonce,
                  const std::vector<uint32_t>& pcrIndices,
                  _Out_ std::vector<uint8_t>* out_quoted,
                  _Out_ std::vector<uint8_t>* out_signature);

    /* SHA-256 bank. */
    _Success_(return == S_OK)
    HRESULT PcrRead(uint32_t pcrIndex, _Out_ std::vector<uint8_t>* out_digest);

    /* out_secret holds recovered TPM secret material: clear it with
     * SecureZeroMemory once it has been consumed. */
    _Success_(return == S_OK)
    HRESULT ActivateCredential(uint32_t akHandle,
                               uint32_t ekHandle,
                               const std::vector<uint8_t>& credentialBlob,
                               const std::vector<uint8_t>& encryptedSecret,
                               _Out_ std::vector<uint8_t>* out_secret);

    HRESULT FlushContext(uint32_t handle);

    /* persistentHandle must be in the owner persistent range
     * 0x81000000-0x817FFFFF. An occupied slot is cleared first. */
    HRESULT EvictControl(uint32_t transientHandle, uint32_t persistentHandle);

    bool IsPersistentPresent(uint32_t persistentHandle);

    /* nvIndex must be a defined NV handle (0x01xxxxxx). */
    _Success_(return == S_OK)
    HRESULT ReadNvCertificate(uint32_t nvIndex, _Out_ std::vector<uint8_t>* out_certificate);

    /* Appends every DER certificate present in the Intel PTT on-die CA range
     * 0x01C00100..0x01C0010F, in NV-handle order. Undefined handles are skipped,
     * which is why an absent chain is not reported as a failure. */
    void ReadIntelOdcaIntermediates(_Inout_ std::vector<std::vector<uint8_t>>* certificates);

private:
    _Success_(return == S_OK)
    HRESULT SendCommand(_Inout_ std::vector<uint8_t>* command,
                        _Out_ std::vector<uint8_t>* out_response);

    UniqueTbsContext _context;
};

} // namespace RootHerald
