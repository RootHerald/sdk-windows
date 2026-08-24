/*
 * Attestation-key lifecycle and credential activation over raw TPM 2.0/TBS.
 *
 * ELEVATION: ActivateCredential requires an elevated process, so enrollment
 * runs under one UAC. The AK is then evicted to a persistent handle, which
 * survives reboots and is reachable from any TBS context — including an
 * unprivileged one — so attestation never elevates again.
 *
 * LIFETIME: CreateAk leaves transient EK and AK handles open in this object's
 * TBS context, and ActivateCredential needs them. The instance must therefore
 * outlive the relayed enroll round-trip; LoadAk cannot rebuild them.
 */

#pragma once

#include <windows.h>
#include <sal.h>
#include <cstdint>
#include <vector>

#include "tpm_commands.h"

namespace RootHerald {

class TbsKeyProvider {
public:
    explicit TbsKeyProvider(uint32_t persistentHandle)
        : _persistentHandle(persistentHandle) {}
    ~TbsKeyProvider();

    TbsKeyProvider(const TbsKeyProvider&) = delete;
    TbsKeyProvider& operator=(const TbsKeyProvider&) = delete;

    _Ret_z_ const char* ModeName() const { return "tbs"; }

    HRESULT Open();
    void Close();

    bool AkExists();

    /* Replaces any existing key. The new one is held open for the following
     * GetAkPublicArea / ActivateCredential / PersistAk calls. */
    HRESULT CreateAk();

    /* Confirms the persisted AK is present; the persistent handle needs no
     * transient slot, so there is nothing else to load. */
    HRESULT LoadAk();

    /* Drops transient handles left by a failed enrollment. Idempotent. The
     * persistent slot is not cleared: PersistAk overwrites it. */
    HRESULT DeleteAk();

    /* TPM2B_PUBLIC of the created AK, from which the server computes the AK
     * Name. Empty until CreateAk succeeds. */
    std::vector<uint8_t> GetAkPublicArea() const;

    /* credentialBlob and encryptedSecret are the server's MakeCredential
     * outputs, already TPM2B-framed. out_secret holds recovered TPM secret
     * material: clear it with SecureZeroMemory once consumed. */
    _Success_(return == S_OK)
    HRESULT ActivateCredential(const std::vector<uint8_t>& credentialBlob,
                               const std::vector<uint8_t>& encryptedSecret,
                               _Out_ std::vector<uint8_t>* out_secret);

    HRESULT PersistAk();

    /* The handle to feed TpmCommands::Quote — persistent, so it stays valid
     * across TBS contexts and processes. */
    uint32_t GetQuoteHandle() const;

private:
    void FlushTransients();

    TpmCommands _tpm;
    uint32_t _persistentHandle;
    uint32_t _ekHandle = 0;
    uint32_t _akHandle = 0;
    std::vector<uint8_t> _akPublicArea;
};

} // namespace RootHerald
