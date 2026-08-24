/*
 * NCrypt Platform Crypto Provider — endorsement key reads only.
 *
 * The AK deliberately lives in TbsKeyProvider instead: PCP's AIK is locked to
 * an RSASSA-SHA1 scheme and its quote handle is bound to PCP's own TBS context.
 * What PCP is still right for is the EK public key and the NV EK certificate —
 * both unprivileged reads, and PCP_EKPUB is the exact blob the server encrypts
 * the activation seed to.
 */

#pragma once

#include <windows.h>
#include <ncrypt.h>
#include <sal.h>
#include <vector>
#include <cstdint>

#include "unique_handle.h"

namespace RootHerald {

class TpmPcp {
public:
    TpmPcp() = default;
    ~TpmPcp() = default;

    TpmPcp(const TpmPcp&) = delete;
    TpmPcp& operator=(const TpmPcp&) = delete;

    bool IsAvailable() const;

    HRESULT Open();
    void Close();

    _Success_(return == S_OK)
    HRESULT ReadEkCertificate(_Out_ std::vector<uint8_t>* out_certificate);

    _Success_(return == S_OK)
    HRESULT ReadEkPublicKey(_Out_ std::vector<uint8_t>* out_publicKey);

private:
    _Success_(return == S_OK)
    HRESULT ReadProperty(_In_z_ PCWSTR property, _Out_ std::vector<uint8_t>* out_value);

    UniqueNcryptProvider _provider;
};

} // namespace RootHerald
