/**
 * NCrypt Platform Crypto Provider wrapper — endorsement key reads only.
 *
 * The attestation key is NOT managed here. Enrollment creates, activates and
 * persists the AK with raw TPM 2.0 commands over TBS (see TbsKeyProvider),
 * which works because the enrolling process is elevated; the PCP AK backend
 * that once mirrored it was removed once raw-TBS activation was proven, as
 * PCP's AIK is locked to a SHA-1 signing scheme and its quote handle is bound
 * to PCP's own TBS context.
 *
 * What PCP is still the right tool for is reading the EK public key and the
 * NV EK certificate: both are unprivileged reads, and PCP_EKPUB is the exact
 * blob the server encrypts the activation seed to.
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

private:
    NCRYPT_PROV_HANDLE _hProvider = 0;
    bool _isOpen = false;
};

} // namespace RootHerald

#endif /* ROOTHERALD_TPM_PCP_H */
