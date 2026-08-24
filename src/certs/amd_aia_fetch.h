/*
 * AMD fTPM EK certificate lookup.
 *
 * An AMD Ryzen firmware TPM ships no EK certificate in NV; AMD hosts it at
 * https://ftpm.amd.com/pki/aia/<sha256(EK modulus) hex> instead. This is the
 * only outbound request the library makes, and it is best-effort.
 */

#pragma once

#include <cstdint>
#include <vector>

namespace RootHerald {

/* Slices the modulus out of a BCRYPT_RSAKEY_BLOB as emitted by NCrypt's
 * PCP_EKPUB property. Empty if the blob is not a recognised RSA public blob. */
std::vector<uint8_t> ExtractRsaModulusFromEkPub(const std::vector<uint8_t>& ekPubBlob);

/* DER-encoded certificate on HTTP 200, empty on anything else. */
std::vector<uint8_t> FetchAmdAiaEkCert(const std::vector<uint8_t>& ekPubModulus);

} // namespace RootHerald
