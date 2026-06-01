/**
 * AMD fTPM EK certificate fetch via Authority Information Access (AIA).
 *
 * On AMD Ryzen platforms the firmware TPM does not ship its EK certificate
 * inside TPM NV; instead AMD hosts it at
 *   https://ftpm.amd.com/pki/aia/<sha256(EK modulus) hex>
 *
 * This helper hashes the EK RSA modulus, performs an HTTPS GET to that URL,
 * and returns the DER-encoded certificate body on HTTP 200 or an empty
 * vector otherwise.
 */

#ifndef ROOTHERALD_AMD_AIA_FETCH_H
#define ROOTHERALD_AMD_AIA_FETCH_H

#include <cstdint>
#include <vector>

namespace RootHerald {

// Extracts the RSA modulus from a Windows BCRYPT_RSAKEY_BLOB style EK pub
// blob (as emitted by NCrypt PCP_EKPUB) and returns it. Returns an empty
// vector if the blob is not a recognized BCRYPT RSA public blob.
std::vector<uint8_t> ExtractRsaModulusFromEkPub(const std::vector<uint8_t>& ekPubBlob);

// Fetches the AMD AIA EK certificate corresponding to the given RSA modulus.
// Returns DER-encoded cert on HTTP 200, empty vector on failure.
std::vector<uint8_t> FetchAmdAiaEkCert(const std::vector<uint8_t>& ekPubModulus);

} // namespace RootHerald

#endif // ROOTHERALD_AMD_AIA_FETCH_H
