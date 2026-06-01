/**
 * Windows TPM Intermediate CA Certificate Store reader.
 *
 * Windows caches vendor TPM intermediate CA certs (Infineon, STMicro, Nuvoton,
 * AMD fTPM, etc.) in the registry when it performs its own TPM cert chain
 * validation. Reading them gives us a vendor-agnostic source of EK chain
 * intermediates that complements the Intel-specific NV-handle reads in
 * TpmCommands::ReadIntelOdcaIntermediates.
 *
 * Registry path:
 *   HKLM\SYSTEM\CurrentControlSet\Services\TPM\WMI\Endorsement\
 *     IntermediateCACertStore\Certificates\<sha1-thumbprint>\Blob
 *
 * The `Blob` value is REG_BINARY and (in practice) holds the raw DER-encoded
 * X.509 certificate.
 */

#ifndef ROOTHERALD_WIN_CERT_STORE_INTERMEDIATES_H
#define ROOTHERALD_WIN_CERT_STORE_INTERMEDIATES_H

#include <cstdint>
#include <vector>

namespace RootHerald {

/// Read all CA certs from the Windows TPM IntermediateCACertStore registry.
///
/// Returns DER-encoded certificate blobs. Filters out anything that does not
/// parse as a valid X.509 cert or that lacks BasicConstraints CA:TRUE.
///
/// Returns an empty vector (NOT an error) if the registry key is missing or
/// the store is empty — this is the normal case on a freshly imaged machine
/// or where Windows has not yet performed TPM chain validation.
std::vector<std::vector<uint8_t>> ReadWindowsTpmIntermediateStore();

} // namespace RootHerald

#endif /* ROOTHERALD_WIN_CERT_STORE_INTERMEDIATES_H */
