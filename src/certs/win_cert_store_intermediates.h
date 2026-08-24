/*
 * Vendor TPM intermediate CA certs that Windows caches when it validates the
 * TPM cert chain itself. Vendor-agnostic, so it complements the Intel-specific
 * NV reads in TpmCommands::ReadIntelOdcaIntermediates.
 *
 *   HKLM\SYSTEM\CurrentControlSet\Services\TPM\WMI\Endorsement\
 *     IntermediateCACertStore\Certificates\<sha1-thumbprint>\Blob
 */

#pragma once

#include <cstdint>
#include <vector>

namespace RootHerald {

/* DER-encoded CA certs. Empty is the normal case, not an error: a freshly
 * imaged machine has no cached chain yet. The server remains the authority on
 * chain validation, so the filtering here only drops obvious non-CA junk. */
std::vector<std::vector<uint8_t>> ReadWindowsTpmIntermediateStore();

} // namespace RootHerald
