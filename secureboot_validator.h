/**
 * Secure Boot Chain Validator
 *
 * Parses EFI Secure Boot variable data from PCR[7] event log entries
 * to extract and validate the complete Secure Boot certificate chain:
 * - PK (Platform Key): OEM identity
 * - KEK (Key Exchange Key): Microsoft + OEM control
 * - db (Allowed Signatures): Microsoft UEFI CA
 * - dbx (Forbidden Signatures): Revocation list
 *
 * Validates that the chain is legitimate by checking certificate
 * thumbprints against known Microsoft and OEM certificates.
 */

#ifndef ROOTHERALD_SECUREBOOT_VALIDATOR_H
#define ROOTHERALD_SECUREBOOT_VALIDATOR_H

#include <cstdint>
#include <string>
#include <vector>

namespace RootHerald {

struct CertInfo {
    std::string subject;
    std::string issuer;
    std::string thumbprintSha256; // Hex uppercase
    std::string notBefore;
    std::string notAfter;
    bool isMicrosoftCert = false;
    bool isKnownOem = false;
    std::string oemName; // If identified
};

struct SecureBootChainReport {
    bool secureBootEnabled = false;

    // PK (Platform Key) — should be OEM
    std::vector<CertInfo> pkCerts;
    bool pkIsKnownOem = false;
    std::string pkOemName;

    // KEK (Key Exchange Key) — should include Microsoft
    std::vector<CertInfo> kekCerts;
    bool kekHasMicrosoft = false;

    // db (Allowed Signatures Database) — must include Microsoft UEFI CA
    std::vector<CertInfo> dbCerts;
    bool dbHasMicrosoftUefiCa2011 = false;
    bool dbHasMicrosoftUefiCa2023 = false;
    bool dbHasWindowsPca2011 = false;

    // dbx (Forbidden Signatures) — revocation list
    int dbxHashCount = 0;

    // Overall
    bool chainValid = false;
    std::string verdict;
    std::vector<std::string> warnings;
    std::vector<std::string> errors;
};

/// Parse EFI variable event data and extract certificate information.
/// The eventData is from a PCR[7] EV_EFI_VARIABLE_DRIVER_CONFIG event.
/// Format: EFI_GUID(16) + UnicodeNameLength(8) + VariableDataLength(8) +
///         UnicodeName(UnicodeNameLength*2) + VariableData
std::vector<CertInfo> ParseEfiSignatureList(const std::vector<uint8_t>& variableData);

/// Validate the complete Secure Boot chain from event log entries.
SecureBootChainReport ValidateSecureBootChain(
    const std::vector<uint8_t>& rawEventLog);

} // namespace RootHerald

#endif /* ROOTHERALD_SECUREBOOT_VALIDATOR_H */
