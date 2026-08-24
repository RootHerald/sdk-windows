/*
 * Extracts the Secure Boot certificate chain (PK / KEK / db / dbx) from the
 * PCR[7] EFI variable events and checks it against known Microsoft and OEM
 * certificates.
 *
 * Advisory only. The server re-derives boot posture from the quote-bound event
 * log and never gates on the report produced here.
 */

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace RootHerald {

struct CertInfo {
    std::string subject;
    std::string issuer;
    std::string thumbprintSha256;   // SHA-256 of the DER, hex uppercase
    std::string notBefore;
    std::string notAfter;
    bool isMicrosoftCert = false;
    bool isKnownOem = false;
    std::string oemName;            // empty unless isKnownOem
};

struct SecureBootChainReport {
    bool secureBootEnabled = false;

    std::vector<CertInfo> pkCerts;      // Platform Key — the OEM's identity
    bool pkIsKnownOem = false;
    std::string pkOemName;

    std::vector<CertInfo> kekCerts;     // Key Exchange Key — expect Microsoft
    bool kekHasMicrosoft = false;

    std::vector<CertInfo> dbCerts;      // allowed signatures
    bool dbHasMicrosoftUefiCa2011 = false;
    bool dbHasMicrosoftUefiCa2023 = false;
    bool dbHasWindowsPca2011 = false;

    int dbxHashCount = 0;               // forbidden signatures

    bool chainValid = false;
    std::string verdict;
    std::vector<std::string> warnings;
    std::vector<std::string> errors;
};

/* variableData is the raw event data of a PCR[7] EV_EFI_VARIABLE_DRIVER_CONFIG
 * entry: EFI_GUID(16) UnicodeNameLength(8) VariableDataLength(8) UnicodeName
 * VariableData. Non-X.509 signature lists yield no certificates. */
std::vector<CertInfo> ParseEfiSignatureList(const std::vector<uint8_t>& variableData);

SecureBootChainReport ValidateSecureBootChain(const std::vector<uint8_t>& rawEventLog);

} // namespace RootHerald
