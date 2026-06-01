/**
 * UEFI DBX Revocation Checker
 *
 * Loads the Microsoft UEFI Forbidden Signatures List (DBX) and checks
 * boot measurement hashes against it.
 *
 * Data source: https://github.com/microsoft/secureboot_objects
 * Format: JSON with SHA-256 Authenticode hashes of revoked UEFI binaries.
 */

#ifndef ROOTHERALD_DBX_CHECKER_H
#define ROOTHERALD_DBX_CHECKER_H

#include <string>
#include <set>
#include <vector>
#include <cstdint>

namespace RootHerald {

class DbxChecker {
public:
    /// Load revoked hashes from the Microsoft DBX JSON file.
    /// Returns the number of hashes loaded.
    int LoadFromJson(const std::string& jsonPath);

    /// Check if a SHA-256 hash is on the revocation list.
    bool IsRevoked(const std::vector<uint8_t>& sha256Digest) const;
    bool IsRevoked(const std::string& hexDigest) const;

    int Count() const { return (int)_revokedHashes.size(); }

private:
    std::set<std::string> _revokedHashes; // Uppercase hex SHA-256
};

} // namespace RootHerald

#endif /* ROOTHERALD_DBX_CHECKER_H */
