/**
 * UEFI DBX Revocation Checker — Implementation.
 *
 * Parses the Microsoft DBX JSON file using simple string scanning.
 * No JSON library dependency — the format is predictable enough for
 * targeted extraction of authenticodeHash fields.
 */

#include "dbx_checker.h"

#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>

namespace RootHerald {

static std::string ToUpper(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), ::toupper);
    return s;
}

static std::string BytesToHexUpper(const uint8_t* data, size_t len) {
    static const char hex[] = "0123456789ABCDEF";
    std::string result;
    result.reserve(len * 2);
    for (size_t i = 0; i < len; i++) {
        result += hex[data[i] >> 4];
        result += hex[data[i] & 0x0F];
    }
    return result;
}

int DbxChecker::LoadFromJson(const std::string& jsonPath)
{
    std::ifstream file(jsonPath);
    if (!file.is_open()) return -1;

    std::ostringstream ss;
    ss << file.rdbuf();
    std::string json = ss.str();

    // Scan for all "authenticodeHash" values
    // Format: "authenticodeHash": "80B4D96931BF..."
    const std::string key = "\"authenticodeHash\"";
    size_t pos = 0;

    while ((pos = json.find(key, pos)) != std::string::npos) {
        pos += key.size();

        // Find the colon
        pos = json.find(':', pos);
        if (pos == std::string::npos) break;
        pos++;

        // Find the opening quote
        pos = json.find('"', pos);
        if (pos == std::string::npos) break;
        pos++;

        // Read until closing quote
        size_t end = json.find('"', pos);
        if (end == std::string::npos) break;

        std::string hash = json.substr(pos, end - pos);
        pos = end + 1;

        // Only store non-empty SHA-256 hashes (64 hex chars)
        if (hash.size() == 64) {
            _revokedHashes.insert(ToUpper(hash));
        }
    }

    return (int)_revokedHashes.size();
}

bool DbxChecker::IsRevoked(const std::vector<uint8_t>& sha256Digest) const
{
    if (sha256Digest.size() != 32) return false;
    return IsRevoked(BytesToHexUpper(sha256Digest.data(), sha256Digest.size()));
}

bool DbxChecker::IsRevoked(const std::string& hexDigest) const
{
    return _revokedHashes.count(ToUpper(hexDigest)) > 0;
}

} // namespace RootHerald
