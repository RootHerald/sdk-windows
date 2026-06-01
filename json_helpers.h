/**
 * Minimal JSON helpers for the  Root Herald client SDK.
 * Handles only the flat object structures needed for the attestation protocol.
 * Not a general-purpose JSON library.
 */

#ifndef ROOTHERALD_JSON_HELPERS_H
#define ROOTHERALD_JSON_HELPERS_H

#include <string>
#include <map>

namespace RootHerald {

/// Build a flat JSON object from string key-value pairs.
inline std::string JsonBuild(const std::map<std::string, std::string>& fields)
{
    std::string json = "{";
    bool first = true;
    for (const auto& [key, value] : fields) {
        if (!first) json += ",";
        first = false;
        json += "\"" + key + "\":";

        // Check if value is already JSON (object/array) or a raw value
        if (!value.empty() && (value[0] == '{' || value[0] == '[' || value == "true" || value == "false" || value == "null")) {
            json += value;
        } else {
            // Escape and quote as string
            json += "\"";
            for (char c : value) {
                if (c == '"') json += "\\\"";
                else if (c == '\\') json += "\\\\";
                else if (c == '\n') json += "\\n";
                else json += c;
            }
            json += "\"";
        }
    }
    json += "}";
    return json;
}

/// Extract a string value from a flat JSON object by key.
/// Returns empty string if not found. Very simple parser — handles the shapes
/// returned by the  Root Herald API.
inline std::string JsonGet(const std::string& json, const std::string& key)
{
    std::string search = "\"" + key + "\"";
    auto pos = json.find(search);
    if (pos == std::string::npos) return "";

    pos = json.find(':', pos + search.size());
    if (pos == std::string::npos) return "";
    pos++;

    // Skip whitespace
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t')) pos++;

    if (pos >= json.size()) return "";

    if (json[pos] == '"') {
        // String value
        pos++;
        std::string result;
        while (pos < json.size() && json[pos] != '"') {
            if (json[pos] == '\\' && pos + 1 < json.size()) {
                pos++;
                if (json[pos] == 'n') result += '\n';
                else result += json[pos];
            } else {
                result += json[pos];
            }
            pos++;
        }
        return result;
    } else {
        // Number, bool, null, or nested object
        size_t start = pos;
        int depth = 0;
        while (pos < json.size()) {
            if (json[pos] == '{' || json[pos] == '[') depth++;
            else if (json[pos] == '}' || json[pos] == ']') {
                if (depth == 0) break;
                depth--;
            } else if (depth == 0 && (json[pos] == ',' || json[pos] == '}')) {
                break;
            }
            pos++;
        }
        return json.substr(start, pos - start);
    }
}

} // namespace RootHerald

#endif /* ROOTHERALD_JSON_HELPERS_H */
