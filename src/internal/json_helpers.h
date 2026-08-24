/*
 * Flat-object JSON build/read for the attestation protocol only. Not a
 * general-purpose JSON library, and deliberately not a dependency.
 */

#pragma once

#include <string>
#include <map>

namespace RootHerald {

/* A value already starting with '{' or '[', or spelling true/false/null, is
 * embedded verbatim; anything else is escaped and quoted. That is how callers
 * splice a pre-built array such as ekCertificateChain into the object. */
inline std::string JsonBuild(const std::map<std::string, std::string>& fields)
{
    std::string json = "{";
    bool first = true;
    for (const auto& [key, value] : fields) {
        if (!first) json += ",";
        first = false;
        json += "\"" + key + "\":";

        if (!value.empty() && (value[0] == '{' || value[0] == '[' || value == "true" || value == "false" || value == "null")) {
            json += value;
        } else {
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

/* Empty string when the key is absent. */
inline std::string JsonGet(const std::string& json, const std::string& key)
{
    std::string search = "\"" + key + "\"";
    auto pos = json.find(search);
    if (pos == std::string::npos) return "";

    pos = json.find(':', pos + search.size());
    if (pos == std::string::npos) return "";
    pos++;

    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t')) pos++;
    if (pos >= json.size()) return "";

    if (json[pos] == '"') {
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
    }

    // Number, bool, null, or a nested object/array.
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

} // namespace RootHerald
