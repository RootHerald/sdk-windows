/*
 * UEFI_VARIABLE_DATA, parsed once and bounds-checked.
 *
 * TCG PC Client Platform Firmware Profile, EV_EFI_VARIABLE_* event data:
 *
 *   EFI_GUID VariableName        16 bytes
 *   UINT64   UnicodeNameLength   characters, not bytes
 *   UINT64   VariableDataLength  bytes
 *   CHAR16   UnicodeName[UnicodeNameLength]
 *   INT8     VariableData[VariableDataLength]
 *
 * Both lengths are attacker-influenceable 64-bit values read straight out of the
 * measured-boot log, so every bound is checked in subtraction form before any
 * multiply or add. Computing `32 + nameChars * 2` first and comparing afterwards
 * wraps on a 64-bit host and admits a wild pointer.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace RootHerald {

/* UEFI variable names are short identifiers ("SecureBoot", "PK", "dbx"). This is
 * far above any real name and keeps a bogus length from producing a huge read. */
constexpr uint64_t MAX_EFI_VARIABLE_NAME_CHARS = 1024;

struct EfiVariableData {
    const uint8_t* nameUtf16;   /* UCS-2LE, nameChars characters, not NUL-terminated */
    size_t         nameChars;
    const uint8_t* data;
    size_t         dataBytes;
};

/*
 * Returns false on any malformed record, leaving out untouched. On success both
 * spans are guaranteed to lie inside raw.
 */
inline bool TryParseEfiVariableData(const std::vector<uint8_t>& raw, EfiVariableData* out)
{
    constexpr size_t HEADER_BYTES = 32;
    if (out == nullptr || raw.size() < HEADER_BYTES)
        return false;

    uint64_t nameChars = 0;
    uint64_t dataBytes = 0;
    memcpy(&nameChars, raw.data() + 16, sizeof nameChars);
    memcpy(&dataBytes, raw.data() + 24, sizeof dataBytes);

    if (nameChars > MAX_EFI_VARIABLE_NAME_CHARS)
        return false;

    /* Subtraction form: raw.size() >= HEADER_BYTES is already established, so
     * this cannot wrap, and nameChars * 2 is only evaluated once it is known to
     * fit. */
    const size_t afterHeader = raw.size() - HEADER_BYTES;
    if (nameChars > afterHeader / 2)
        return false;
    const size_t nameBytes = static_cast<size_t>(nameChars) * 2;

    if (dataBytes > afterHeader - nameBytes)
        return false;

    out->nameUtf16 = raw.data() + HEADER_BYTES;
    out->nameChars = static_cast<size_t>(nameChars);
    out->data      = raw.data() + HEADER_BYTES + nameBytes;
    out->dataBytes = static_cast<size_t>(dataBytes);
    return true;
}

/* ASCII rendering of the variable name, with non-ASCII replaced. Stops at the
 * first NUL, matching how firmware writes these. */
inline std::string EfiVariableName(const EfiVariableData& var)
{
    std::string name;
    name.reserve(var.nameChars);
    for (size_t i = 0; i < var.nameChars; i++) {
        const uint16_t ch = static_cast<uint16_t>(var.nameUtf16[i * 2])
                          | static_cast<uint16_t>(var.nameUtf16[i * 2 + 1] << 8);
        if (ch == 0)
            break;
        name += (ch < 128) ? static_cast<char>(ch) : '?';
    }
    return name;
}

} // namespace RootHerald
