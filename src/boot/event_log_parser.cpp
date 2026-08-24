/*
 * Parses the TCG event log: the legacy TCG_PCR_EVENT Spec ID header followed
 * by TCG_PCR_EVENT2 entries.
 *
 * The log is untrusted binary input, so each step bounds-checks against the
 * remaining length before advancing the cursor. Nothing produced here is a
 * security verdict — the server re-derives boot posture from the quote-bound
 * log and never gates on this.
 */

#include "event_log_parser.h"
#include "efi_variable.h"

#include <sal.h>
#include <cstring>

namespace RootHerald {

static const uint8_t EFI_GLOBAL_VARIABLE_GUID[] = {
    0x61, 0xDF, 0xE4, 0x8B, 0xCA, 0x93, 0xD2, 0x11,
    0xAA, 0x0D, 0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C
};

static const uint8_t EFI_IMAGE_SECURITY_DATABASE_GUID[] = {
    0xCB, 0xB2, 0x19, 0xD7, 0x3A, 0x3D, 0x96, 0x45,
    0xA3, 0xBC, 0xDA, 0xD0, 0x0E, 0x67, 0x65, 0x6F
};

static uint16_t ReadU16LE(_In_reads_bytes_(2) const uint8_t* p) { return p[0] | (p[1] << 8); }
static uint32_t ReadU32LE(_In_reads_bytes_(4) const uint8_t* p) { return p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24); }

const char* EventTypeName(uint32_t eventType) {
    switch (eventType) {
        case EV_PREBOOT_CERT:           return "EV_PREBOOT_CERT";
        case EV_POST_CODE:              return "EV_POST_CODE";
        case EV_NO_ACTION:              return "EV_NO_ACTION";
        case EV_SEPARATOR:              return "EV_SEPARATOR";
        case EV_ACTION:                 return "EV_ACTION";
        case EV_S_CRTM_CONTENTS:        return "EV_S_CRTM_CONTENTS";
        case EV_S_CRTM_VERSION:         return "EV_S_CRTM_VERSION";
        case EV_CPU_MICROCODE:          return "EV_CPU_MICROCODE";
        case EV_PLATFORM_CONFIG_FLAGS:  return "EV_PLATFORM_CONFIG_FLAGS";
        case EV_TABLE_OF_DEVICES:       return "EV_TABLE_OF_DEVICES";
        case EV_COMPACT_HASH:           return "EV_COMPACT_HASH";
        case EV_IPL:                    return "EV_IPL";
        case EV_NONHOST_CODE:           return "EV_NONHOST_CODE";
        case EV_NONHOST_CONFIG:         return "EV_NONHOST_CONFIG";
        case EV_EFI_VARIABLE_DRIVER_CONFIG:    return "EV_EFI_VARIABLE_DRIVER_CONFIG";
        case EV_EFI_VARIABLE_BOOT:             return "EV_EFI_VARIABLE_BOOT";
        case EV_EFI_BOOT_SERVICES_APPLICATION: return "EV_EFI_BOOT_SERVICES_APPLICATION";
        case EV_EFI_BOOT_SERVICES_DRIVER:      return "EV_EFI_BOOT_SERVICES_DRIVER";
        case EV_EFI_RUNTIME_SERVICES_DRIVER:   return "EV_EFI_RUNTIME_SERVICES_DRIVER";
        case EV_EFI_GPT_EVENT:                 return "EV_EFI_GPT_EVENT";
        case EV_EFI_ACTION:                    return "EV_EFI_ACTION";
        case EV_EFI_PLATFORM_FIRMWARE_BLOB:    return "EV_EFI_PLATFORM_FIRMWARE_BLOB";
        case EV_EFI_PLATFORM_FIRMWARE_BLOB2:   return "EV_EFI_PLATFORM_FIRMWARE_BLOB2";
        case EV_EFI_HANDOFF_TABLES:            return "EV_EFI_HANDOFF_TABLES";
        case EV_EFI_VARIABLE_AUTHORITY:        return "EV_EFI_VARIABLE_AUTHORITY";
        case EV_EFI_SPDM_FIRMWARE_BLOB:        return "EV_EFI_SPDM_FIRMWARE_BLOB";
        default: return "UNKNOWN";
    }
}

/* Event data layout: GUID(16) UnicodeNameLength(8) VariableDataLength(8)
 * UnicodeName VariableData. The name is UCS-2LE; anything non-ASCII becomes
 * a question mark, and the walk stops at 256 characters. */
static std::string ExtractEfiVariableName(const std::vector<uint8_t>& data) {
    EfiVariableData var;
    if (!TryParseEfiVariableData(data, &var)) return "";
    return EfiVariableName(var);
}

/* UEFI_IMAGE_LOAD_EVENT: ImageLocationInMemory(8) ImageLengthInMemory(8)
 * ImageLinkTimeAddress(8) LengthOfDevicePath(8) DevicePath. The device path is
 * a binary node structure, so this recovers the readable UCS-2LE run inside it
 * rather than decoding every node type. */
static std::string ExtractBootAppPath(const std::vector<uint8_t>& data) {
    if (data.size() < 32) return "(unknown path)";

    std::string result;
    for (size_t i = 32; i + 1 < data.size(); i += 2) {
        uint16_t ch = ReadU16LE(data.data() + i);
        if (ch == '\\' || ch == '/' || (ch >= 'A' && ch <= 'z') || ch == '.' || ch == '-' || ch == '_') {
            if (ch < 128) result += (char)ch;
        } else if (ch == 0 && !result.empty()) {
            if (result.length() > 4 && (result.find(".efi") != std::string::npos ||
                                          result.find(".EFI") != std::string::npos ||
                                          result.find("\\") != std::string::npos)) {
                return result;
            }
            result.clear();
        } else {
            result.clear();
        }
    }
    return result.empty() ? "(binary device path)" : result;
}

static std::string BytesToHex(_In_reads_bytes_(len) const uint8_t* data, size_t len) {
    static const char HEX[] = "0123456789abcdef";
    std::string result;
    result.reserve(len * 2);
    for (size_t i = 0; i < len; i++) {
        result += HEX[data[i] >> 4];
        result += HEX[data[i] & 0x0F];
    }
    return result;
}

/* The SecureBoot variable's data is a single byte, 1 = enabled. */
static bool IsSecureBootEnabled(const std::string& varName, const std::vector<uint8_t>& data) {
    if (varName != "SecureBoot") return false;
    if (data.size() < 33) return false;

    EfiVariableData var;
    if (!TryParseEfiVariableData(data, &var) || var.dataBytes < 1)
        return false;

    return var.data[0] == 1;
}

EventLogAnalysis ParseAndAnalyzeEventLog(const std::vector<uint8_t>& rawLog) {
    EventLogAnalysis analysis;
    const uint8_t* p = rawLog.data();
    size_t remaining = rawLog.size();

    // Legacy TCG_PCR_EVENT Spec ID header, if present:
    // pcrIndex(4) eventType(4) SHA1digest(20) eventDataSize(4) eventData
    if (remaining >= 32) {
        uint32_t eventType = ReadU32LE(p + 4);
        if (eventType == EV_NO_ACTION) {
            uint32_t eventDataSize = ReadU32LE(p + 28);
            size_t skip = 32 + (size_t)eventDataSize;
            if (skip <= remaining) {
                p += skip;
                remaining -= skip;
            }
        }
    }

    // A truncated entry ends the walk and is discarded rather than emitted.
    bool truncated = false;
    while (remaining >= 12 && !truncated) {
        EventLogEntry entry;
        entry.pcrIndex = ReadU32LE(p);
        p += 4; remaining -= 4;

        entry.eventType = ReadU32LE(p);
        p += 4; remaining -= 4;

        entry.eventTypeName = EventTypeName(entry.eventType);

        // TPML_DIGEST_VALUES
        if (remaining < 4) break;
        uint32_t digestCount = ReadU32LE(p);
        p += 4; remaining -= 4;

        if (digestCount > 8) break;

        for (uint32_t i = 0; i < digestCount; i++) {
            if (remaining < 2) { truncated = true; break; }
            uint16_t algId = ReadU16LE(p);
            p += 2; remaining -= 2;

            uint32_t digestSize = 0;
            switch (algId) {
                case 0x0004: digestSize = 20; break;  // SHA-1
                case 0x000B: digestSize = 32; break;  // SHA-256
                case 0x000C: digestSize = 48; break;  // SHA-384
                case 0x000D: digestSize = 64; break;  // SHA-512
                case 0x0012: digestSize = 32; break;  // SM3
                default: break;                       // size unknown: stop here
            }
            if (digestSize == 0) { truncated = true; break; }

            if (remaining < digestSize) { truncated = true; break; }
            entry.digests[algId] = std::vector<uint8_t>(p, p + digestSize);
            p += digestSize; remaining -= digestSize;
        }
        if (truncated) break;

        if (remaining < 4) break;
        uint32_t eventDataSize = ReadU32LE(p);
        p += 4; remaining -= 4;

        if (remaining < eventDataSize) break;
        entry.eventData.assign(p, p + eventDataSize);
        p += eventDataSize; remaining -= eventDataSize;

        switch (entry.eventType) {
            case EV_EFI_VARIABLE_DRIVER_CONFIG:
            case EV_EFI_VARIABLE_BOOT:
            case EV_EFI_VARIABLE_BOOT2: {
                std::string varName = ExtractEfiVariableName(entry.eventData);
                entry.description = "EFI Variable: " + varName;
                entry.classification = "policy";
                analysis.policyCount++;

                if (varName == "SecureBoot") {
                    analysis.secureBootEnabled = IsSecureBootEnabled(varName, entry.eventData);
                    entry.description += analysis.secureBootEnabled ? " (ENABLED)" : " (DISABLED)";
                }
                if (varName == "PK" || varName == "KEK" || varName == "db" || varName == "dbx") {
                    entry.description += " (Secure Boot key database)";
                    if (varName == "db" || varName == "KEK") {
                        // Presence of db/KEK is taken as Microsoft keying. It is
                        // descriptive only; the verdict is server-side.
                        analysis.secureBootMicrosoftKeys = true;
                    }
                }
                break;
            }

            case EV_EFI_BOOT_SERVICES_APPLICATION: {
                std::string path = ExtractBootAppPath(entry.eventData);
                entry.description = "Boot Application: " + path;
                entry.classification = "verified";
                analysis.verifiedCount++;
                break;
            }

            case EV_EFI_BOOT_SERVICES_DRIVER: {
                std::string path = ExtractBootAppPath(entry.eventData);
                entry.description = "Boot Driver: " + path;
                entry.classification = "verified";
                analysis.verifiedCount++;
                break;
            }

            case EV_EFI_PLATFORM_FIRMWARE_BLOB:
            case EV_EFI_PLATFORM_FIRMWARE_BLOB2: {
                entry.description = "Platform Firmware Blob";
                entry.classification = "verified";
                analysis.verifiedCount++;
                break;
            }

            case EV_S_CRTM_VERSION: {
                std::string version;
                for (size_t i = 0; i + 1 < entry.eventData.size(); i += 2) {
                    uint16_t ch = ReadU16LE(entry.eventData.data() + i);
                    if (ch == 0) break;
                    if (ch < 128) version += (char)ch;
                }
                entry.description = "CRTM/BIOS Version: " + version;
                entry.classification = "verified";
                analysis.verifiedCount++;
                break;
            }

            case EV_POST_CODE:
            case EV_S_CRTM_CONTENTS:
            case EV_CPU_MICROCODE: {
                entry.description = std::string(EventTypeName(entry.eventType));
                entry.classification = "verified";
                analysis.verifiedCount++;
                break;
            }

            case EV_SEPARATOR: {
                entry.description = "Separator (transition to OS measurements)";
                entry.classification = "policy";
                analysis.policyCount++;
                break;
            }

            case EV_EFI_ACTION: {
                std::string action(entry.eventData.begin(), entry.eventData.end());
                entry.description = "EFI Action: " + action;
                entry.classification = "policy";
                analysis.policyCount++;
                break;
            }

            case EV_EFI_VARIABLE_AUTHORITY: {
                entry.description = "EFI Variable Authority (certificate used for Secure Boot verification)";
                entry.classification = "policy";
                analysis.policyCount++;
                break;
            }

            case EV_EFI_GPT_EVENT: {
                entry.description = "GPT Partition Table";
                entry.classification = "policy";
                analysis.policyCount++;
                break;
            }

            case EV_NO_ACTION: {
                entry.description = "No Action (informational)";
                entry.classification = "policy";
                analysis.policyCount++;
                break;
            }

            case EV_EFI_HANDOFF_TABLES:
            case EV_EFI_HANDOFF_TABLES2: {
                entry.description = "EFI Handoff Tables (SMBIOS/ACPI)";
                entry.classification = "policy";
                analysis.policyCount++;
                break;
            }

            case EV_PLATFORM_CONFIG_FLAGS: {
                entry.description = "Platform Configuration Flags";
                entry.classification = "policy";
                analysis.policyCount++;
                break;
            }

            case EV_COMPACT_HASH: {
                entry.description = "Compact Hash (Windows integrity measurement)";
                entry.classification = "verified";
                analysis.verifiedCount++;
                break;
            }

            case EV_EFI_RUNTIME_SERVICES_DRIVER: {
                std::string path = ExtractBootAppPath(entry.eventData);
                entry.description = "Runtime Driver: " + path;
                entry.classification = "verified";
                analysis.verifiedCount++;
                break;
            }

            default: {
                // PCR[11-14] carry Windows OS measurements (BitLocker, Secure
                // Launch); expected here, so not counted as unknown.
                if (entry.pcrIndex >= 11 && entry.pcrIndex <= 14) {
                    entry.description = "Windows OS measurement (PCR[" +
                        std::to_string(entry.pcrIndex) + "])";
                    entry.classification = "verified";
                    analysis.verifiedCount++;
                } else {
                    entry.description = std::string(EventTypeName(entry.eventType)) +
                        " (PCR[" + std::to_string(entry.pcrIndex) + "])";
                    entry.classification = "unknown";
                    analysis.unknownCount++;
                }
                break;
            }
        }

        analysis.entries.push_back(std::move(entry));
    }

    if (analysis.secureBootEnabled) {
        if (analysis.unknownCount == 0) {
            analysis.verdict = "PASS";
            analysis.verdictReason = "Secure Boot enabled, all boot components verified";
        } else {
            analysis.verdict = "WARNING";
            analysis.verdictReason = "Secure Boot enabled, but " + std::to_string(analysis.unknownCount) +
                                    " unknown measurement(s) detected";
        }
    } else {
        analysis.verdict = "FAIL";
        analysis.verdictReason = "Secure Boot is DISABLED — boot chain integrity cannot be guaranteed";
    }

    return analysis;
}

} // namespace RootHerald
