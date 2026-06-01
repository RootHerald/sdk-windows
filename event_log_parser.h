/**
 * TCG Event Log Parser — Detailed analysis of boot measurements.
 *
 * Parses the Windows TCG event log into structured entries,
 * classifying each measurement by type and extracting human-readable
 * descriptions. This is the foundation for bootkit detection.
 */

#ifndef ROOTHERALD_EVENT_LOG_PARSER_H
#define ROOTHERALD_EVENT_LOG_PARSER_H

#include <cstdint>
#include <string>
#include <vector>
#include <map>

namespace RootHerald {

// TCG Event Types (TCG PC Client Spec)
enum EventType : uint32_t {
    EV_PREBOOT_CERT           = 0x00000000,
    EV_POST_CODE              = 0x00000001,
    EV_UNUSED                 = 0x00000002,
    EV_NO_ACTION              = 0x00000003,
    EV_SEPARATOR              = 0x00000004,
    EV_ACTION                 = 0x00000005,
    EV_EVENT_TAG              = 0x00000006,
    EV_S_CRTM_CONTENTS       = 0x00000007,
    EV_S_CRTM_VERSION         = 0x00000008,
    EV_CPU_MICROCODE          = 0x00000009,
    EV_PLATFORM_CONFIG_FLAGS  = 0x0000000A,
    EV_TABLE_OF_DEVICES       = 0x0000000B,
    EV_COMPACT_HASH           = 0x0000000C,
    EV_IPL                    = 0x0000000D,
    EV_IPL_PARTITION_DATA     = 0x0000000E,
    EV_NONHOST_CODE           = 0x0000000F,
    EV_NONHOST_CONFIG         = 0x00000010,
    EV_NONHOST_INFO           = 0x00000011,
    EV_OMIT_BOOT_DEVICE_EVENTS = 0x00000012,

    // EFI Events
    EV_EFI_EVENT_BASE                = 0x80000000,
    EV_EFI_VARIABLE_DRIVER_CONFIG    = 0x80000001,
    EV_EFI_VARIABLE_BOOT             = 0x80000002,
    EV_EFI_BOOT_SERVICES_APPLICATION = 0x80000003,
    EV_EFI_BOOT_SERVICES_DRIVER      = 0x80000004,
    EV_EFI_RUNTIME_SERVICES_DRIVER   = 0x80000005,
    EV_EFI_GPT_EVENT                 = 0x80000006,
    EV_EFI_ACTION                    = 0x80000007,
    EV_EFI_PLATFORM_FIRMWARE_BLOB    = 0x80000008,
    EV_EFI_HANDOFF_TABLES            = 0x80000009,
    EV_EFI_PLATFORM_FIRMWARE_BLOB2   = 0x8000000A,
    EV_EFI_HANDOFF_TABLES2           = 0x8000000B,
    EV_EFI_VARIABLE_BOOT2            = 0x8000000C,
    EV_EFI_HCRTM_EVENT               = 0x80000010,
    EV_EFI_VARIABLE_AUTHORITY        = 0x800000E0,
    EV_EFI_SPDM_FIRMWARE_BLOB        = 0x800000E1,
    EV_EFI_SPDM_FIRMWARE_CONFIG      = 0x800000E2,
};

struct EventLogEntry {
    uint32_t pcrIndex;
    uint32_t eventType;
    std::string eventTypeName;
    std::map<uint16_t, std::vector<uint8_t>> digests; // algId -> digest
    std::vector<uint8_t> eventData;
    std::string description;  // Human-readable description
    std::string classification; // "verified", "revoked", "unknown", "policy"
};

struct EventLogAnalysis {
    std::vector<EventLogEntry> entries;
    bool secureBootEnabled = false;
    bool secureBootMicrosoftKeys = false;
    int verifiedCount = 0;
    int unknownCount = 0;
    int revokedCount = 0;
    int policyCount = 0;
    std::string verdict; // "PASS", "FAIL", "WARNING"
    std::string verdictReason;
};

/// Parse a raw TCG event log into structured entries.
EventLogAnalysis ParseAndAnalyzeEventLog(const std::vector<uint8_t>& rawLog);

/// Get human-readable name for an event type.
const char* EventTypeName(uint32_t eventType);

} // namespace RootHerald

#endif /* ROOTHERALD_EVENT_LOG_PARSER_H */
