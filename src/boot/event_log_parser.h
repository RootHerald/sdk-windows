/*
 * Structured view of the TCG event log: one entry per measurement, classified
 * and given a human-readable description.
 *
 * Descriptive only. The verdict fields are advisory client-side observations;
 * the server re-derives boot posture from the quote-bound log.
 */

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <map>

namespace RootHerald {

/* TCG PC Client Platform Firmware Profile event types. */
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
    std::map<uint16_t, std::vector<uint8_t>> digests; // TPM algorithm id -> digest
    std::vector<uint8_t> eventData;
    std::string description;
    std::string classification;   // "verified" | "unknown" | "policy"
};

struct EventLogAnalysis {
    std::vector<EventLogEntry> entries;
    bool secureBootEnabled = false;
    bool secureBootMicrosoftKeys = false;
    int verifiedCount = 0;
    int unknownCount = 0;
    int policyCount = 0;
    std::string verdict;          // "PASS" | "FAIL" | "WARNING"
    std::string verdictReason;
};

/* Stops at the first truncated entry; a partial entry is discarded. */
EventLogAnalysis ParseAndAnalyzeEventLog(const std::vector<uint8_t>& rawLog);

/* Static string, never NULL; "UNKNOWN" for an unrecognised type. */
const char* EventTypeName(uint32_t eventType);

} // namespace RootHerald
