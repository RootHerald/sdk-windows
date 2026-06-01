/**
 * TCG Event Log reader for Windows (via Tbsi_Get_TCG_Log_Ex).
 */

#ifndef ROOTHERALD_EVENT_LOG_H
#define ROOTHERALD_EVENT_LOG_H

#include <vector>
#include <cstdint>

namespace RootHerald {

/// Reads the SRTM TCG event log from the TPM Base Services.
std::vector<uint8_t> ReadEventLog();

} // namespace RootHerald

#endif /* ROOTHERALD_EVENT_LOG_H */
