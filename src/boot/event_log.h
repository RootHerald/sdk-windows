/*
 * TCG event log reader (Tbsi_Get_TCG_Log_Ex).
 */

#pragma once

#include <vector>
#include <cstdint>

namespace RootHerald {

/* Empty if the log is unavailable, which is not itself an error: a machine
 * with no measured boot simply has none. */
std::vector<uint8_t> ReadEventLog();

} // namespace RootHerald
