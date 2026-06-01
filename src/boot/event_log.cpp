/**
 * TCG Event Log reader — Windows implementation
 */

#include "event_log.h"
#include <windows.h>
#include <tbs.h>

namespace RootHerald {

std::vector<uint8_t> ReadEventLog()
{
    UINT32 logSize = 0;

    // First call to get size
    TBS_RESULT result = Tbsi_Get_TCG_Log_Ex(
        TBS_TCGLOG_SRTM_CURRENT, nullptr, &logSize);

    if (result != TBS_SUCCESS || logSize == 0)
        return {};

    std::vector<uint8_t> log(logSize);

    result = Tbsi_Get_TCG_Log_Ex(
        TBS_TCGLOG_SRTM_CURRENT, log.data(), &logSize);

    if (result != TBS_SUCCESS)
        return {};

    log.resize(logSize);
    return log;
}

} // namespace RootHerald
