#include "event_log.h"

#include <windows.h>
#include <tbs.h>

#include "log.h"

namespace RootHerald {

std::vector<uint8_t> ReadEventLog()
{
    UINT32 logSize = 0;
    TBS_RESULT result = Tbsi_Get_TCG_Log_Ex(TBS_TCGLOG_SRTM_CURRENT, nullptr, &logSize);
    if (result != TBS_SUCCESS || logSize == 0) {
        RH_LOG_DEBUG("[eventlog] size query: 0x%08X (size=%u)\n", (unsigned)result, logSize);
        return {};
    }

    std::vector<uint8_t> log(logSize);
    result = Tbsi_Get_TCG_Log_Ex(TBS_TCGLOG_SRTM_CURRENT, log.data(), &logSize);
    if (result != TBS_SUCCESS) {
        RH_LOG_DEBUG("[eventlog] read: 0x%08X\n", (unsigned)result);
        return {};
    }

    log.resize(logSize);
    return log;
}

} // namespace RootHerald
