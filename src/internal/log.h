/*
 * Internal logging shim. Not installed; the public API for registering a
 * callback is in <rootherald.h>.
 *
 * With no callback registered — the default — rh_log costs one NULL check and
 * an integer compare, and does no formatting.
 */

#pragma once

#include <sal.h>

#include "rootherald.h"

#ifdef __cplusplus
extern "C" {
#endif

void rh_log(RootHeraldLogLevel level, _In_z_ _Printf_format_string_ const char* fmt, ...);

#ifdef __cplusplus
}
#endif

#define RH_LOG_ERROR(...) rh_log(ROOTHERALD_LOG_ERROR, __VA_ARGS__)
#define RH_LOG_WARN(...)  rh_log(ROOTHERALD_LOG_WARN,  __VA_ARGS__)
#define RH_LOG_INFO(...)  rh_log(ROOTHERALD_LOG_INFO,  __VA_ARGS__)
#define RH_LOG_DEBUG(...) rh_log(ROOTHERALD_LOG_DEBUG, __VA_ARGS__)
