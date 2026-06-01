/**
 * Internal logging shim used by RootHerald.lib. Customers do NOT include
 * this header — it lives inside src/ and is not exported. The public API
 * for registering log callbacks is in <rootherald.h>.
 *
 * Library code uses rh_log(level, "fmt %s", ...) wherever it would
 * previously have called fprintf(stderr, ...) or printf(...). When no
 * callback is registered (the default), rh_log is a near-noop — one NULL
 * check and an integer compare, no formatting work.
 */

#ifndef ROOTHERALD_INTERNAL_LOG_H
#define ROOTHERALD_INTERNAL_LOG_H

#include "rootherald.h"

#ifdef __cplusplus
extern "C" {
#endif

void rh_log(RootHeraldLogLevel level, const char* fmt, ...);

#ifdef __cplusplus
}
#endif

/* Per-level convenience macros — same idiom as libfido2's
 * fido_log_debug/fido_log_xxd/fido_log_error.                            */
#define RH_LOG_ERROR(...) rh_log(ROOTHERALD_LOG_ERROR, __VA_ARGS__)
#define RH_LOG_WARN(...)  rh_log(ROOTHERALD_LOG_WARN,  __VA_ARGS__)
#define RH_LOG_INFO(...)  rh_log(ROOTHERALD_LOG_INFO,  __VA_ARGS__)
#define RH_LOG_DEBUG(...) rh_log(ROOTHERALD_LOG_DEBUG, __VA_ARGS__)
#define RH_LOG_TRACE(...) rh_log(ROOTHERALD_LOG_TRACE, __VA_ARGS__)

#endif /* ROOTHERALD_INTERNAL_LOG_H */
