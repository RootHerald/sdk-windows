/**
 * Root Herald native SDK — logging shim (Windows).
 *
 * Single global callback + level filter. NULL callback = library is silent
 * (the default). Matches the libfido2 / libsodium pattern researched and
 * documented in INTEGRATING.md.
 *
 * The callback may be invoked from any thread the library runs on. The
 * `g_log_callback` pointer is read with relaxed semantics — a torn read
 * during registration is acceptable because the worst case is one missed or
 * spurious log line. We do not lock around log emission; the caller is
 * expected to make their callback thread-safe.
 */

#include "rootherald.h"
#include "log.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

namespace {
    RootHeraldLogCallback g_log_callback = nullptr;
    void* g_log_user_data = nullptr;
    RootHeraldLogLevel g_log_max_level = ROOTHERALD_LOG_WARN;
}

extern "C" void RootHerald_SetLogCallback(
    RootHeraldLogCallback callback,
    void* user_data)
{
    g_log_callback = callback;
    g_log_user_data = user_data;
}

extern "C" void RootHerald_SetLogLevel(RootHeraldLogLevel max_level)
{
    g_log_max_level = max_level;
}

void rh_log(RootHeraldLogLevel level, const char* fmt, ...)
{
    // Fast path: bail before formatting if filtered or no callback.
    if (g_log_callback == nullptr) return;
    if (static_cast<int>(level) > static_cast<int>(g_log_max_level)) return;

    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    if (n < 0) {
        // vsnprintf failed; emit a best-effort marker rather than nothing.
        strncpy_s(buf, sizeof(buf), "(log message formatting failed)", _TRUNCATE);
    }
    // Trim trailing newline — customer loggers add their own.
    size_t len = strnlen(buf, sizeof(buf));
    while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r')) {
        buf[--len] = '\0';
    }

    g_log_callback(level, buf, g_log_user_data);
}

extern "C" const char* RootHerald_ErrorString(RootHeraldStatus status)
{
    switch (status) {
        case ROOTHERALD_OK:                  return "ok";
        case ROOTHERALD_ERR_INVALID_ARG:     return "invalid argument";
        case ROOTHERALD_ERR_TPM_UNAVAILABLE: return "TPM or secure-enclave unavailable on this host";
        case ROOTHERALD_ERR_NETWORK:         return "network error reaching the Root Herald endpoint";
        case ROOTHERALD_ERR_SERVER:          return "Root Herald server returned an error";
        case ROOTHERALD_ERR_QUOTA_EXCEEDED:  return "tenant quota exceeded";
        case ROOTHERALD_ERR_NOT_ENROLLED:    return "device is not enrolled";
        case ROOTHERALD_ERR_ELEVATION_REQUIRED: return "enrollment requires an elevated process; run EnrollBegin/EnrollComplete in an elevated resident worker (the single elevation spans both), then retry";
        case ROOTHERALD_ERR_INTERNAL:        return "internal library error";
        default:                             return "unknown error";
    }
}
