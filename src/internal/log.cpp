/*
 * Single global callback plus a level filter; a NULL callback means the
 * library is silent, which is the default.
 *
 * THREAD-SAFETY: the callback may be invoked from any thread the library runs
 * on, and g_logCallback is read without a lock. A torn read during
 * registration costs at most one missed or spurious line, so the caller's
 * callback — not this shim — is what has to be thread-safe.
 */

#include "rootherald.h"
#include "log.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

namespace {
    RootHeraldLogCallback g_logCallback = nullptr;
    void* g_logUserData = nullptr;
    RootHeraldLogLevel g_logMaxLevel = ROOTHERALD_LOG_WARN;
}

extern "C" _Use_decl_annotations_ void RootHerald_SetLogCallback(
    RootHeraldLogCallback callback,
    void* user_data)
{
    g_logCallback = callback;
    g_logUserData = user_data;
}

extern "C" void RootHerald_SetLogLevel(RootHeraldLogLevel max_level)
{
    g_logMaxLevel = max_level;
}

_Use_decl_annotations_
void rh_log(RootHeraldLogLevel level, const char* fmt, ...)
{
    if (g_logCallback == nullptr) return;
    if (static_cast<int>(level) > static_cast<int>(g_logMaxLevel)) return;

    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    if (n < 0) {
        strncpy_s(buf, sizeof(buf), "(log message formatting failed)", _TRUNCATE);
    }

    // Customer loggers add their own line ending.
    size_t len = strnlen(buf, sizeof(buf));
    while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r')) {
        buf[--len] = '\0';
    }

    g_logCallback(level, buf, g_logUserData);
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
