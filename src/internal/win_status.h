/*
 * One carrier for every failure this library observes below the ABI edge.
 *
 * NCrypt's SECURITY_STATUS and TBS_RESULT are already HRESULT-valued, so they
 * propagate unchanged; a raw TPM 2.0 response code is widened here the way
 * Windows itself does. Flattening to RootHeraldStatus happens once, in
 * rootherald_client.cpp.
 */

#pragma once

#include <windows.h>
#include <tbs.h>
#include <cstdint>

namespace RootHerald {

/* HRESULT_FROM_WIN32(ERROR_INVALID_DATA) — a TPM/TBS reply too short or
 * malformed to parse. Spelled numerically because the macro is not constexpr. */
constexpr HRESULT RH_E_MALFORMED_RESPONSE = static_cast<HRESULT>(0x8007000DL);

/* An operation was attempted before Open() succeeded. */
constexpr HRESULT RH_E_NOT_OPEN = E_NOT_VALID_STATE;

inline HRESULT HrFromTbs(TBS_RESULT result)
{
    return static_cast<HRESULT>(result);
}

inline HRESULT HrFromSecurityStatus(SECURITY_STATUS status)
{
    return static_cast<HRESULT>(status);
}

/* Widens a TPM 2.0 response code into FACILITY_TPM_SOFTWARE, matching the
 * TPM_20_E_* block in winerror.h — so a logged 0x80290185 is greppable there
 * rather than being an unattributed bare number. */
inline HRESULT HrFromTpmRc(uint32_t responseCode)
{
    return responseCode == 0
        ? S_OK
        : static_cast<HRESULT>(0x80290000u | (responseCode & 0x0000FFFFu));
}

} // namespace RootHerald
