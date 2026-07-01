cmake_minimum_required(VERSION 3.20)
project(rootherald_windows VERSION 0.2.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# -----------------------------------------------------------------------------
# RootHerald.lib — embeddable STATIC native SDK (Windows).
#
# Customer integration is: link RootHerald.lib + include common/rootherald.h.
# The library is silent by default; register a log callback via
# RootHerald_SetLogCallback() if you want output. See INTEGRATING.md.
#
# Layout:
#   src/client/    — RootHeraldClient lifecycle + Windows driver
#   src/tpm/       — NCrypt PCP + raw TBS
#   src/boot/      — Event log + Secure Boot validation
#   src/certs/     — AIA cert chasing + Windows cert store
#   src/transport/ — HTTPS via WinHTTP
#   src/internal/  — Log shim + JSON helpers (not exported)
#   tools/         — Dev diagnostics (test_client, test_harness, tpm_diag,
#                    boot_verify, dbx_checker). NOT part of RootHerald.lib.
# -----------------------------------------------------------------------------

set(RH_LIB_SOURCES
    src/client/rootherald_client.cpp
    src/client/rootherald_win.cpp
    src/tpm/tpm_pcp.cpp
    src/tpm/tpm_commands.cpp
    src/tpm/tbs_key_provider.cpp
    src/boot/event_log.cpp
    src/boot/event_log_parser.cpp
    src/boot/secureboot_validator.cpp
    src/certs/amd_aia_fetch.cpp
    src/certs/win_cert_store_intermediates.cpp
    src/transport/http_winhttp.cpp
    src/internal/log.cpp
)

set(RH_INCLUDE_DIRS
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/src/client
    ${CMAKE_CURRENT_SOURCE_DIR}/src/tpm
    ${CMAKE_CURRENT_SOURCE_DIR}/src/boot
    ${CMAKE_CURRENT_SOURCE_DIR}/src/certs
    ${CMAKE_CURRENT_SOURCE_DIR}/src/transport
    ${CMAKE_CURRENT_SOURCE_DIR}/src/internal
)

set(RH_SYSTEM_LIBS ncrypt tbs winhttp bcrypt crypt32)

add_library(RootHerald STATIC ${RH_LIB_SOURCES})
target_include_directories(RootHerald
    PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR}/../common
    PRIVATE ${RH_INCLUDE_DIRS}
)
target_link_libraries(RootHerald PUBLIC ${RH_SYSTEM_LIBS})
add_library(rootherald ALIAS RootHerald)

# -----------------------------------------------------------------------------
# Developer diagnostics — separate executables, not part of RootHerald.lib.
# Each links the library plus any extra deps it needs.
# -----------------------------------------------------------------------------

add_executable(test_client tools/test_client.cpp)
target_link_libraries(test_client PRIVATE RootHerald)
target_include_directories(test_client PRIVATE ${RH_INCLUDE_DIRS} ${CMAKE_CURRENT_SOURCE_DIR}/tools)

add_executable(gate_collect tools/gate_collect.cpp)
target_link_libraries(gate_collect PRIVATE RootHerald)
target_include_directories(gate_collect PRIVATE ${RH_INCLUDE_DIRS} ${CMAKE_CURRENT_SOURCE_DIR}/tools)

add_executable(test_harness
    tools/test_harness.cpp
    tools/dbx_checker.cpp
)
target_link_libraries(test_harness PRIVATE RootHerald)
target_include_directories(test_harness PRIVATE ${RH_INCLUDE_DIRS} ${CMAKE_CURRENT_SOURCE_DIR}/tools)

add_executable(tpm_diag tools/tpm_diag.cpp)
target_link_libraries(tpm_diag PRIVATE RootHerald advapi32)
target_include_directories(tpm_diag PRIVATE ${RH_INCLUDE_DIRS} ${CMAKE_CURRENT_SOURCE_DIR}/tools)

add_executable(boot_verify
    tools/boot_verify.cpp
    tools/dbx_checker.cpp
)
target_link_libraries(boot_verify PRIVATE RootHerald)
target_include_directories(boot_verify PRIVATE ${RH_INCLUDE_DIRS} ${CMAKE_CURRENT_SOURCE_DIR}/tools)

# -----------------------------------------------------------------------------
# Install rules — for downstreams that use `cmake --install`.
# -----------------------------------------------------------------------------
install(TARGETS RootHerald ARCHIVE DESTINATION lib)
install(FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/../common/rootherald.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../common/protocol.h
    DESTINATION include
)
