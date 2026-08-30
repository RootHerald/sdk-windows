cmake_minimum_required(VERSION 3.20)
project(rootherald_windows VERSION 0.2.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# -----------------------------------------------------------------------------
# C runtime: DYNAMIC (/MD, /MDd), stated rather than inherited.
#
# This matters more here than for a normal project. RootHerald.lib is a STATIC
# archive that customers link into their own binary, so their CRT model has to
# match ours — mismatch it and the link fails on CRT symbols (__imp_toupper and
# friends) behind a wall of LNK4286 warnings that names nothing useful.
#
# /MD was already the effective setting, because it is CMake's default under
# policy CMP0091. Pinning it changes no output; it stops the ABI of a shipped
# release artifact from depending on which CMake defaults were in force on the
# machine that built it. Consumers must compile with /MD (note that bare `cl`
# with no runtime flag defaults to /MT and will NOT link).
#
# Documented for customers under "Linking" in README.md.
# -----------------------------------------------------------------------------
if(MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
endif()

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
    PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR}/common
    PRIVATE ${RH_INCLUDE_DIRS}
)
target_link_libraries(RootHerald PUBLIC ${RH_SYSTEM_LIBS})
add_library(rootherald ALIAS RootHerald)

# -----------------------------------------------------------------------------
# Install rules — for downstreams that use `cmake --install`.
# -----------------------------------------------------------------------------
install(TARGETS RootHerald ARCHIVE DESTINATION lib)
install(FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/common/rootherald.h
    ${CMAKE_CURRENT_SOURCE_DIR}/common/protocol.h
    DESTINATION include
)
