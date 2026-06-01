cmake_minimum_required(VERSION 3.20)
project(rootherald_windows VERSION 0.2.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# -----------------------------------------------------------------------------
# Wave 6 artifact layout (STATIC library)
#
#   RootHerald.lib          — embeddable STATIC library; exposes the public
#                              C ABI from <rootherald.h> and the legacy
#                              RootHerald* symbols used by the tray and
#                              native-messaging shells. Customers link this
#                              archive directly into their own binary, which
#                              is then signed by *their* EV / code-signing
#                              cert — Root Herald's name does not appear in
#                              the customer's binary signature.
#   rootherald_tray.exe     — system-tray shell. Static-links RootHerald.lib.
#   native_host.exe         — browser-extension native-messaging host.
#                              Static-links RootHerald.lib.
#
# The diagnostic / test executables (test_client, test_harness, tpm_diag,
# boot_verify) are retained for engineer use but are not part of the
# customer-shippable surface.
#
# Note: the .NET NuGet (`RootHerald.Native.dll`), Node N-API addon
# (`.node`), and Python wheel keep their own dynamic-library packaging
# because those runtimes require it; they wrap this same static archive
# internally and ship it inside our org's signed package.
# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
# Chrome / Edge extension ID for the native-messaging host manifest.
#
# Chrome enforces the `allowed_origins` list as part of the native-messaging
# protocol — only the listed extension may invoke the host. The published
# extension's ID is computed from its public key and is stable across
# releases, so the production build pins the real value:
#
#   cmake ... -DROOTHERALD_EXTENSION_ID=abcdefghijklmnopabcdefghijklmnop
#
# Dev / forked builds keep the placeholder below so the build does not fail;
# at install time the native host will not be reachable from any real
# extension, which is the right default.
# -----------------------------------------------------------------------------
# Note: native_host, tray, and installer were moved to the separate
# RootHerald/windows-host repository. This CMakeLists builds only the
# public SDK (RootHerald.lib) plus the developer diagnostic tools
# (test_client, test_harness, tpm_diag, boot_verify) that integrators
# may want to reference.

# -----------------------------------------------------------------------------
# RootHerald.lib — the embeddable STATIC native SDK library.
#
# Carries two surfaces from the same archive:
#   1. The public C ABI from <rootherald.h>   (RootHeraldClient_*, etc.)
#   2. The legacy RootHerald* symbols used by the tray and native-messaging
#      shells. These will be deprecated once a future wave routes them
#      through the public ABI, but live alongside it for now to keep the
#      shells thin.
#
# Linkage is INTERFACE-propagated: any executable that does
# `target_link_libraries(<exe> PRIVATE RootHerald)` automatically pulls in
# the same system dependencies the library itself needs (ncrypt, tbs, ...).
# -----------------------------------------------------------------------------
add_library(RootHerald STATIC
    rootherald_client.cpp
    rootherald_win.cpp
    tpm_pcp.cpp
    tpm_commands.cpp
    tbs_key_provider.cpp
    event_log.cpp
    event_log_parser.cpp
    secureboot_validator.cpp
    dbx_checker.cpp
    http_winhttp.cpp
    amd_aia_fetch.cpp
    win_cert_store_intermediates.cpp
)

target_include_directories(RootHerald PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../common
)

# PUBLIC, not PRIVATE — for a static library, the consuming executable is
# the one that ultimately resolves these symbols at link time. Marking
# them PUBLIC propagates the dependency through the static-link transitive
# closure, so customer integrations only need
# `target_link_libraries(... RootHerald)`.
target_link_libraries(RootHerald PUBLIC
    ncrypt
    tbs
    winhttp
    bcrypt
    crypt32
)

# Alias retained so existing in-tree consumers that link against `rootherald`
# continue to resolve. Inno Setup and dev-time scripts gain the new name.
add_library(rootherald ALIAS RootHerald)

# Test client (exercises full flow against real TPM)
# Links against source directly instead of DLL so it can access internal helpers
add_executable(test_client
    test_client.cpp
    rootherald_win.cpp
    tpm_pcp.cpp
    tpm_commands.cpp
    tbs_key_provider.cpp
    event_log.cpp
    event_log_parser.cpp
    secureboot_validator.cpp
    dbx_checker.cpp
    http_winhttp.cpp
    amd_aia_fetch.cpp
    win_cert_store_intermediates.cpp
)

target_include_directories(test_client PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../common
)

target_link_libraries(test_client PRIVATE
    ncrypt tbs winhttp bcrypt crypt32
)

# Diagnostic tool
add_executable(tpm_diag
    tpm_diag.cpp
    win_cert_store_intermediates.cpp
)
target_include_directories(tpm_diag PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../common
)
target_link_libraries(tpm_diag PRIVATE ncrypt tbs crypt32 bcrypt advapi32)

# Security gap test harness
add_executable(test_harness
    test_harness.cpp
    tpm_pcp.cpp
    tpm_commands.cpp
    event_log.cpp
    event_log_parser.cpp
    secureboot_validator.cpp
    dbx_checker.cpp
    http_winhttp.cpp
    amd_aia_fetch.cpp
)
target_include_directories(test_harness PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../common
)
target_link_libraries(test_harness PRIVATE ncrypt tbs winhttp bcrypt crypt32)

# Boot verification tool (event log analysis)
add_executable(boot_verify
    boot_verify.cpp
    event_log_parser.cpp
    dbx_checker.cpp
    tpm_commands.cpp
    secureboot_validator.cpp
)
target_include_directories(boot_verify PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../common
)
target_link_libraries(boot_verify PRIVATE tbs)
