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
set(ROOTHERALD_EXTENSION_ID "rootheraldofficialextensionidplaceholder"
    CACHE STRING "Chrome/Edge extension ID granted access to the native host")

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/native_host/com.rootherald.native.json.in
    ${CMAKE_CURRENT_BINARY_DIR}/com.rootherald.native.json
    @ONLY)

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

# -----------------------------------------------------------------------------
# native_host.exe — browser-extension native-messaging host shell.
# Renamed from rootherald_host so the installer can pick the new name up.
# A `rootherald_host` alias target is provided for backwards compat.
#
# The shell is thin: it static-links RootHerald.lib for all TPM/HTTP work
# and carries only the JSON framing + stdio loop. There is no runtime DLL
# dependency on RootHerald — the resulting EXE is fully self-contained.
# -----------------------------------------------------------------------------
add_executable(native_host
    native_host/native_host.cpp
)

target_include_directories(native_host PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../common
)
# Static-link RootHerald and pick up its transitive system deps.
target_link_libraries(native_host PRIVATE RootHerald)

# Legacy name kept as an alias for any external consumer that references it.
add_executable(rootherald_host ALIAS native_host)

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

# -----------------------------------------------------------------------------
# rootherald_tray.exe — system-tray shell. Static-links RootHerald.lib for
# all real work (TPM access, secure-boot collection, transport). The shell
# itself is the icon + status-window glue.
#
# Because RootHerald is now a static archive, the tray executable is fully
# self-contained: no companion DLL ships next to it.
# -----------------------------------------------------------------------------
add_executable(rootherald_tray WIN32
    tray/rootherald_tray.cpp
    tray/rootherald_tray.rc
    http_winhttp.cpp
)
target_include_directories(rootherald_tray PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../common
)
# Static-link the embeddable archive + UI/system libs the shell itself
# needs (shell32/user32/gdi32 for the tray icon, etc.).
target_link_libraries(rootherald_tray PRIVATE
    RootHerald shell32 user32 gdi32
)

# Legacy name retained as alias for in-tree references.
add_executable(rootherald_app ALIAS rootherald_tray)

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

# Stage the substituted native-host manifest where the installer expects it
# (..\build\native-host\com.rootherald.native.json relative to the installer
# script). Driven by a post-configure custom target so a plain
# `cmake --build .` leaves it in place for the Inno Setup step.
set(_native_host_stage "${CMAKE_BINARY_DIR}/../native-host")
file(MAKE_DIRECTORY "${_native_host_stage}")
add_custom_target(rootherald_native_host_manifest ALL
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${CMAKE_CURRENT_BINARY_DIR}/com.rootherald.native.json"
        "${_native_host_stage}/com.rootherald.native.json"
    COMMENT "Staging native-host manifest (extension id = ${ROOTHERALD_EXTENSION_ID})")

# CMake install rule for consumers who use `cmake --install`. The installer
# (Inno Setup) reads from the staged path above; this rule covers the
# `cmake --install` workflow that other downstreams may use.
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/com.rootherald.native.json"
        DESTINATION bin)

# -----------------------------------------------------------------------------
# rootherald_installer.exe — single-file preprod installer.
#
# This is the customer-facing artifact. It embeds rootherald_tray.exe and
# native_host.exe as RT_RCDATA resources, extracts them to
# %LOCALAPPDATA%\RootHerald\, writes the native-messaging-host manifest,
# registers it under HKCU for Chrome + Edge, wires the tray to run on
# login, and launches it. The end user double-clicks one .exe and is done.
#
# Because the .rc file references the BUILT paths of the other two targets,
# we have to generate the .rc post-configure and force the installer build
# to depend on the other two completing first.
# -----------------------------------------------------------------------------
set(_installer_rc "${CMAKE_CURRENT_BINARY_DIR}/rootherald_installer.rc")
set(_brand_icon "${CMAKE_CURRENT_SOURCE_DIR}/assets/rootherald.ico")
add_custom_command(
    OUTPUT  "${_installer_rc}"
    DEPENDS rootherald_tray native_host
            "${CMAKE_CURRENT_SOURCE_DIR}/installer/rootherald_installer.rc.in"
            "${_brand_icon}"
    COMMAND ${CMAKE_COMMAND}
        -DIN=${CMAKE_CURRENT_SOURCE_DIR}/installer/rootherald_installer.rc.in
        -DOUT=${_installer_rc}
        -DTRAY_PATH=$<TARGET_FILE:rootherald_tray>
        -DHOST_PATH=$<TARGET_FILE:native_host>
        -DICON_PATH=${_brand_icon}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/installer/generate_rc.cmake
    VERBATIM
    COMMENT "Generating rootherald_installer.rc with embedded payloads")

add_executable(rootherald_installer WIN32
    installer/rootherald_installer.cpp
    "${_installer_rc}"
)
target_compile_definitions(rootherald_installer PRIVATE
    ROOTHERALD_EXTENSION_ID="${ROOTHERALD_EXTENSION_ID}"
)
target_link_libraries(rootherald_installer PRIVATE
    shell32 user32 advapi32 ole32
)

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
