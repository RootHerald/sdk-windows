# Changelog

ABI history for `common/rootherald.h`. The header documents the *current*
contract; this file documents how it got there.

The C ABI is identical across `sdk-windows`, `sdk-linux` and `sdk-macos`, and CI
fails on drift, so every entry below applies to all three unless stated otherwise.

## 4.0 — BREAKING

Consumers must recompile. Nothing on the wire changed; this is a surface removal.

**Removed — mock mode.**
`RootHeraldClient_SetMockTpm` and every canned-data path behind it. It was a plain
runtime setter with no build gate, so it shipped in Release and anything in the
consumer's process could flip it. `CollectPosture` under mock returned an all-green
snapshot — `oem_name = "MockOEM"`, a `…000mock` device id — which an embedder
rendering posture would show as a fully-attested device that never touched a TPM.
It could not forge an attestation (`CollectEvidence` never had a mock branch, and
the server rejects mock enrollment evidence at EK validation), but a shipped API
that fabricates trust signals does not belong in a library whose value is not
overclaiming. Test doubles belong in the test harness, not in the product.

**Removed — the legacy ABI 1.x surface.**
`RootHeraldEnroll`, `RootHeraldAttest`, `RootHeraldEnrollmentInfo` and
`RootHeraldAttestationInfo` are gone. These were the direct-POST "Passport" path
retired in 3.0, still advertised as public afterwards.

They were dead on every platform. On Windows they were declared but never defined,
so calling one failed at link time. On Linux and macOS the only consumers were the
`native_host` programs — which no `CMakeLists.txt` builds, no workflow references,
and no README documents. The Linux implementation additionally posted to
`/api/v1/attest`, an endpoint the server no longer exposes, so that path could not
have worked even if something had called it.

**Removed — internal helpers that were never public.**
`RootHeraldDeviceStatus`, `RootHeraldGetStatus` and `RootHeraldSetDeviceId` left
the shared headers. `protocol.h` already described them as "NOT the public
surface"; now the header agrees with the comment. Where a platform still uses one
internally it is declared in that repo's `src/client/client_internal.h`; on Linux
and macOS nothing did, so nothing was relocated.

**Removed — the last HTTP client (Linux).**
Deleting the legacy driver removed the only caller of the curl transport, so
`sdk-linux` no longer links libcurl and the archive contains no HTTP client at
all. "The client opens no socket to Root Herald" is now a property of the link
line rather than a convention.

**Changed — external symbol names (Linux).**
Every symbol crossing a translation unit now carries an `rh_` prefix
(`tpm_open` → `rh_tpm_open`, `event_log_read` → `rh_event_log_read`, and so on),
and anything with a single in-file caller became `static`. C has one flat link
namespace and this ships as a static archive that gets pulled into a stranger's
binary; unprefixed globals like `http_get` were a collision waiting to happen.
GNU Coding Standards §4.3 states the rule normatively.

**Moved — `RootHeraldResult` (`RH_PROTO_*`).**
Out of the shared `protocol.h` and into `sdk-windows/src/client/client_internal.h`,
now that Windows is its only consumer. `protocol.h` is the shared wire contract
and says platform-internal declarations do not belong in it; it now holds none.

**Changed — the header itself.**
Down from 504 lines to 238, first declaration from line 149 to line 29. The
version history that occupied roughly a hundred lines is this file. SAL annotations
(`_In_`, `_Out_`, `_Outptr_result_z_`, …) now document each pointer's direction and
nullability; they compile to nothing and are checked by MSVC `/analyze`, and a shim
keeps non-MSVC consumers building.

## 3.0 — BREAKING

Keyless, backend-relayed client. The client stopped holding a Root Herald key and
stopped opening a socket to Root Herald: its whole job became local TPM work
emitting opaque blobs the embedder's backend relays.

- Removed `RootHeraldClient_Verify`, `RootHeraldClient_AttestSession` and
  `RootHeraldClient_SetLinkToken`. A verdict is only a security control when
  enforced server-side, so it must never travel through the client. Account
  binding is the backend mapping a verified `deviceId` to its user. The
  `RootHeraldVerdict` enum and the `RootHeraldVerifyResult` /
  `RootHeraldAttestResult` / `RootHeraldEnrollResult` structs went with them.
- Replaced the direct-POST `RootHeraldClient_Enroll` with the keyless two-leg
  handshake `RootHeraldClient_EnrollBegin` / `RootHeraldClient_EnrollComplete`.
  The single elevation now spans both calls: the elevated worker stays resident
  across the relayed round-trip, because the transient EK+AK context
  `TPM2_ActivateCredential` needs cannot be rebuilt from the persisted handle.
- Removed `RootHeraldClient_SetEndpoint` and the `api_key` / `endpoint` parameters
  of `RootHeraldClient_Create`, which takes no arguments — there is no socket to
  point anywhere and no key to carry.
- Removed `RootHerald_RunElevatedEstablishKey`. Arranging the elevated resident
  worker is the embedder's responsibility.

## 2.0 — BREAKING

Removed `RootHeraldClient_EnrollCollect` and `RootHeraldClient_EnrollActivate`,
the 1.4 PCP-only page-driven enrollment split. Enrollment ran under a single
elevation via `RootHeraldClient_Enroll` instead. Dropped once raw-TBS credential
activation was proven to work under elevation, which made the PCP backend — whose
only advantage was avoiding the UAC prompt at the cost of an RSASSA-SHA1 AIK —
unnecessary. 3.0 reintroduced the relayed shape on the TBS base, not on PCP.

## 1.4

Added `RootHeraldClient_EnrollCollect` and `RootHeraldClient_EnrollActivate`:
the TPM-only halves of the two-round-trip enrollment ceremony with the network
boundary removed, for the Background-Check page-driven flow.

## 1.3

Added `RootHeraldClient_CollectEvidence` and `RootHeraldClient_FreeEvidence`.
Collect-only: no key, no Root Herald network call. Returns the self-contained
evidence blob for the embedder to hand to the customer's server.

## 1.2

Added `RootHeraldClient_CollectPosture`, a local-only readiness snapshot.
