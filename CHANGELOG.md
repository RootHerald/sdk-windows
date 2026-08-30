# Changelog

ABI history for `common/rootherald.h`. The header documents the *current*
contract; this file documents how it got there.

The C ABI is identical across `sdk-windows`, `sdk-linux` and `sdk-macos`, and CI
fails on drift, so every entry below applies to all three unless stated otherwise.

## 5.0 — BREAKING

Consumers must recompile. Nothing on the wire changed. Thirteen exported symbols
become ten, and the status enum stops describing work no platform does.

**Removed — all logging.**
`RootHerald_SetLogCallback`, `RootHerald_SetLogLevel`, `RootHeraldLogLevel`,
`RootHeraldLogCallback` and the internal shim behind them. 99 call sites across the
three repos went with them, and with those the string literals they compiled into an
archive that ends up inside a stranger's signed binary.

The surface was not carrying its weight. 91 of the 99 sites logged at `WARN`, one at
`ERROR`, and **none** at `INFO` or `TRACE` — so a five-level filter had one level to
filter, and both shipping `windows-host` binaries were setting `INFO`, a level nothing
logged at. What replaced it is a status enum granular enough that a caller can log the
failure themselves, in their own stack, keyed to a documented symbol.

**Removed — `RootHeraldClient_SetApplicationId`.**
It advertised "a logical application id surfaced in audit logs and per-application
policy." The entire implementation was a `strdup` into the client struct; nothing
ever read it back, on any platform, and `ApplicationId` appears nowhere in the
server. It could not have been a policy input in any case — the value is an
unauthenticated self-declaration, so a caller wanting another application's policy
would simply claim to be it.

**Removed — `RootHeraldClient_GetDeviceInfo` and `RootHeraldDeviceInfo`.**
Merged into `CollectPosture`, which on every platform already performed a strict
superset of the same work — the same functions in the same order, then more — and
returned a strict superset of the same fields. The one field only `GetDeviceInfo`
carried, `platform_name`, moves onto `RootHeraldPosture`. It was a compile-time
constant, not something the extra call went and discovered.

**Changed — the status enum now names actions, not layers.**
`ERR_NETWORK` (3) and `ERR_QUOTA_EXCEEDED` (5) are gone: neither had a single
producer anywhere, both describing the direct-POST network client 3.0 deleted.
`ERR_SERVER` (4) is gone because it was worse than dead — it was reachable, and it
reported *local* TPM and crypto failures as "the server returned an error", sending
integrators to debug the wrong system. `windows-host` had already written a
workaround translating it back to the truth.

In their place, five codes that each name a different next action:

| Code | Means | Do |
|---|---|---|
| `ERR_EK_READ_FAILED` (8) | TPM present, EK unreadable | Check the resource manager, permissions, driver |
| `ERR_AK_FAILED` (9) | AK create/load/persist failed | Retry enrollment |
| `ERR_ACTIVATION_FAILED` (10) | Challenge could not be consumed | Restart from `EnrollBegin` — it is single-use and now spent |
| `ERR_QUOTE_FAILED` (11) | PCR read or quote failed | Retry the attestation; do **not** re-enroll |
| `ERR_ENTITLEMENT_MISSING` (12) | Host binary lacks the keychain entitlement | Fix code signing (macOS/iOS) |

3, 4 and 5 are **not reused**. A consumer built against an older header must fail to
compile rather than silently re-map onto a new meaning.

`RootHerald_ErrorString` stays. It is a convenience for a `printf` during integration
and for a CI harness's failure output, not the documentation — the per-code
cause-and-remedy reference is on the developer portal, keyed by symbol rather than by
number.

**Changed — the driver returns `RootHeraldStatus` directly (Windows).**
The internal `RootHeraldResult` / `RH_PROTO_ERR_*` vocabulary is gone. It existed so
the driver could speak its own error language and the facade could translate once, but
it collapsed twice: an `HRESULT` became a coarse `RH_PROTO_ERR_*`, which became a
coarser public status. Nine distinct TPM failures arrived at the caller as "internal
library error". A failure is now named once, where it happens.

**Documented — `protocol.h` covers all three ceremonies.**
It described only the TPM ceremony while claiming to be the contract shared by all
three SDKs, so an integrator writing a cross-platform relay against it got macOS
wrong: the fields it named (`credentialBlob`, `encryptedSecret`, `decryptedSecret`)
do not exist there. It is now an envelope plus per-platform variants — TPM 2.0, Apple
Secure Enclave, and Apple App Attest — with the discriminator and the anti-downgrade
rule stated once.

**Noted — `boot_log_revoked` is not computed.**
It has always reported `-1`. The header previously implied the data was merely
unavailable; in fact nothing cross-references measured digests against the dbx
revocation list, and the dbx *list size* that is known is a property of the firmware
rather than a finding about the device. The field stays — consumers render it and
degrade correctly on `-1` — and the header now says plainly that it is uncomputed.

**Removed — dead internals (Windows).**
`RootHeraldGetStatus`, `RootHeraldDeviceStatus`, `RootHeraldSetDeviceId` and the
`g_deviceId` override it wrote to. Nothing set the override, so the read always fell
through to `DeriveLocalDeviceId()`. `client_internal.h` also stopped claiming the
native messaging host calls across that boundary; it links only the public ABI.

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
