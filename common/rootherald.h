/**
 * Root Herald — public C ABI for embeddable native SDK.
 *
 * This header is the stable, language-agnostic surface for the Root Herald
 * native SDK. It is C99-compatible (no C++ features) so it can be consumed
 * from C, C++, Rust, Go, Zig, Swift (via clang module), and P/Invoke
 * (.NET) without an intermediate shim layer.
 *
 * Keyless / backend-relayed model (ABI 3.0)
 * -----------------------------------------
 * The client holds NO RootHerald key and opens NO socket to RootHerald. It does
 * local TPM work and emits/consumes opaque JSON blobs; the embedder's BACKEND
 * (a server SDK, authenticated with its rh_sk_ secret) relays those blobs to
 * RootHerald. The client therefore takes no endpoint and no api_key — there is
 * nothing for it to connect to. "Where does the traffic go" is entirely the
 * embedder's concern (its own client<->backend channel + its backend's RootHerald
 * calls). The only network the library itself performs is best-effort fetches to
 * TPM-vendor PKI (e.g. AMD's AIA endpoint) to complete an EK certificate chain —
 * never a call to RootHerald.
 *
 * Memory ownership
 * ----------------
 * All RootHeraldClient* handles must be paired with RootHeraldClient_Destroy.
 * Result structs (RootHeraldDeviceInfo, RootHeraldPosture) are caller-allocated;
 * the library only writes into them. The blob-emitting calls (EnrollBegin,
 * EnrollComplete, CollectEvidence) return a newly-allocated NUL-terminated
 * char* the CALLER owns and MUST free with RootHeraldClient_FreeEvidence.
 *
 * Thread-safety
 * -------------
 * A RootHeraldClient* may be used from any thread, but is not safe for
 * concurrent calls from multiple threads. Serialize calls behind a mutex
 * if you need shared use.
 */

#ifndef ROOTHERALD_H
#define ROOTHERALD_H

#include <stdint.h>
#include <stddef.h>

#define ROOTHERALD_ABI_VERSION_MAJOR 3
#define ROOTHERALD_ABI_VERSION_MINOR 0

/*
 * ABI changelog
 * -------------
 * 3.0 — KEYLESS, BACKEND-RELAYED CLIENT. BREAKING. The client now holds NO
 *       RootHerald key and opens NO socket to RootHerald: its entire job is local
 *       TPM work that emits/consumes opaque blobs the embedder's backend relays.
 *       Changes:
 *         * REMOVED RootHeraldClient_Verify, RootHeraldClient_AttestSession,
 *           RootHeraldClient_SetLinkToken (the client-gets-a-verdict / OIDC
 *           authorization-code surface). A verdict is only a security control
 *           when enforced SERVER-side (needs rh_sk_, needs a customer backend),
 *           so it never travels through the client. Account binding = the backend
 *           maps a verified deviceId to its user. With them go the
 *           RootHeraldVerdict enum and the RootHeraldVerifyResult /
 *           RootHeraldAttestResult / RootHeraldEnrollResult structs.
 *         * REMOVED the direct-POST RootHeraldClient_Enroll. Enrollment is now a
 *           keyless two-leg, blob-emitting handshake:
 *             RootHeraldClient_EnrollBegin(client, &request_json)      — gen AK +
 *               gather EK pub/cert under a SINGLE elevation (raw-TBS), emit the
 *               /devices/enroll request body. No network, no key.
 *             RootHeraldClient_EnrollComplete(client, challenge_json,
 *               &activation_json) — TPM2_ActivateCredential over the server's
 *               MakeCredential challenge, emit the /devices/activate request body.
 *               No network, no key.
 *           The customer's backend relays the two legs (POST /devices/enroll then
 *           /devices/activate, authenticated with its rh_sk_). The single
 *           elevation SPANS begin -> complete: the elevated worker stays resident
 *           across the relayed round-trip so the transient EK+AK handle context
 *           that ActivateCredential needs survives. Both buffers are caller-owned
 *           and freed with RootHeraldClient_FreeEvidence.
 *         * REMOVED RootHeraldClient_SetEndpoint and the api_key/endpoint
 *           parameters of RootHeraldClient_Create (now RootHeraldClient_Create()):
 *           the client opens no RootHerald socket, so it has no endpoint and no
 *           key to carry.
 *         * REMOVED RootHerald_RunElevatedEstablishKey. Its POST-bearing
 *           "elevated child enrolls and writes deviceId" contract is replaced by
 *           the keyless EnrollBegin/EnrollComplete pair (which require elevation
 *           for the TPM ops). The elevated worker that pumps those two calls
 *           across the relay is the embedder's/host's responsibility.
 *       KEPT, UNCHANGED: RootHeraldClient_CollectEvidence (per-attestation, keyless
 *       quote-over-nonce), RootHeraldClient_CollectPosture (local readiness),
 *       RootHeraldClient_GetDeviceInfo (local), RootHeraldClient_FreeEvidence,
 *       handle lifecycle, mock mode, logging.
 * 2.0 — REMOVED RootHeraldClient_EnrollCollect + RootHeraldClient_EnrollActivate
 *       (the 1.4 PCP-only page-driven enroll split). BREAKING. Enrollment ran
 *       under a single elevation via RootHeraldClient_Enroll (elevated-TBS):
 *       the host/embedder triggered that one-shot elevated ceremony rather than
 *       relaying TPM halves through the customer server. Removed once raw-TBS
 *       credential activation was proven to succeed under elevation, making the
 *       PCP (SHA-1-AIK) backend — whose only value was dodging the UAC —
 *       unnecessary. (3.0 re-introduces the keyless relayed shape on this TBS
 *       single-elevation base, NOT on PCP.)
 * 1.4 — ADDED RootHeraldClient_EnrollCollect + RootHeraldClient_EnrollActivate
 *       (Background-Check page-driven enrollment, contract C-enroll). Additive
 *       only; every 1.3 symbol is unchanged. These are the TPM-only halves of
 *       the two-round-trip enroll ceremony with the NETWORK boundary removed:
 *       keyless and network-free, exactly like the 1.3 collect pair. The page
 *       RELAYS the two server round-trips (POST /devices/enroll then
 *       /devices/activate) through the CUSTOMER's server (WP4 Option A); the
 *       client never POSTs to RootHerald on this path. EnrollCollect returns the
 *       /enroll request body; the page posts it and hands the server's
 *       MakeCredential challenge to EnrollActivate, which returns the /activate
 *       request body. Both buffers are caller-owned and freed with the existing
 *       RootHeraldClient_FreeEvidence (a generic char* free). The key-bearing
 *       RootHeraldClient_Enroll stays for non-browser embedders that POST direct.
 * 1.3 — ADDED RootHeraldClient_CollectEvidence + RootHeraldClient_FreeEvidence
 *       (Background-Check "dumb client", contract C5). Additive only; every
 *       1.2 symbol is unchanged. Collect-only: NO API/site key required and NO
 *       RootHerald network call — returns the self-contained evidence blob to
 *       the embedder, who hands it to the CUSTOMER's server (which relays it
 *       server→server to POST /api/v1/attestations/verify). The existing
 *       key-bearing Create / AttestSession / Verify entry points remain for the
 *       Passport / "badge" tier (backend-less customers that POST directly to
 *       RootHerald with a publishable key).
 * 1.2 — RootHeraldClient_CollectPosture (local-only readiness snapshot).
 */

/*
 * Linkage model (Wave 6 — static library)
 * ---------------------------------------
 * The Root Herald native library ships as a *static* archive
 * (`RootHerald.lib` on Windows, `librootherald.a` on Linux, `librootherald.a`
 * inside a static framework on macOS). Customers link it into their own
 * binary at compile time, which is then signed by their own EV / Developer ID
 * certificate. There is no runtime .dll / .so / .dylib dependency on us.
 *
 * As a result there is no `__declspec(dllexport/dllimport)` decoration on
 * the public ABI: every public symbol is a plain `extern "C"` function with
 * default visibility. `ROOTHERALD_API` is retained as a backwards-compatible
 * no-op so older translation units that reference it still compile.
 *
 * The handful of cases that *do* still ship a dynamic library — the .NET
 * NuGet's `RootHerald.Native.dll`, the Node N-API `.node` addon, and the
 * Python wheel-internal shared lib — wrap this same static library themselves
 * and re-export via their host runtime's normal mechanism (P/Invoke, N-API,
 * ctypes). They do not need the public ABI to carry Windows DLL decorations.
 */
#define ROOTHERALD_API /* static linkage — no decoration */

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque client handle. */
typedef struct RootHeraldClient RootHeraldClient;

/* Result codes returned by client entry points. */
typedef enum {
    ROOTHERALD_OK = 0,
    ROOTHERALD_ERR_INVALID_ARG = 1,
    ROOTHERALD_ERR_TPM_UNAVAILABLE = 2,
    ROOTHERALD_ERR_NETWORK = 3,
    ROOTHERALD_ERR_SERVER = 4,
    ROOTHERALD_ERR_QUOTA_EXCEEDED = 5,
    ROOTHERALD_ERR_NOT_ENROLLED = 6,
    /*
     * Enrollment requires an elevated (administrator) process, but the current
     * process is not elevated. Returned by RootHeraldClient_EnrollBegin /
     * _EnrollComplete. The SDK does NOT elevate on your behalf — it reports this
     * so YOU can choose an elevation strategy. Recover by running EnrollBegin /
     * EnrollComplete in an elevated, resident worker (the single elevation must
     * span both calls), then retry. Windows-only; see INTEGRATING.md ("Windows
     * elevation").
     */
    ROOTHERALD_ERR_ELEVATION_REQUIRED = 7,
    ROOTHERALD_ERR_INTERNAL = 99
} RootHeraldStatus;

/*
 * NOTE (ABI 3.0): the client-side verdict surface is gone. There is no
 * RootHeraldVerdict enum and no RootHeraldVerifyResult / RootHeraldAttestResult /
 * RootHeraldEnrollResult struct — a verdict is computed and enforced by the
 * customer's BACKEND (it never travels through the client), and enrollment now
 * emits opaque JSON blobs rather than filling a result struct. See the changelog.
 */

/* Result of RootHeraldClient_GetDeviceInfo. Caller-allocated. */
typedef struct {
    int is_enrolled;
    int has_tpm;
    char device_id[129];
    char platform_name[16];     /* "windows" | "linux" | "macos" */
} RootHeraldDeviceInfo;

/* Result of RootHeraldClient_CollectPosture. Caller-allocated. */
typedef struct {
    int has_tpm;                  /* 1 = TPM 2.0 reachable */
    int is_enrolled;              /* 1 = an attestation key exists locally */
    int ek_cert_present;          /* 1 = vendor EK certificate found */
    int secure_boot;              /* 1 on, 0 off, -1 undetermined */
    int oem_keyed;                /* 1 known-OEM PK, 0 custom/unknown, -1 undetermined */
    char oem_name[64];            /* "" when unknown */
    int boot_log_measurements;    /* measured-boot entries; -1 unavailable */
    int boot_log_revoked;         /* dbx-revoked entries; -1 unavailable */
    char device_id[129];          /* deterministic local id, "" if underivable */
    char detail_json[2048];       /* machine-readable detail snapshot */
} RootHeraldPosture;

/* ------------------------------------------------------------------ */
/* Lifecycle                                                          */
/* ------------------------------------------------------------------ */

/**
 * Create a new client. Takes no api_key and no endpoint — the client is keyless
 * and opens no socket to RootHerald (ABI 3.0). The handle holds only local config
 * (application id, mock mode) and per-process TPM context. Returns NULL on
 * out-of-memory.
 */
ROOTHERALD_API RootHeraldClient* RootHeraldClient_Create(void);

/**
 * Destroy a client. Safe to call with NULL.
 */
ROOTHERALD_API void RootHeraldClient_Destroy(RootHeraldClient* client);

/* ------------------------------------------------------------------ */
/* Config                                                             */
/* ------------------------------------------------------------------ */

/**
 * Associate this client with a logical application id (e.g. "launcher",
 * "matchmaker"). Surfaced in audit logs and per-application policy.
 */
ROOTHERALD_API RootHeraldStatus RootHeraldClient_SetApplicationId(
    RootHeraldClient* client,
    const char* app_id);

/**
 * Enable mock-TPM mode. When true, the client emits canned attestation
 * evidence and never touches real TPM / Secure-Enclave hardware. Intended
 * for headless build agents and CI; never enable in production.
 */
ROOTHERALD_API RootHeraldStatus RootHeraldClient_SetMockTpm(
    RootHeraldClient* client,
    int mock_enabled);

/* ------------------------------------------------------------------ */
/* Enrollment (keyless, backend-relayed two-leg handshake)            */
/* ------------------------------------------------------------------ */
/*
 * Enrollment is a one-time (or rotation) bootstrap of the device attestation
 * key. It is irreducibly TWO server round-trips with a TPM op between them, and
 * RootHerald computes a MakeCredential challenge to the EK that the TPM must
 * decrypt with ActivateCredential. ABI 3.0 splits the TPM-only halves out and
 * removes the network: the client emits/consumes opaque JSON blobs the embedder's
 * BACKEND relays to RootHerald (authenticated with its rh_sk_):
 *
 *   1. EnrollBegin(client, &request_json)
 *        -> local: gen AK + gather EK pub/cert chain under a SINGLE elevation
 *           (raw-TBS). Emits the verbatim POST /api/v1/devices/enroll body.
 *      [backend relays it; RootHerald validates the EK chain + AK template,
 *       MakeCredential-seals a secret to the EK, returns {deviceId,
 *       credentialBlob, encryptedSecret} — the deviceId is known after leg 1.]
 *   2. EnrollComplete(client, challenge_json, &activation_json)
 *        -> local: TPM2_ActivateCredential over that challenge. Emits the
 *           verbatim POST /api/v1/devices/activate body ({deviceId,
 *           decryptedSecret}).
 *      [backend relays it; RootHerald constant-time compares the secret and
 *       Name-match guards the bound AK -> enrolled.]
 *
 * NEITHER call opens a socket or consults a key. Both returned buffers are
 * caller-owned and freed with RootHeraldClient_FreeEvidence.
 *
 * ELEVATION + SINGLE-ELEVATION SPAN: raw-TBS AK creation (begin) and
 * TPM2_ActivateCredential (complete) require an ELEVATED process; an
 * unprivileged caller gets ROOTHERALD_ERR_ELEVATION_REQUIRED. The library never
 * elevates on your behalf. Critically, the transient EK+AK TPM context that
 * ActivateCredential needs is established in begin and cannot be reconstructed
 * from the persisted handle alone, so the SAME (elevated) process must remain
 * resident from EnrollBegin through EnrollComplete — the one elevation spans the
 * relayed network round-trip. The embedder/host arranges that (e.g. an elevated
 * worker that emits the begin blob over IPC, waits for the relayed challenge,
 * then calls complete).
 *
 * PLATFORM SUPPORT: functional on Windows. Linux/macOS declare the symbols for
 * ABI uniformity but return ROOTHERALD_ERR_INTERNAL until their collectors land.
 */

/**
 * Begin enrollment: create an AK and gather EK pub + EK cert chain under a single
 * elevation, then emit the POST /api/v1/devices/enroll request body.
 *   out_request_json : on ROOTHERALD_OK, a newly-allocated NUL-terminated JSON
 *                      string ({ekPublicKey, akPublicArea, platform, optional
 *                      ekCertPem, optional ekCertificateChain}). Caller OWNS it;
 *                      free with RootHeraldClient_FreeEvidence. NULL on error.
 * Returns ROOTHERALD_ERR_ELEVATION_REQUIRED if the process is not elevated.
 */
ROOTHERALD_API RootHeraldStatus RootHeraldClient_EnrollBegin(
    RootHeraldClient* client,
    char** out_request_json);

/**
 * Complete enrollment: run TPM2_ActivateCredential over the server's
 * MakeCredential challenge and emit the POST /api/v1/devices/activate body.
 *   challenge_json     : the verbatim /enroll response the backend relayed back
 *                        ({deviceId, credentialBlob, encryptedSecret}). Required.
 *   out_activation_json: on ROOTHERALD_OK, a newly-allocated NUL-terminated JSON
 *                        string ({deviceId, decryptedSecret}). Caller OWNS it;
 *                        free with RootHeraldClient_FreeEvidence. NULL on error.
 * MUST be called in the same resident (elevated) process as the matching
 * EnrollBegin (see "single-elevation span" above). Returns
 * ROOTHERALD_ERR_NOT_ENROLLED if no in-flight EnrollBegin state is present.
 */
ROOTHERALD_API RootHeraldStatus RootHeraldClient_EnrollComplete(
    RootHeraldClient* client,
    const char* challenge_json,
    char** out_activation_json);

/* ------------------------------------------------------------------ */
/* Local device info                                                  */
/* ------------------------------------------------------------------ */

/**
 * Local device/TPM status; never touches the network.
 */
ROOTHERALD_API RootHeraldStatus RootHeraldClient_GetDeviceInfo(
    RootHeraldClient* client,
    RootHeraldDeviceInfo* out_result);

/**
 * LOCAL-ONLY device-readiness snapshot: never touches the network.
 *
 * Collects everything the device can know about itself without a server
 * round-trip — TPM reachability, local enrollment, EK certificate
 * presence, Secure Boot state, OEM platform-key identity, and measured-
 * boot log counts. This is the free pre-flight check: call it cheaply
 * (e.g. from a game launcher) before spending a billable attestation
 * (CollectEvidence + the backend's /verify).
 *
 * Honesty rule: these are READINESS SIGNALS, not a verdict — the verdict
 * is always server-side (tenant policy + trust-anchor chain validation),
 * and is unknowable locally. Never render these signals as "you will
 * pass".
 *
 * Tri-state ints (secure_boot / oem_keyed) use -1 for "undetermined"
 * (e.g. the TCG event log was unavailable); count fields use -1 for
 * "unavailable".
 */
ROOTHERALD_API RootHeraldStatus RootHeraldClient_CollectPosture(
    RootHeraldClient* client,
    RootHeraldPosture* out_result);

/* ------------------------------------------------------------------ */
/* Per-attestation evidence collection (keyless)                      */
/* ------------------------------------------------------------------ */
/*
 * The per-attestation verb for the RATS Background-Check model. The on-device
 * client collects a self-contained evidence blob (a fresh TPM quote over a
 * backend-issued nonce) and returns it to the embedder — it makes NO RootHerald
 * network call and needs NO key.
 *
 * BOUNDARY — READ THIS. This is a CLIENT library. It collects evidence; it
 * NEVER verifies anything and NEVER holds a secret. The `rh_sk_` secret key and
 * the token/verdict verification step live in a SEPARATE component: the
 * CUSTOMER'S BACKEND (their own server). The flow is:
 *   1. (here, client)   collect the evidence blob — no secret, no verdict.
 *   2. (customer server) relay the blob server→server, authenticated with the
 *                        customer's `rh_sk_` secret key, to
 *                        `POST /api/v1/attestations/verify`.
 *   3. (RootHerald)     appraise it and return a verdict to the customer server,
 *                        which ENFORCES it (the verdict never travels through the
 *                        client).
 * The `rh_sk_` secret MUST NOT ever be compiled into, passed to, or stored by
 * this library — putting it on the device defeats the model. To implement
 * step 2 in the customer backend, use a SERVER SDK (a different component):
 * @rootherald/node, sdk-go, sdk-dotnet, sdk-java, sdk-php, or sdk-ruby at
 * https://github.com/RootHerald.
 *
 * Step-up / re-attest (RFC 9470) is just calling this again with a fresh nonce.
 */

/**
 * Collect attestation evidence WITHOUT contacting RootHerald and WITHOUT
 * requiring an API key.
 *
 *   nonce_b64         : the server-issued challenge nonce (base64, NUL-
 *                       terminated) the customer obtained from
 *                       `POST /api/v1/attestations/challenge` and relayed to
 *                       this client. The TPM quote is taken OVER this nonce, so
 *                       freshness / anti-replay is preserved end-to-end exactly
 *                       as on the direct path (the nonce is bound inside the
 *                       signature). Required.
 *   out_evidence_json : on ROOTHERALD_OK, receives a newly-allocated,
 *                       NUL-terminated JSON string — the self-contained evidence
 *                       blob. This is EXACTLY the object the server's
 *                       `/attestations/verify` expects in its `evidence` field
 *                       (an AttestationRequest-shaped payload: quote-over-nonce,
 *                       PCRs, event log, EK cert chain, secure-boot chain). The
 *                       customer's server forwards it verbatim. The caller OWNS
 *                       the buffer and MUST free it with
 *                       RootHeraldClient_FreeEvidence. Set to NULL on any error.
 *
 * Keyless — no key is consulted; this call collects only.
 * Returns ROOTHERALD_OK on success; ROOTHERALD_ERR_NOT_ENROLLED if no enrolled
 * attestation key exists on the device; ROOTHERALD_ERR_TPM_UNAVAILABLE /
 * ROOTHERALD_ERR_SERVER on a TPM / quote failure; ROOTHERALD_ERR_INVALID_ARG on
 * a bad argument.
 *
 * PLATFORM SUPPORT: functional on Windows. Linux and macOS declare the entry
 * point (so the ABI is uniform) but return ROOTHERALD_ERR_INTERNAL until their
 * per-platform collectors land.
 */
ROOTHERALD_API RootHeraldStatus RootHeraldClient_CollectEvidence(
    const char* nonce_b64,
    char** out_evidence_json);

/**
 * Free an evidence buffer returned by RootHeraldClient_CollectEvidence. Safe to
 * call with NULL. Pairs with the caller-frees ownership of out_evidence_json.
 * Also frees the evidence buffer returned by RootHeraldClient_CollectEvidence —
 * it is a generic char* deallocator.
 */
ROOTHERALD_API void RootHeraldClient_FreeEvidence(char* evidence_json);

/* ------------------------------------------------------------------ */
/* Logging                                                            */
/* ------------------------------------------------------------------ */
/*
 * The library is silent by default — no writes to stdout/stderr unless the
 * customer explicitly registers a callback. This matches the precedent set
 * by libfido2, libsodium, libcurl, and mbedTLS: a library embedded in a
 * customer's binary should not impose log destinations on its host.
 *
 * Customers wire their preferred logger (spdlog, log4cpp, Sentry SDK, etc.)
 * by registering a callback. Filtering happens internally: messages above
 * the configured max level are dropped before any formatting work, so
 * production builds can leave callbacks installed at ERROR without paying
 * for TRACE-level message construction.
 */

typedef enum {
    ROOTHERALD_LOG_ERROR = 0,
    ROOTHERALD_LOG_WARN  = 1,
    ROOTHERALD_LOG_INFO  = 2,
    ROOTHERALD_LOG_DEBUG = 3,
    ROOTHERALD_LOG_TRACE = 4
} RootHeraldLogLevel;

/**
 * Receives a single formatted log message from the library. The `message`
 * pointer is null-terminated and owned by the library; copy if you need to
 * retain it past the call. `user_data` is whatever was passed to
 * RootHerald_SetLogCallback. The callback may be invoked from any thread
 * the library does work on; implementations should be thread-safe.
 */
typedef void (*RootHeraldLogCallback)(
    RootHeraldLogLevel level,
    const char* message,
    void* user_data);

/**
 * Register a log callback. Pass NULL to disable logging entirely (default).
 * Replaces any prior registration. Pass `user_data` to receive an arbitrary
 * context pointer on every invocation; the library does not interpret it.
 *
 * Process-wide; not per-handle. Safe to call before any RootHeraldClient
 * exists.
 */
ROOTHERALD_API void RootHerald_SetLogCallback(
    RootHeraldLogCallback callback,
    void* user_data);

/**
 * Set the maximum log level the library will emit. Defaults to
 * ROOTHERALD_LOG_WARN. Messages with level > max_level are dropped before
 * formatting, so this is the cheap way to gate verbose logging in
 * production while keeping the callback registered.
 */
ROOTHERALD_API void RootHerald_SetLogLevel(RootHeraldLogLevel max_level);

/* ------------------------------------------------------------------ */
/* Utility                                                            */
/* ------------------------------------------------------------------ */

/**
 * Returns a human-readable, English string describing a status code.
 * The pointer is owned by the library and remains valid for the process
 * lifetime. Useful for surfacing failures to logs without a switch
 * statement on every call site.
 */
ROOTHERALD_API const char* RootHerald_ErrorString(RootHeraldStatus status);

/**
 * Returns the ABI version as a static "MAJOR.MINOR" string. The pointer
 * is owned by the library and remains valid for the process lifetime.
 */
ROOTHERALD_API const char* RootHerald_AbiVersionString(void);

/**
 * Returns the library build version (semver) as a static null-terminated
 * string. Same ownership rules as RootHerald_AbiVersionString().
 */
ROOTHERALD_API const char* RootHerald_LibraryVersionString(void);

#ifdef __cplusplus
}
#endif

#endif /* ROOTHERALD_H */
