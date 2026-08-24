/*
 * Root Herald — public C ABI for the embeddable native SDK.
 *
 * C99, no C++ constructs, so this is consumable from C, C++, Rust, Go, Zig,
 * Swift, and P/Invoke without a shim. Identical byte-for-byte in sdk-windows,
 * sdk-linux and sdk-macos; CI fails on drift. Version history is in CHANGELOG.md.
 *
 * The client holds no Root Herald key and opens no socket to Root Herald. It does
 * local TPM/enclave work and emits opaque JSON the embedder's backend relays,
 * authenticated with the backend's rh_sk_ secret. A verdict is only a security
 * control when enforced server-side, so it never travels through the client.
 * The single exception to "no network" is a best-effort fetch to TPM-vendor PKI
 * during enrollment (AMD's AIA endpoint) to complete an EK certificate chain.
 *
 * Ownership: every RootHeraldClient* pairs with RootHeraldClient_Destroy. Result
 * structs are caller-allocated. The blob-emitting calls return a newly-allocated
 * NUL-terminated char* the CALLER owns and frees with RootHeraldClient_FreeEvidence.
 *
 * Thread-safety: a client may be used from any thread but not concurrently.
 * Serialize calls behind a mutex to share one.
 */

#ifndef ROOTHERALD_H
#define ROOTHERALD_H

#include <stdint.h>
#include <stddef.h>

#define ROOTHERALD_ABI_VERSION_MAJOR 4
#define ROOTHERALD_ABI_VERSION_MINOR 0

/* Static archive: no import/export decoration. Retained as a no-op so older
 * translation units referencing it still compile. */
#define ROOTHERALD_API

/*
 * SAL annotations document each pointer's direction and nullability and are
 * checked by MSVC /analyze. They compile to nothing, and the shim keeps
 * non-MSVC consumers building.
 */
#if defined(_MSC_VER) && defined(__has_include)
#  if __has_include(<sal.h>)
#    include <sal.h>
#    define ROOTHERALD_HAS_SAL 1
#  endif
#endif
#ifndef ROOTHERALD_HAS_SAL
#  define _In_
#  define _In_z_
#  define _In_opt_
#  define _Out_
#  define _Outptr_result_z_
#  define _Ret_maybenull_
#  define _Success_(expr)
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct RootHeraldClient RootHeraldClient;

typedef enum {
    ROOTHERALD_OK = 0,
    ROOTHERALD_ERR_INVALID_ARG = 1,
    ROOTHERALD_ERR_TPM_UNAVAILABLE = 2,
    ROOTHERALD_ERR_NETWORK = 3,
    ROOTHERALD_ERR_SERVER = 4,
    ROOTHERALD_ERR_QUOTA_EXCEEDED = 5,
    ROOTHERALD_ERR_NOT_ENROLLED = 6,
    /* Enrollment needs an elevated process and this one is not. The SDK never
     * elevates on your behalf: run EnrollBegin/EnrollComplete in an elevated
     * resident worker and retry. Windows-only. */
    ROOTHERALD_ERR_ELEVATION_REQUIRED = 7,
    ROOTHERALD_ERR_INTERNAL = 99
} RootHeraldStatus;

typedef struct {
    int  is_enrolled;
    int  has_tpm;
    char device_id[129];
    char platform_name[16];       /* "windows" | "linux" | "macos" */
} RootHeraldDeviceInfo;

typedef struct {
    int  has_tpm;                 /* 1 = TPM 2.0 / Secure Enclave reachable */
    int  is_enrolled;             /* 1 = an attestation key exists locally */
    int  ek_cert_present;         /* 1 = vendor EK certificate found */
    int  secure_boot;             /* 1 on, 0 off, -1 undetermined */
    int  oem_keyed;               /* 1 known-OEM PK, 0 custom/unknown, -1 undetermined */
    char oem_name[64];            /* "" when unknown */
    int  boot_log_measurements;   /* measured-boot entries; -1 unavailable */
    int  boot_log_revoked;        /* dbx-revoked entries; -1 unavailable */
    char device_id[129];          /* deterministic local id, "" if underivable */
    char detail_json[2048];       /* machine-readable detail snapshot */
} RootHeraldPosture;

/* ------------------------------------------------------------------ */
/* Lifecycle                                                          */
/* ------------------------------------------------------------------ */

_Ret_maybenull_
ROOTHERALD_API RootHeraldClient* RootHeraldClient_Create(void);

/* Safe to call with NULL. */
ROOTHERALD_API void RootHeraldClient_Destroy(_In_opt_ RootHeraldClient* client);

/* Logical application id (e.g. "launcher") surfaced in audit logs and
 * per-application policy. */
_Success_(return == ROOTHERALD_OK)
ROOTHERALD_API RootHeraldStatus RootHeraldClient_SetApplicationId(
    _In_ RootHeraldClient* client,
    _In_z_ const char* app_id);

/* ------------------------------------------------------------------ */
/* Enrollment — keyless, backend-relayed, two legs                     */
/* ------------------------------------------------------------------ */
/*
 * A one-time bootstrap of the device attestation key. It is irreducibly two
 * server round-trips with a TPM operation between them: Root Herald seals a
 * secret to the endorsement key that only this TPM can recover.
 *
 *   1. EnrollBegin  -> emits the POST /api/v1/devices/enroll body.
 *      Backend relays it; Root Herald returns {deviceId, credentialBlob,
 *      encryptedSecret}.
 *   2. EnrollComplete(challenge) -> runs TPM2_ActivateCredential over it and
 *      emits the POST /api/v1/devices/activate body.
 *
 * Neither call opens a socket or consults a key.
 *
 * ELEVATION: on Windows both legs require an elevated process, and the SAME
 * process must remain resident across the relayed round-trip — the transient
 * EK+AK context ActivateCredential needs is established in EnrollBegin and
 * cannot be rebuilt from the persisted handle. Unprivileged callers get
 * ROOTHERALD_ERR_ELEVATION_REQUIRED.
 */

/* out_request_json: caller owns; free with RootHeraldClient_FreeEvidence.
 * NULL on error. */
_Success_(return == ROOTHERALD_OK)
ROOTHERALD_API RootHeraldStatus RootHeraldClient_EnrollBegin(
    _In_ RootHeraldClient* client,
    _Outptr_result_z_ char** out_request_json);

/* challenge_json: the verbatim /enroll response the backend relayed back.
 * out_activation_json: caller owns; free with RootHeraldClient_FreeEvidence.
 * Returns ROOTHERALD_ERR_NOT_ENROLLED if no in-flight EnrollBegin state exists. */
_Success_(return == ROOTHERALD_OK)
ROOTHERALD_API RootHeraldStatus RootHeraldClient_EnrollComplete(
    _In_ RootHeraldClient* client,
    _In_z_ const char* challenge_json,
    _Outptr_result_z_ char** out_activation_json);

/* ------------------------------------------------------------------ */
/* Local state — never touches the network                             */
/* ------------------------------------------------------------------ */

_Success_(return == ROOTHERALD_OK)
ROOTHERALD_API RootHeraldStatus RootHeraldClient_GetDeviceInfo(
    _In_ RootHeraldClient* client,
    _Out_ RootHeraldDeviceInfo* out_result);

/*
 * Device-readiness snapshot: everything the device can know about itself with
 * no server round-trip. The free pre-flight check before spending a billable
 * attestation.
 *
 * These are READINESS SIGNALS, not a verdict. The verdict is server-side
 * (tenant policy plus trust-anchor chain validation) and is unknowable locally.
 * Never render them as "you will pass".
 *
 * Tri-state ints use -1 for undetermined; counts use -1 for unavailable.
 */
_Success_(return == ROOTHERALD_OK)
ROOTHERALD_API RootHeraldStatus RootHeraldClient_CollectPosture(
    _In_ RootHeraldClient* client,
    _Out_ RootHeraldPosture* out_result);

/* ------------------------------------------------------------------ */
/* Per-attestation evidence collection — keyless                       */
/* ------------------------------------------------------------------ */
/*
 * This is a CLIENT library: it collects evidence, never verifies it, and never
 * holds a secret. The rh_sk_ key and the verification step live in the
 * customer's BACKEND:
 *
 *   1. (here)             collect the evidence blob — no key, no verdict.
 *   2. (customer backend) relay it server->server with rh_sk_ to
 *                         POST /api/v1/attestations/verify.
 *   3. (Root Herald)      appraise and return a verdict the backend ENFORCES.
 *
 * Never compile an rh_sk_ secret into this library — putting it on the device
 * defeats the model. Use a server SDK (@rootherald/node, sdk-go, sdk-dotnet,
 * sdk-java, sdk-php, sdk-ruby) for step 2.
 *
 * Step-up re-attestation (RFC 9470) is this call again with a fresh nonce.
 */

/* nonce_b64: the backend's challenge nonce from POST /api/v1/attestations/challenge.
 * The quote is taken OVER it, so freshness is bound inside the signature.
 * out_evidence_json: exactly the object /attestations/verify expects in its
 * `evidence` field. Caller owns; free with RootHeraldClient_FreeEvidence. */
_Success_(return == ROOTHERALD_OK)
ROOTHERALD_API RootHeraldStatus RootHeraldClient_CollectEvidence(
    _In_z_ const char* nonce_b64,
    _Outptr_result_z_ char** out_evidence_json);

/* Frees any buffer returned by EnrollBegin, EnrollComplete or CollectEvidence.
 * Safe to call with NULL. */
ROOTHERALD_API void RootHeraldClient_FreeEvidence(_In_opt_ char* evidence_json);

/* ------------------------------------------------------------------ */
/* Diagnostics                                                         */
/* ------------------------------------------------------------------ */

typedef enum {
    ROOTHERALD_LOG_ERROR = 0,
    ROOTHERALD_LOG_WARN  = 1,
    ROOTHERALD_LOG_INFO  = 2,
    ROOTHERALD_LOG_DEBUG = 3,
    ROOTHERALD_LOG_TRACE = 4
} RootHeraldLogLevel;

typedef void (*RootHeraldLogCallback)(
    RootHeraldLogLevel level,
    const char* message,
    void* user_data);

/* Pass NULL to disable. The callback may be invoked from any thread. */
ROOTHERALD_API void RootHerald_SetLogCallback(
    _In_opt_ RootHeraldLogCallback callback,
    _In_opt_ void* user_data);

ROOTHERALD_API void RootHerald_SetLogLevel(RootHeraldLogLevel max_level);

/* Static, human-readable strings. Never NULL; do not free. */
ROOTHERALD_API const char* RootHerald_ErrorString(RootHeraldStatus status);
ROOTHERALD_API const char* RootHerald_AbiVersionString(void);
ROOTHERALD_API const char* RootHerald_LibraryVersionString(void);

#ifdef __cplusplus
}
#endif

#endif /* ROOTHERALD_H */
