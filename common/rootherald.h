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
 *
 * DIAGNOSTICS. This library emits no log messages. Everything it can tell you
 * about a failure is the RootHeraldStatus it returns, and every code below names
 * a distinct thing for the caller to DO — that is the test a code has to pass to
 * exist. Log the code in your own logging stack, where it belongs; the per-code
 * cause-and-remedy reference lives at rootherald.io/developers/sdks/status-codes.
 */

#ifndef ROOTHERALD_H
#define ROOTHERALD_H

#include <stdint.h>
#include <stddef.h>

#define ROOTHERALD_ABI_VERSION_MAJOR 5
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

/*
 * Every code names a different next action. Codes 3, 4 and 5 were retired in
 * 5.0 and are deliberately NOT reused: 3 and 5 described a network client that
 * 3.0 deleted, and 4 reported local TPM failures as "the server returned an
 * error". A consumer compiled against an older header must fail to build, not
 * silently re-map onto a new meaning.
 */
typedef enum {
    ROOTHERALD_OK = 0,

    /* Caller bug — the arguments are wrong. Fix the call; retrying is pointless. */
    ROOTHERALD_ERR_INVALID_ARG = 1,

    /* No TPM 2.0 / Secure Enclave reachable at all. A hardware ceiling: gate the
     * feature off for this device rather than retrying. */
    ROOTHERALD_ERR_TPM_UNAVAILABLE = 2,

    /* No attestation key is enrolled on this device (or, for EnrollComplete, no
     * in-flight EnrollBegin state exists in this process). Run enrollment. */
    ROOTHERALD_ERR_NOT_ENROLLED = 6,

    /* Enrollment needs an elevated process and this one is not. The SDK never
     * elevates on your behalf: run EnrollBegin/EnrollComplete in an elevated
     * resident worker and retry. Windows-only. */
    ROOTHERALD_ERR_ELEVATION_REQUIRED = 7,

    /* A TPM is present but its endorsement key could not be read. Distinct from
     * TPM_UNAVAILABLE because it is usually fixable: a missing resource manager
     * (tpm2-abrmd), a permissions problem on /dev/tpmrm0, or a driver fault.
     * Worth surfacing to the operator rather than degrading silently. */
    ROOTHERALD_ERR_EK_READ_FAILED = 8,

    /* Creating, loading, reading or persisting the attestation key failed. The
     * device's TPM state is the problem, not the caller's arguments — retry
     * enrollment. */
    ROOTHERALD_ERR_AK_FAILED = 9,

    /* The enrollment challenge could not be consumed: TPM2_ActivateCredential
     * failed, or the enclave could not sign it. The challenge is SINGLE-USE and
     * is now burned — restart from EnrollBegin. Never retry EnrollComplete with
     * the same challenge. */
    ROOTHERALD_ERR_ACTIVATION_FAILED = 10,

    /* Reading PCRs or producing the quote failed on an enrolled device. This is
     * an attestation-time fault, not an enrollment one: retry the attestation.
     * Do NOT re-enroll — the key is fine. */
    ROOTHERALD_ERR_QUOTE_FAILED = 11,

    /* macOS/iOS only. The host executable is not signed with a provisioning
     * profile granting data-protection keychain access, so the Secure Enclave is
     * unreachable from this binary (OSStatus -34018). A build/signing
     * misconfiguration in the EMBEDDING app — add the entitlement and re-sign.
     * Not a device fault and not retriable. */
    ROOTHERALD_ERR_ENTITLEMENT_MISSING = 12,

    /* Nothing above fits. Genuinely unexpected — report it. */
    ROOTHERALD_ERR_INTERNAL = 99
} RootHeraldStatus;

/*
 * Device-readiness snapshot: everything the device can know about itself with
 * no server round-trip, and the free pre-flight check before spending a billable
 * attestation.
 *
 * These are READINESS SIGNALS, not a verdict. The verdict is server-side (tenant
 * policy plus trust-anchor chain validation) and is unknowable locally. Never
 * render them as "you will pass".
 *
 * Tri-state ints use -1 for undetermined; counts use -1 for unavailable. -1 is
 * distinct from 0 everywhere in this struct: 0 means "we looked and it is off /
 * there are none", -1 means "we could not tell". Reporting 0 for something never
 * examined would claim knowledge the device does not have.
 */
typedef struct {
    int  has_tpm;                 /* 1 = TPM 2.0 / Secure Enclave reachable */
    int  is_enrolled;             /* 1 = an attestation key exists locally */
    int  ek_cert_present;         /* 1 = vendor EK certificate found */
    int  secure_boot;             /* 1 on, 0 off, -1 undetermined */
    int  oem_keyed;               /* 1 known-OEM PK, 0 custom/unknown, -1 undetermined */
    char oem_name[64];            /* "" when unknown */
    int  boot_log_measurements;   /* measured-boot entries; -1 unavailable */
    /* Measured entries whose digest appears in the platform's dbx revocation
     * list. NOT COMPUTED by any platform today, so it always reports -1.
     * Deriving it means cross-referencing each parsed entry against the dbx
     * hash set, which no analyser does yet — the dbx list's SIZE is known, but
     * that is a property of the firmware, not a finding about this device, and
     * reporting it here would show a revocation count on every healthy machine.
     * The field stays because consumers already render it and degrade correctly
     * on -1; it will report a real number when the cross-reference is built. */
    int  boot_log_revoked;
    char device_id[129];          /* deterministic local id, "" if underivable */
    char platform_name[16];       /* "windows" | "linux" | "macos" */
    char detail_json[2048];       /* machine-readable detail snapshot */
} RootHeraldPosture;

/* ------------------------------------------------------------------ */
/* Lifecycle                                                          */
/* ------------------------------------------------------------------ */

_Ret_maybenull_
ROOTHERALD_API RootHeraldClient* RootHeraldClient_Create(void);

/* Safe to call with NULL. */
ROOTHERALD_API void RootHeraldClient_Destroy(_In_opt_ RootHeraldClient* client);

/* ------------------------------------------------------------------ */
/* Enrollment — keyless, backend-relayed, two legs                     */
/* ------------------------------------------------------------------ */
/*
 * A one-time bootstrap of the device attestation key. It is irreducibly two
 * server round-trips with a TPM operation between them, because the server's
 * challenge is a FUNCTION of what the first leg emits: Root Herald seals a
 * secret to the endorsement key that only this TPM can recover, bound to the
 * attestation key this device just minted.
 *
 *   1. EnrollBegin  -> reads the EK, mints an AK, emits the
 *      POST /api/v1/attest/enroll body. Backend relays it; Root Herald returns
 *      {deviceId, credentialBlob, encryptedSecret}.
 *   2. EnrollComplete(challenge) -> runs TPM2_ActivateCredential over it,
 *      PERSISTS the AK, and emits the POST /api/v1/attest/activate body.
 *
 * Neither call opens a socket or consults a key.
 *
 * ELEVATION: on Windows both legs require an elevated process, and the SAME
 * process must remain resident across the relayed round-trip — the transient
 * EK+AK context ActivateCredential needs cannot be rebuilt from the persisted
 * handle. Unprivileged callers get ROOTHERALD_ERR_ELEVATION_REQUIRED.
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

/*
 * One call answers everything the device knows about itself locally. Through 4.0
 * this was split across GetDeviceInfo and CollectPosture; the former performed a
 * strict subset of the latter's work and returned a strict subset of its fields,
 * so 5.0 merged them and moved platform_name onto RootHeraldPosture.
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
 *                         POST /api/v1/attest/verify.
 *   3. (Root Herald)      appraise and return a verdict the backend ENFORCES.
 *
 * Never compile an rh_sk_ secret into this library — putting it on the device
 * defeats the model. Use a server SDK (@rootherald/node, sdk-go, sdk-dotnet,
 * sdk-java, sdk-php, sdk-ruby) for step 2.
 *
 * Step-up re-attestation (RFC 9470) is this call again with a fresh nonce.
 *
 * A device with no TCG event log still succeeds here. The eventLog field is
 * simply omitted and secureBootChain is null; the server appraises with fewer
 * claims. Most VMs and every software TPM are in that position, so treating a
 * missing log as a failure would refuse attestation to a large part of the fleet.
 * Whether a log was found is reported by CollectPosture.boot_log_measurements.
 */

/* nonce_b64: the backend's challenge nonce from POST /api/v1/attest/challenge.
 * The quote is taken OVER it, so freshness is bound inside the signature.
 * out_evidence_json: exactly the object /attestations/verify expects in its
 * `evidence` field. Caller owns; free with RootHeraldClient_FreeEvidence.
 *
 * Handle-less by design: no key is consulted and no network call is made, so
 * there is nothing for a client object to carry. */
_Success_(return == ROOTHERALD_OK)
ROOTHERALD_API RootHeraldStatus RootHeraldClient_CollectEvidence(
    _In_z_ const char* nonce_b64,
    _Outptr_result_z_ char** out_evidence_json);

/* Frees any buffer returned by EnrollBegin, EnrollComplete or CollectEvidence.
 * Safe to call with NULL. */
ROOTHERALD_API void RootHeraldClient_FreeEvidence(_In_opt_ char* evidence_json);

/* ------------------------------------------------------------------ */
/* Versions                                                            */
/* ------------------------------------------------------------------ */

/* Static, human-readable strings. Never NULL; do not free.
 *
 * ErrorString is a convenience for a printf during integration and for a CI
 * harness's failure output — it is NOT the documentation. Branch on the
 * RootHeraldStatus value; the per-code reference is on the developer portal. */
ROOTHERALD_API const char* RootHerald_ErrorString(RootHeraldStatus status);
ROOTHERALD_API const char* RootHerald_AbiVersionString(void);
ROOTHERALD_API const char* RootHerald_LibraryVersionString(void);

#ifdef __cplusplus
}
#endif

#endif /* ROOTHERALD_H */
