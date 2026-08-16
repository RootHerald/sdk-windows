/**
 *  Root Herald Client SDK - Wire Protocol Definitions
 *
 * Shared structures for communication between the client SDK
 * and the  Root Herald attestation platform.
 *
 * NOTE (planned migration): These C structs are usable from Windows (C++),
 * Linux (C), and macOS (Obj-C) but cannot be shared with Android (Kotlin)
 * or iOS (Swift) without manual translation. Before mobile client work
 * begins, this file is to be replaced with a `.proto` source of truth that
 * `protoc` codegens for C++/C#/Kotlin/Swift/Obj-C from a single definition.
 * See research deliverable on client/server release decoupling for context.
 */

#ifndef ROOTHERALD_PROTOCOL_H
#define ROOTHERALD_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>

/*
 * Linkage (Wave 6 — static library): the embeddable Root Herald library is
 * static-linked into the customer / tray binary. No DLL export/import
 * decoration is needed. ROOTHERALD_API is retained as a no-op for
 * source-level backwards compatibility.
 */
#define ROOTHERALD_API

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Wire format notes
 * -----------------
 * The on-the-wire JSON contracts are defined here for reference; the
 * structs below describe only the C-API surface (SDK input/output), not
 * the request/response bodies themselves.
 *
 * POST /api/v1/devices/enroll  (client -> server)
 *   {
 *     "ekCertPem":    "...PEM..."        // optional; omitted on firmware TPMs
 *                                        // (e.g. Intel PTT) with no NV cert.
 *                                        // Windows clients also try AMD AIA
 *                                        // (https://ftpm.amd.com/pki/aia/<hash>)
 *                                        // before giving up on this field.
 *     "ekCertificateChain": ["...PEM..."] // ADDED 2026-05; optional. List of
 *                                        // intermediate CA certificates the
 *                                        // client recovered from one or more
 *                                        // local sources. Sources include:
 *                                        //   - TPM NV (Intel PTT ODCA chain at
 *                                        //     NV indices 0x01C00100..0x01C0010F)
 *                                        //   - Windows registry-cached vendor
 *                                        //     intermediates (HKLM\...\TPM\WMI\
 *                                        //     Endorsement\IntermediateCACertStore;
 *                                        //     Infineon / STMicro / Nuvoton / AMD
 *                                        //     fTPM, etc.)
 *                                        //   - Future: Linux/macOS equivalents.
 *                                        // Entries are deduplicated by client
 *                                        // (SHA-256 of DER) and capped at 8.
 *                                        // The server MUST treat all entries
 *                                        // uniformly — order is not significant
 *                                        // and the source is not labeled.
 *                                        // Server SHOULD prefer these over a
 *                                        // built-in ICA trust list and SHOULD
 *                                        // avoid AIA-fetching intermediates if
 *                                        // a valid chain can be built from this
 *                                        // array alone.
 *     "ekPublicKey":  "<base64>",        // platform-native EK pub blob
 *                                        // (Windows: NCrypt PCP_EKPUB).
 *     "akPublicArea": "<base64>",        // TPM2B_PUBLIC of the AK
 *                                        // (length-prefixed TPMT_PUBLIC).
 *                                        // CHANGED 2026-05: was an NCrypt RSA
 *                                        // public blob; now matches what the
 *                                        // TPM emits from TPM2_CreatePrimary
 *                                        // so the server can hash it into the
 *                                        // AK Name used by MakeCredential.
 *     "platform":     "windows" | "linux" | "macos"
 *   }
 *   -> 201 { "deviceId", "credentialBlob", "encryptedSecret" }
 *      201 are the TPM2_MakeCredential outputs (already TPM2B-framed);
 *      the client feeds them straight into TPM2_ActivateCredential.
 *   -> 409 { "deviceId" } when already enrolled.
 *
 * POST /api/v1/devices/activate
 *   { "deviceId", "decryptedSecret" }
 *   -> 200 on success.
 *
 * POST /api/v1/attestations/verify   (customer BACKEND -> server, rh_sk_ auth)
 *   The keyless client (RootHeraldClient_CollectEvidence) emits the `evidence`
 *   object below and hands it to the embedder; the customer's BACKEND relays it
 *   here. The client never POSTs this itself and holds no key. (ABI 3.0 removed
 *   the old client-side Passport `POST /api/v1/attest` direct path.)
 *   evidence:
 *   {
 *     "deviceId":   "..." (the enrolled device; EK-derived when not overridden),
 *     "pcrValues":  { "sha256": { "0": "<hex>", ... } },
 *     "quote": {
 *       "quoted":    "<base64 TPMS_ATTEST>",
 *       "signature": "<base64 TPMT_SIGNATURE>",
 *       "nonce":     "<base64>"           // == the backend's challenge nonce.
 *     },
 *     "eventLog":        "<base64 TCG log>",
 *     "secureBootChain": { ... } | null,
 *     "ekCertPem":           "...PEM..." (optional),
 *     "ekCertificateChain":  ["...PEM..."] (optional)
 *   }
 *   The server MUST verify `signature` against the AK pub stored at
 *   enrollment, MUST verify `quoted.extraData == nonce`, and MUST verify
 *   that `quoted.pcrDigest` equals SHA-256 of the concatenated PCR values
 *   in `pcrValues.sha256`. Trusting `pcrValues` without `quote` allows an
 *   attacker on the device to inject arbitrary PCR values.
 */

/* Legacy SDK result codes. Distinct from the public Wave-2 ABI in
 * rootherald.h (RootHeraldStatus / RH_PROTO_OK there). Prefix kept as
 * RH_PROTO_ to avoid the collision while we still ship both interfaces. */
typedef enum {
    RH_PROTO_OK = 0,
    RH_PROTO_ERR_NO_TPM = 1,
    RH_PROTO_ERR_ENROLLMENT_FAILED = 2,
    RH_PROTO_ERR_ATTESTATION_FAILED = 3,
    RH_PROTO_ERR_NETWORK = 4,
    RH_PROTO_ERR_INTERNAL = 5,
    RH_PROTO_ERR_NOT_ENROLLED = 6,
    RH_PROTO_ERR_INVALID_PARAM = 7,
    RH_PROTO_ERR_ALREADY_ENROLLED = 8, /* RootHeraldEnroll called with force_reenroll=0 on a TPM that already has a persistent AK at 0x81010001. Pass force_reenroll=1 to overwrite. */
    RH_PROTO_ERR_ELEVATION_REQUIRED = 9 /* Cold enrollment needs an elevated process (raw-TBS AK create + TPM2_ActivateCredential) but the caller is unprivileged. The SDK does NOT elevate; run the keyless EnrollBegin/EnrollComplete in an elevated resident worker (the single elevation spans both). */
} RootHeraldResult;

/* Enrollment output */
typedef struct {
    char device_id[64];
    char credential_blob[4096];
    char encrypted_secret[4096];
} RootHeraldEnrollmentInfo;

/* Attestation output */
typedef struct {
    char session_id[64];
    char status[32];           /* "verified", "failed", "expired" */
    char authorization_code[128];
    char redirect_uri[2048];
    char failure_reason[512];
} RootHeraldAttestationInfo;

/* Device status */
typedef struct {
    int is_enrolled;
    char device_id[64];
    char platform[16];         /* "windows", "linux", "macos" */
    int has_tpm;
} RootHeraldDeviceStatus;

/*
 * DEPRECATED / INTERNAL legacy surface. The global functions below are the
 * pre-handle SDK surface. New integrations use the handle-based, KEYLESS
 * RootHeraldClient_* API in <rootherald.h> (EnrollBegin / EnrollComplete /
 * CollectEvidence / CollectPosture / GetDeviceInfo).
 *
 * These globals are retained for: (a) the Linux/macOS legacy driver
 * implementation (rootherald_linux.c / rootherald_macos.m still define
 * RootHeraldEnroll / RootHeraldAttest / RootHeraldGetStatus, used by the
 * non-CI native_host samples), and (b) Windows-internal keyless helpers the
 * facade builds on (RootHeraldGetStatus, RootHeraldSetDeviceId). They are NOT
 * the public surface and gain no new capabilities.
 *
 * ABI 3.0 (Windows) removed the network-bearing direct-POST globals
 * RootHeraldEnroll / RootHeraldAttest, the one-shot link-token global
 * RootHeraldSetLinkToken, and the elevated-enroll worker
 * RootHeraldRunElevatedEstablishKey from the Windows build — the Windows SDK
 * opens no socket to RootHerald and enrollment is the keyless EnrollBegin /
 * EnrollComplete handshake. (The Enroll/Attest *declarations* remain here only
 * because the Linux/macOS legacy drivers still implement them.)
 */

/**
 * Enroll this device with the  Root Herald platform.
 * Initiates the EK validation and credential activation flow.
 *
 * `force_reenroll`: if 0 (default), enrollment is short-circuited with
 * RH_PROTO_ERR_ALREADY_ENROLLED when the TPM already has a persistent AK
 * at the  Root Herald slot (0x81010001). If non-zero, any existing AK is
 * evicted and replaced.
 *
 * BREAKING (pre-1.0): added the `force_reenroll` parameter. Callers built
 * against an earlier SDK must be rebuilt against this header.
 */
ROOTHERALD_API RootHeraldResult RootHeraldEnroll(
    const char* server_url,
    int force_reenroll,
    RootHeraldEnrollmentInfo* out_info
);

/**
 * Perform attestation for a given session.
 * Collects a TPM Quote (or Secure Enclave signature) and submits it.
 */
ROOTHERALD_API RootHeraldResult RootHeraldAttest(
    const char* server_url,
    const char* session_id,
    const char* nonce_b64,
    size_t nonce_len,
    RootHeraldAttestationInfo* out_info
);

/**
 * Set an optional device ID override to bind into collected evidence (the
 * keyless CollectEvidence path reads it; empty -> deviceId is derived from the
 * EK). Windows-internal host hook; no network.
 */
ROOTHERALD_API void RootHeraldSetDeviceId(const char* device_id);

/**
 * Get current device enrollment and TPM status.
 */
ROOTHERALD_API RootHeraldResult RootHeraldGetStatus(
    RootHeraldDeviceStatus* out_status
);

#ifdef __cplusplus
}
#endif

#endif /* ROOTHERALD_PROTOCOL_H */
