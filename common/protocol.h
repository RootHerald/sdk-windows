/*
 * Root Herald — wire contract shared by the Windows, Linux and macOS SDKs.
 *
 * Documents the JSON the client emits and consumes. The C-API surface itself is
 * in rootherald.h. Identical byte-for-byte across all three SDK repos; CI fails
 * on drift.
 *
 * This header declares nothing. Platform-internal types live in each repo's
 * src/client/client_internal.h; the public entry points live in rootherald.h.
 * It is installed because the wire contract is what an integrator or auditor
 * needs to read alongside them.
 */

#ifndef ROOTHERALD_PROTOCOL_H
#define ROOTHERALD_PROTOCOL_H

/*
 * POST /api/v1/devices/enroll   (relayed by the customer backend)
 * {
 *   "ekPublicKey":  "<base64>",          platform-native EK public blob
 *   "akPublicArea": "<base64>",          TPM2B_PUBLIC of the AK, length-prefixed
 *   "platform":     "windows" | "linux" | "macos",
 *   "ekCertPem":    "<PEM>",             optional; firmware TPMs may have no NV cert
 *   "ekCertificateChain": ["<PEM>", ...] optional intermediates recovered locally
 * }
 * -> 201 { "deviceId", "credentialBlob", "encryptedSecret" }
 *    credentialBlob and encryptedSecret are TPM2_MakeCredential outputs, already
 *    TPM2B-framed: feed them straight into TPM2_ActivateCredential, do not re-wrap.
 *
 * ekCertificateChain sources are TPM NV (Intel PTT On-Die CA at 0x01C00100..0x01C0010F)
 * and platform vendor-intermediate stores. Entries are deduplicated by SHA-256 of
 * DER and capped at 8. Order is not significant and the source is not labeled; the
 * server treats every entry uniformly and still requires the chain to terminate at
 * a seeded vendor root.
 *
 * POST /api/v1/devices/activate
 * { "deviceId", "decryptedSecret" }  -> 200
 *
 * POST /api/v1/attestations/verify   (customer BACKEND only, rh_sk_ auth)
 * The keyless client emits the `evidence` object; the backend relays it. The
 * client never posts this itself and holds no key.
 * evidence: {
 *   "deviceId":  "...",
 *   "pcrValues": { "sha256": { "0": "<hex>", ... } },
 *   "quote":     { "quoted": "<base64 TPMS_ATTEST>",
 *                  "signature": "<base64 TPMT_SIGNATURE>",
 *                  "nonce": "<base64>" },
 *   "eventLog":  "<base64 TCG log>",
 *   "secureBootChain": { ... } | null,
 *   "ekCertPem": "<PEM>",                optional
 *   "ekCertificateChain": ["<PEM>", ...] optional
 * }
 *
 * The server verifies `signature` against the AK public area bound at enrollment,
 * verifies `quoted.extraData` equals the challenge nonce, and verifies
 * `quoted.pcrDigest` against the supplied PCR values. `pcrValues` is not itself
 * signed — only the quote's digest over it is — so trusting it without the quote
 * lets an attacker on the device choose arbitrary PCRs. `secureBootChain` is
 * client-computed and advisory: the server re-derives boot posture from the
 * quote-bound event log and never gates on that object.
 */

#endif /* ROOTHERALD_PROTOCOL_H */
