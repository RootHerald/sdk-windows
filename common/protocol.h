/*
 * Root Herald — wire contract shared by the native SDKs.
 *
 * Documents the JSON the client emits and consumes. The C-API surface itself is
 * in rootherald.h. Identical byte-for-byte across all SDK repos; CI fails on drift.
 *
 * This header declares nothing. Platform-internal types live in each repo's
 * src/client/client_internal.h; the public entry points live in rootherald.h.
 * It is installed because the wire contract is what an integrator or auditor
 * needs to read alongside them.
 *
 * READ THIS FIRST: there is ONE set of endpoints and THREE ceremonies behind
 * them. Through ABI 4.0 this file documented only the TPM ceremony, which meant
 * an integrator writing a cross-platform relay against it got macOS wrong — the
 * fields it looked for do not exist there. The envelope is common; the objects
 * inside it are per-platform, and the server discriminates on `platform`.
 */

#ifndef ROOTHERALD_PROTOCOL_H
#define ROOTHERALD_PROTOCOL_H

/* ====================================================================
 * THE ENVELOPE — common to every platform
 * ==================================================================== */
/*
 * Three endpoints. The CLIENT never calls them; it emits bodies the embedder's
 * BACKEND relays, authenticated with the backend's rh_sk_ secret.
 *
 *   POST /api/v1/attest/enroll        leg 1 of enrollment
 *   POST /api/v1/attest/activate      leg 2 of enrollment
 *   POST /api/v1/attest/verify   every attestation thereafter
 *
 * `platform` on the enroll body is the discriminator. It is recorded on the
 * device row, and ACTIVATION decides which proof to demand from the RECORDED
 * platform rather than from the request — so a caller cannot downgrade a TPM
 * device onto a weaker ceremony by reshaping its own JSON.
 *
 * The nonce for /attestations/verify comes from
 * POST /api/v1/attest/challenge, which is device-agnostic: it takes a
 * tenant and returns a fresh single-use nonce. It does not need to know which
 * device will answer.
 */

/* ====================================================================
 * VARIANT A — TPM 2.0        platform: "windows" | "linux"
 * ==================================================================== */
/*
 * Two legs are irreducible here because the server's challenge is a FUNCTION of
 * what leg 1 emits: it seals a secret to this EK, bound to this AK's Name.
 *
 * POST /devices/enroll
 * {
 *   "ekPublicKey":  "<base64>",          platform-native EK public blob
 *   "akPublicArea": "<base64>",          TPM2B_PUBLIC of the AK, length-prefixed
 *   "platform":     "windows" | "linux",
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
 * POST /devices/activate
 * { "deviceId", "decryptedSecret", "akPublicKey"? }  -> 200
 *
 * Returning the decrypted secret proves two things at once: only the TPM holding
 * the private EK could recover it, and MakeCredential bound it to the AK's Name,
 * so that AK lives in the SAME silicon as the EK. Without the second property a
 * real EK certificate could be paired with a software AK.
 *
 * evidence for /attestations/verify:
 * {
 *   "deviceId":  "...",
 *   "pcrValues": { "sha256": { "0": "<hex>", ... } },
 *   "quote":     { "quoted": "<base64 TPMS_ATTEST>",
 *                  "signature": "<base64 TPMT_SIGNATURE>",
 *                  "nonce": "<base64>" },
 *   "eventLog":  "<base64 TCG log>",     OMITTED when the device has none
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
 *
 * A missing eventLog is NOT an error. Most VMs and every software TPM have no
 * TCG log; the field is omitted, secureBootChain is null, and the appraisal
 * proceeds with fewer claims rather than failing.
 */

/* ====================================================================
 * VARIANT B — Apple Secure Enclave      platform: "macos"
 * ==================================================================== */
/*
 * MakeCredential cannot be reused here and the reason is not incidental: it
 * OAEP-encrypts a seed to the endorsement key, which is inherently RSA, and a
 * Secure Enclave key is P-256 and cannot decrypt at all. The analogue proves
 * residency by SIGNING instead — the server issues a nonce in the clear and the
 * device returns an ECDSA-P256-SHA256 signature over it. Publishing the nonce is
 * safe because the secret under test is the signing key, not the nonce.
 *
 * POST /devices/enroll
 * {
 *   "ekPublicKey":  "<base64>",   the enclave key, X9.63 uncompressed (65 bytes)
 *   "akPublicArea": "<base64>",   THE SAME KEY — there is no separate EK to bind
 *   "platform":     "macos"
 * }
 * -> 201 { "deviceId", "challengeNonce" }
 *
 * No ekCertPem and no ekCertificateChain: macOS has no EK certificate at all,
 * and a placeholder would only invite the server to classify on a fiction.
 *
 * POST /devices/activate
 * { "deviceId", "signature" }  -> 200
 *   DER (SecKeyCreateSignature's default) or IEEE-P1363; both are accepted
 *   because the encoding is a property of the client's crypto library rather
 *   than of the security claim.
 *
 * evidence for /attestations/verify:
 * {
 *   "keyAttestation": { "signedNonce": "<base64>", "publicKey": "<base64>" },
 *   "deviceId": "..."
 * }
 *
 * WHAT THIS PROVES. Possession of a key that cannot leave the enclave — enough
 * to defeat session export, cookie theft and credential replay, because the
 * attacker cannot move the key. It does NOT prove the key is in hardware: this
 * ceremony cannot distinguish a Secure Enclave key from a software P-256 key,
 * so the server classes these devices AppleSecureEnclaveUnattested, which is
 * deliberately not real hardware and does not satisfy `real-device`.
 */

/* ====================================================================
 * VARIANT C — Apple App Attest          platform: "ios"
 * ==================================================================== */
/*
 * Documented here because the SERVER accepts it and a cross-platform relay has
 * to handle it. NOT implemented by the SDKs that ship this header — iOS is a
 * separate Swift package.
 *
 * App Attest is SELF-ENROLLING: the attestation object carries Apple's signed
 * certificate chain, the attested public key and the challenge binding all in
 * one blob, so everything the two-leg ceremony exists to establish is already
 * inside it. There is no /devices/enroll or /devices/activate leg.
 *
 * evidence for /attestations/verify:
 * {
 *   "iosAttestation": { "attestationObject": "<base64 CBOR>", "keyId": "<base64>" }
 * }
 *
 * Sent WITHOUT a deviceId. The device identity is derived from the attested key
 * itself — keyId is SHA-256 of the attested public key, which the server
 * verifies rather than trusts. App Attest evidence accompanied by a deviceId or
 * a quote is treated as AMBIGUOUS and falls through to the fail-closed TPM path
 * rather than silently skipping the enroll gate.
 */

#endif /* ROOTHERALD_PROTOCOL_H */
