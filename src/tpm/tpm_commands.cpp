/**
 * Raw TPM 2.0 command implementation via TBS.
 *
 * Marshals TPM2 command structures manually and sends them through
 * Tbsip_Submit_Command. This provides real TPM Quote and PCR Read
 * without any external library dependency.
 *
 * TPM2 command format (big-endian):
 *   tag (2) | commandSize (4) | commandCode (4) | handles... | parameters...
 *
 * TPM2 response format (big-endian):
 *   tag (2) | responseSize (4) | responseCode (4) | parameters...
 */

#include "tpm_commands.h"
#include <cstring>
#include <algorithm>
#include "log.h"

#pragma comment(lib, "tbs.lib")

// TPM2 command codes
#define TPM2_CC_PCR_Read              0x0000017E
#define TPM2_CC_Quote                 0x00000158
#define TPM2_CC_FlushContext          0x00000165
#define TPM2_CC_CreatePrimary         0x00000131
#define TPM2_CC_ActivateCredential    0x00000147
#define TPM2_CC_StartAuthSession      0x00000176
#define TPM2_CC_PolicySecret          0x00000151
#define TPM2_CC_EvictControl          0x00000120
#define TPM2_CC_ReadPublic            0x00000173
#define TPM2_CC_NV_Read               0x0000014E
#define TPM2_CC_NV_ReadPublic         0x00000169

// TPM2 tags
#define TPM2_ST_NO_SESSIONS       0x8001
#define TPM2_ST_SESSIONS          0x8002

// Algorithm IDs
#define TPM2_ALG_SHA256           0x000B
#define TPM2_ALG_RSASSA           0x0014
#define TPM2_ALG_NULL             0x0010

// Hierarchy handles
#define TPM2_RH_OWNER             0x40000001
#define TPM2_RH_ENDORSEMENT       0x40000009

// Response codes
#define TPM2_RC_SUCCESS           0x00000000

namespace RootHerald {

// Big-endian helpers
static void WriteU16(std::vector<uint8_t>& buf, uint16_t v) {
    buf.push_back((v >> 8) & 0xFF);
    buf.push_back(v & 0xFF);
}

static void WriteU32(std::vector<uint8_t>& buf, uint32_t v) {
    buf.push_back((v >> 24) & 0xFF);
    buf.push_back((v >> 16) & 0xFF);
    buf.push_back((v >> 8) & 0xFF);
    buf.push_back(v & 0xFF);
}

static void WriteBytes(std::vector<uint8_t>& buf, const uint8_t* data, size_t len) {
    buf.insert(buf.end(), data, data + len);
}

static void WriteTPM2B(std::vector<uint8_t>& buf, const uint8_t* data, size_t len) {
    WriteU16(buf, (uint16_t)len);
    if (len > 0)
        WriteBytes(buf, data, len);
}

// Begin a TPM command header: tag, a placeholder commandSize, and the command
// code. SendCommand back-patches the size from the final buffer length, so
// callers only append parameters and never touch the size field.
static void BeginCommand(std::vector<uint8_t>& buf, uint16_t tag, uint32_t commandCode) {
    WriteU16(buf, tag);
    WriteU32(buf, 0); // commandSize placeholder
    WriteU32(buf, commandCode);
}

static uint16_t ReadU16(const uint8_t* p) {
    return ((uint16_t)p[0] << 8) | p[1];
}

static uint32_t ReadU32(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

// Password auth session (empty auth)
static void WritePasswordAuth(std::vector<uint8_t>& buf) {
    // Authorization area:
    //   authorizationSize (4)
    //   TPMS_AUTH_COMMAND:
    //     sessionHandle (4) = TPM_RS_PW
    //     nonceCaller (2+0) = empty
    //     sessionAttributes (1) = continueSession
    //     hmac (2+0) = empty
    std::vector<uint8_t> auth;
    WriteU32(auth, 0x40000009); // TPM_RS_PW (password session)
    WriteU16(auth, 0);          // nonceCaller = empty
    auth.push_back(0x01);       // sessionAttributes = continueSession
    WriteU16(auth, 0);          // hmac = empty

    WriteU32(buf, (uint32_t)auth.size());
    WriteBytes(buf, auth.data(), auth.size());
}

TpmCommands::TpmCommands() = default;
TpmCommands::~TpmCommands() { Close(); }

bool TpmCommands::Open()
{
    if (_isOpen) return true;

    TBS_CONTEXT_PARAMS2 params = {};
    params.version = TBS_CONTEXT_VERSION_TWO;
    params.includeTpm20 = 1;

    TBS_RESULT result = Tbsi_Context_Create(
        (PCTBS_CONTEXT_PARAMS)&params, &_hContext);
    if (result != TBS_SUCCESS)
        return false;

    _isOpen = true;
    return true;
}

void TpmCommands::Close()
{
    if (_isOpen && _hContext) {
        Tbsip_Context_Close(_hContext);
        _hContext = 0;
        _isOpen = false;
    }
}

std::vector<uint8_t> TpmCommands::SendCommand(std::vector<uint8_t>& cmd)
{
    if (!_isOpen) return {};

    // Back-patch the commandSize field (bytes 2..5) reserved by BeginCommand.
    if (cmd.size() >= 6) {
        uint32_t size = (uint32_t)cmd.size();
        cmd[2] = (size >> 24) & 0xFF;
        cmd[3] = (size >> 16) & 0xFF;
        cmd[4] = (size >> 8) & 0xFF;
        cmd[5] = size & 0xFF;
    }

    // Allocate response buffer (max 4096 for most commands)
    std::vector<uint8_t> resp(4096);
    UINT32 respLen = (UINT32)resp.size();

    TBS_RESULT result = Tbsip_Submit_Command(
        _hContext,
        TBS_COMMAND_LOCALITY_ZERO,
        TBS_COMMAND_PRIORITY_NORMAL,
        cmd.data(), (UINT32)cmd.size(),
        resp.data(), &respLen);

    if (result != TBS_SUCCESS)
        return {};

    resp.resize(respLen);
    return resp;
}

std::vector<uint8_t> TpmCommands::PcrRead(uint32_t pcrIndex)
{
    // TPM2_PCR_Read command (no sessions)
    std::vector<uint8_t> cmd;
    BeginCommand(cmd, TPM2_ST_NO_SESSIONS, TPM2_CC_PCR_Read);

    // pcrSelectionIn (TPML_PCR_SELECTION)
    WriteU32(cmd, 1);                   // count = 1
    WriteU16(cmd, TPM2_ALG_SHA256);     // hash = SHA-256
    cmd.push_back(3);                   // sizeofSelect = 3 bytes
    uint8_t bitmap[3] = {0, 0, 0};
    if (pcrIndex < 24)
        bitmap[pcrIndex / 8] = (uint8_t)(1 << (pcrIndex % 8));
    WriteBytes(cmd, bitmap, 3);

    auto resp = SendCommand(cmd);
    if (resp.size() < 10) return {};

    uint32_t rc = ReadU32(resp.data() + 6);
    if (rc != TPM2_RC_SUCCESS) return {};

    // Parse response: skip header (10) + pcrUpdateCounter (4) + pcrSelectionOut (variable)
    size_t offset = 10;
    offset += 4; // pcrUpdateCounter

    // TPML_PCR_SELECTION
    if (offset + 4 > resp.size()) return {};
    uint32_t selCount = ReadU32(resp.data() + offset);
    offset += 4;
    for (uint32_t i = 0; i < selCount; i++) {
        offset += 2; // hash
        if (offset >= resp.size()) return {};
        uint8_t selectSize = resp[offset];
        offset += 1 + selectSize;
    }

    // TPML_DIGEST: count (4) + TPM2B_DIGEST entries
    if (offset + 4 > resp.size()) return {};
    uint32_t digestCount = ReadU32(resp.data() + offset);
    offset += 4;

    if (digestCount > 0 && offset + 2 <= resp.size()) {
        uint16_t digestSize = ReadU16(resp.data() + offset);
        offset += 2;
        if (offset + digestSize <= resp.size()) {
            return std::vector<uint8_t>(resp.data() + offset, resp.data() + offset + digestSize);
        }
    }

    return {};
}

bool TpmCommands::Quote(uint32_t akHandle,
                        const std::vector<uint8_t>& nonce,
                        const std::vector<uint32_t>& pcrIndices,
                        std::vector<uint8_t>& outQuoted,
                        std::vector<uint8_t>& outSignature)
{
    // TPM2_Quote command (with sessions for auth)
    std::vector<uint8_t> cmd;
    BeginCommand(cmd, TPM2_ST_SESSIONS, TPM2_CC_Quote);

    // Handle: signHandle = akHandle
    WriteU32(cmd, akHandle);

    // Auth session (password, empty)
    WritePasswordAuth(cmd);

    // qualifyingData (nonce)
    WriteTPM2B(cmd, nonce.data(), nonce.size());

    // inScheme (TPMT_SIG_SCHEME) = RSASSA SHA-256
    WriteU16(cmd, TPM2_ALG_RSASSA);
    WriteU16(cmd, TPM2_ALG_SHA256);

    // PCR selection (TPML_PCR_SELECTION)
    WriteU32(cmd, 1);               // count = 1
    WriteU16(cmd, TPM2_ALG_SHA256); // hash
    cmd.push_back(3);               // sizeofSelect = 3
    uint8_t bitmap[3] = {0, 0, 0};
    for (uint32_t idx : pcrIndices) {
        if (idx < 24)
            bitmap[idx / 8] |= (uint8_t)(1 << (idx % 8));
    }
    WriteBytes(cmd, bitmap, 3);

    auto resp = SendCommand(cmd);
    if (resp.size() < 10) return false;

    uint32_t rc = ReadU32(resp.data() + 6);
    if (rc != TPM2_RC_SUCCESS) return false;

    // Parse response
    // After header (10): parameterSize (4) + quoted (TPM2B_ATTEST) + signature (TPMT_SIGNATURE)
    size_t offset = 10;

    if (offset + 4 > resp.size()) return false;
    uint32_t paramSize = ReadU32(resp.data() + offset);
    offset += 4;

    // TPM2B_ATTEST
    if (offset + 2 > resp.size()) return false;
    uint16_t attestSize = ReadU16(resp.data() + offset);
    offset += 2;
    if (offset + attestSize > resp.size()) return false;
    outQuoted.assign(resp.data() + offset, resp.data() + offset + attestSize);
    offset += attestSize;

    // TPMT_SIGNATURE — copy the rest as the raw signature blob
    // (the server knows how to parse TPMT_SIGNATURE)
    if (offset < resp.size()) {
        outSignature.assign(resp.data() + offset, resp.data() + resp.size());
    }

    return true;
}

void TpmCommands::FlushContext(uint32_t handle)
{
    std::vector<uint8_t> cmd;
    BeginCommand(cmd, TPM2_ST_NO_SESSIONS, TPM2_CC_FlushContext);
    WriteU32(cmd, handle);

    SendCommand(cmd);
}

// Helper: write the AK TPMT_PUBLIC template
// RSA-2048, restricted signing, RSASSA-SHA256, no symmetric
static void WriteAkTemplate(std::vector<uint8_t>& buf)
{
    std::vector<uint8_t> pub;

    // type = TPM_ALG_RSA
    WriteU16(pub, 0x0001);
    // nameAlg = SHA256
    WriteU16(pub, 0x000B);
    // objectAttributes: fixedTPM | fixedParent | sensitiveDataOrigin |
    // userWithAuth | restricted | sign. Note: stClear (bit 2) MUST be clear —
    // an stClear object cannot be made persistent via TPM2_EvictControl
    // (TPM returns TPM_RC_ATTRIBUTES), which breaks AK persistence for Quote.
    uint32_t attrs = (1u << 1)   // fixedTPM
                   | (1u << 4)   // fixedParent
                   | (1u << 5)   // sensitiveDataOrigin
                   | (1u << 6)   // userWithAuth
                   | (1u << 16)  // restricted
                   | (1u << 18); // sign
    WriteU32(pub, attrs);
    // authPolicy: empty
    WriteU16(pub, 0);
    // parameters: TPMS_RSA_PARMS
    //   symmetric: null (signing keys don't use symmetric)
    WriteU16(pub, 0x0010); // TPM_ALG_NULL
    //   scheme: RSASSA-SHA256
    WriteU16(pub, 0x0014); // TPM_ALG_RSASSA
    WriteU16(pub, 0x000B); // SHA256
    //   keyBits: 2048
    WriteU16(pub, 2048);
    //   exponent: 0 (default)
    WriteU32(pub, 0);
    // unique: TPM2B_PUBLIC_KEY_RSA with 256 bytes of zeros
    WriteU16(pub, 256);
    for (int i = 0; i < 256; i++) pub.push_back(0);

    WriteU16(buf, (uint16_t)pub.size());
    WriteBytes(buf, pub.data(), pub.size());
}

uint32_t TpmCommands::CreateAndLoadAk(uint32_t parentHandle, std::vector<uint8_t>* outPublicKey)
{
    // For simplicity, use TPM2_CreatePrimary under the parent hierarchy
    // to create a restricted signing key directly. This avoids the
    // Create + Load two-step and works when parentHandle is a hierarchy.
    //
    // Note: This creates a transient key that must be flushed when done.

    std::vector<uint8_t> cmd;
    BeginCommand(cmd, TPM2_ST_SESSIONS, TPM2_CC_CreatePrimary);

    // primaryHandle = OWNER hierarchy (we create AK as primary for simplicity)
    WriteU32(cmd, 0x40000001); // TPM_RH_OWNER

    WritePasswordAuth(cmd);

    // inSensitive: empty
    WriteU16(cmd, 4);
    WriteU16(cmd, 0);
    WriteU16(cmd, 0);

    // inPublic: AK template
    WriteAkTemplate(cmd);

    // outsideInfo: empty
    WriteU16(cmd, 0);

    // creationPCR: empty
    WriteU32(cmd, 0);

    auto resp = SendCommand(cmd);
    if (resp.size() < 14) return 0;

    uint32_t rc = ReadU32(resp.data() + 6);
    if (rc != TPM2_RC_SUCCESS) return 0;

    uint32_t handle = ReadU32(resp.data() + 10);

    // Extract TPM2B_PUBLIC from response if requested
    // Response: header(10) + handle(4) + parameterSize(4) + TPM2B_PUBLIC + ...
    if (outPublicKey && resp.size() > 18) {
        uint32_t paramSize = ReadU32(resp.data() + 14);
        if (paramSize > 0 && 18 + paramSize <= resp.size()) {
            // TPM2B_PUBLIC starts at offset 18
            uint16_t pubSize = ReadU16(resp.data() + 18);
            if (pubSize > 0 && 20 + pubSize <= resp.size()) {
                // Store the complete TPM2B_PUBLIC (size + content)
                outPublicKey->assign(resp.data() + 18, resp.data() + 20 + pubSize);
            }
        }
    }

    return handle;
}

/// Helper to write the EK template for CreatePrimary
/// RSA-2048, restricted decrypt, AES-128-CFB, with standard EK auth policy
static void WriteEkTemplate(std::vector<uint8_t>& buf)
{
    std::vector<uint8_t> pub;

    // type = TPM_ALG_RSA
    WriteU16(pub, 0x0001);
    // nameAlg = SHA256
    WriteU16(pub, 0x000B);
    // objectAttributes: fixedTPM | fixedParent | sensitiveDataOrigin | adminWithPolicy | restricted | decrypt
    uint32_t attrs = (1 << 1) | (1 << 4) | (1 << 5) | (1 << 7) | (1 << 16) | (1 << 17);
    WriteU32(pub, attrs);
    // authPolicy: TPM2_PolicySecret(TPM_RH_ENDORSEMENT) — standard 32-byte hash
    WriteU16(pub, 32);
    static const uint8_t ekPolicy[] = {
        0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xB3, 0xF8,
        0x1A, 0x90, 0xCC, 0x8D, 0x46, 0xA5, 0xD7, 0x24,
        0xFD, 0x52, 0xD7, 0x6E, 0x06, 0x52, 0x0B, 0x64,
        0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14, 0x69, 0xAA
    };
    WriteBytes(pub, ekPolicy, 32);
    // parameters: TPMS_RSA_PARMS
    // symmetric: AES-128-CFB
    WriteU16(pub, 0x0006); // AES
    WriteU16(pub, 128);    // keyBits
    WriteU16(pub, 0x0043); // CFB
    // scheme: null
    WriteU16(pub, 0x0010);
    // keyBits: 2048
    WriteU16(pub, 2048);
    // exponent: 0 (default 65537)
    WriteU32(pub, 0);
    // unique: 256 bytes of zeros
    WriteU16(pub, 256);
    for (int i = 0; i < 256; i++) pub.push_back(0);

    WriteU16(buf, (uint16_t)pub.size());
    WriteBytes(buf, pub.data(), pub.size());
}

uint32_t TpmCommands::CreateEk()
{
    std::vector<uint8_t> cmd;
    BeginCommand(cmd, TPM2_ST_SESSIONS, TPM2_CC_CreatePrimary);

    // primaryHandle = ENDORSEMENT
    WriteU32(cmd, 0x4000000B); // TPM_RH_ENDORSEMENT

    WritePasswordAuth(cmd);

    // inSensitive: empty
    WriteU16(cmd, 4);
    WriteU16(cmd, 0);
    WriteU16(cmd, 0);

    // inPublic: EK template
    WriteEkTemplate(cmd);

    // outsideInfo: empty
    WriteU16(cmd, 0);
    // creationPCR: empty
    WriteU32(cmd, 0);

    auto resp = SendCommand(cmd);
    if (resp.size() < 14) return 0;

    uint32_t rc = ReadU32(resp.data() + 6);
    if (rc != TPM2_RC_SUCCESS) return 0;

    return ReadU32(resp.data() + 10);
}

std::vector<uint8_t> TpmCommands::ActivateCredential(
    uint32_t akHandle, uint32_t ekHandle,
    const std::vector<uint8_t>& credentialBlob,
    const std::vector<uint8_t>& encryptedSecret)
{
    std::vector<uint8_t> secret;
    uint32_t sessionHandle = 0;

    // Step 1: TPM2_StartAuthSession — a policy session to satisfy EK auth.
    {
        std::vector<uint8_t> startCmd;
        BeginCommand(startCmd, TPM2_ST_NO_SESSIONS, TPM2_CC_StartAuthSession);
        WriteU32(startCmd, 0x40000007);   // tpmKey = TPM_RH_NULL (no salt)
        WriteU32(startCmd, 0x40000007);   // bind   = TPM_RH_NULL

        uint8_t sessionNonce[32];
        for (int i = 0; i < 32; i++) sessionNonce[i] = (uint8_t)(i * 7 + 3);
        WriteU16(startCmd, 32);
        WriteBytes(startCmd, sessionNonce, 32);
        WriteU16(startCmd, 0);            // encryptedSalt: empty
        startCmd.push_back(0x01);         // sessionType: TPM_SE_POLICY
        WriteU16(startCmd, 0x0010);       // symmetric: TPM_ALG_NULL
        WriteU16(startCmd, 0x000B);       // authHash: SHA-256

        auto startResp = SendCommand(startCmd);
        if (startResp.size() < 14) goto Cleanup;
        if (ReadU32(startResp.data() + 6) != TPM2_RC_SUCCESS) goto Cleanup;

        // Tag-aware handle offset. TPM_ST_NO_SESSIONS responses place the
        // session handle at offset 10 (right after rc); TPM_ST_SESSIONS
        // responses interpose a parameterSize(4) field, pushing it to 14.
        size_t handleOffset =
            (ReadU16(startResp.data()) == TPM2_ST_SESSIONS) ? 14 : 10;
        if (startResp.size() < handleOffset + 4) goto Cleanup;
        sessionHandle = ReadU32(startResp.data() + handleOffset);
    }

    // Step 2: TPM2_PolicySecret(TPM_RH_ENDORSEMENT) satisfies the EK policy.
    {
        std::vector<uint8_t> policyCmd;
        BeginCommand(policyCmd, TPM2_ST_SESSIONS, TPM2_CC_PolicySecret);
        WriteU32(policyCmd, 0x4000000B);  // authHandle = TPM_RH_ENDORSEMENT
        WriteU32(policyCmd, sessionHandle); // policySession
        WritePasswordAuth(policyCmd);     // ENDORSEMENT auth (empty password)
        WriteU16(policyCmd, 0);           // nonceTPM: empty
        WriteU16(policyCmd, 0);           // cpHashA: empty
        WriteU16(policyCmd, 0);           // policyRef: empty
        WriteU32(policyCmd, 0);           // expiration: 0

        auto policyResp = SendCommand(policyCmd);
        if (policyResp.size() < 10) {
            RH_LOG_WARN("[PolicySecret] Response too short\n");
            goto Cleanup;
        }
        uint32_t rc = ReadU32(policyResp.data() + 6);
        if (rc != TPM2_RC_SUCCESS) {
            RH_LOG_WARN("[PolicySecret] TPM error: 0x%08X\n", rc);
            goto Cleanup;
        }
    }

    // Step 3: TPM2_ActivateCredential. Two auth sessions: password for the AK,
    // the policy session for the EK.
    {
        std::vector<uint8_t> authArea;
        WriteU32(authArea, 0x40000009);   // AK: TPM_RS_PW
        WriteU16(authArea, 0);            // nonceCaller
        authArea.push_back(0x01);         // continueSession
        WriteU16(authArea, 0);            // hmac
        WriteU32(authArea, sessionHandle); // EK: policy session
        WriteU16(authArea, 0);            // nonceCaller
        authArea.push_back(0x01);         // continueSession
        WriteU16(authArea, 0);            // hmac (empty for policy session)

        std::vector<uint8_t> actCmd;
        BeginCommand(actCmd, TPM2_ST_SESSIONS, TPM2_CC_ActivateCredential);
        WriteU32(actCmd, akHandle);       // activateHandle = AK
        WriteU32(actCmd, ekHandle);       // keyHandle = EK
        WriteU32(actCmd, (uint32_t)authArea.size());
        WriteBytes(actCmd, authArea.data(), authArea.size());

        // credentialBlob and encryptedSecret arrive from the server already in
        // TPM2B form (size prefix + data); send them as-is, do not double-wrap.
        WriteBytes(actCmd, credentialBlob.data(), credentialBlob.size());
        WriteBytes(actCmd, encryptedSecret.data(), encryptedSecret.size());

        auto actResp = SendCommand(actCmd);
        if (actResp.size() < 10) goto Cleanup;

        uint32_t rc = ReadU32(actResp.data() + 6);
        if (rc != TPM2_RC_SUCCESS) {
            // TBS surfaces Windows HRESULTs here; 0x80280400 =
            // TPM_E_COMMAND_BLOCKED means a non-elevated caller hit the TBS
            // user-mode block.
            RH_LOG_WARN("[tbs] ActivateCredential failed: 0x%08X\n", rc);
            goto Cleanup;
        }

        // Response: parameterSize(4) + TPM2B_DIGEST (the recovered secret).
        if (ReadU32(actResp.data() + 10) < 2) goto Cleanup;
        uint16_t secretSize = ReadU16(actResp.data() + 14);
        if (16 + secretSize > actResp.size()) goto Cleanup;
        secret.assign(actResp.data() + 16, actResp.data() + 16 + secretSize);
    }

Cleanup:
    if (sessionHandle) FlushContext(sessionHandle);
    return secret;
}

bool TpmCommands::IsPersistentPresent(uint32_t persistentHandle)
{
    // TPM2_ReadPublic on the persistent handle. If the slot is empty,
    // the TPM returns TPM_RC_HANDLE (or similar) and the response is short.
    std::vector<uint8_t> cmd;
    BeginCommand(cmd, TPM2_ST_NO_SESSIONS, TPM2_CC_ReadPublic);
    WriteU32(cmd, persistentHandle);

    auto resp = SendCommand(cmd);
    if (resp.size() < 10) return false;

    uint32_t rc = ReadU32(resp.data() + 6);
    return rc == TPM2_RC_SUCCESS;
}

bool TpmCommands::EvictControl(uint32_t transientHandle, uint32_t persistentHandle)
{
    // If the persistent slot is already populated, clear it first by
    // calling EvictControl with the persistent handle as objectHandle.
    if (IsPersistentPresent(persistentHandle)) {
        std::vector<uint8_t> clearCmd;
        BeginCommand(clearCmd, TPM2_ST_SESSIONS, TPM2_CC_EvictControl);
        WriteU32(clearCmd, TPM2_RH_OWNER);     // auth = TPM_RH_OWNER
        WriteU32(clearCmd, persistentHandle);  // objectHandle = slot to clear
        WritePasswordAuth(clearCmd);
        WriteU32(clearCmd, persistentHandle);  // persistentHandle parameter

        auto clearResp = SendCommand(clearCmd);
        if (clearResp.size() < 10) {
            RH_LOG_WARN("[EvictControl] Clear: response too short\n");
            return false;
        }
        uint32_t rc0 = ReadU32(clearResp.data() + 6);
        if (rc0 != TPM2_RC_SUCCESS) {
            RH_LOG_WARN("[EvictControl] Clear failed: 0x%08X\n", rc0);
            return false;
        }
    }

    // Evict transient -> persistent
    std::vector<uint8_t> cmd;
    BeginCommand(cmd, TPM2_ST_SESSIONS, TPM2_CC_EvictControl);
    WriteU32(cmd, TPM2_RH_OWNER);      // auth = TPM_RH_OWNER
    WriteU32(cmd, transientHandle);    // objectHandle = transient being evicted
    WritePasswordAuth(cmd);
    WriteU32(cmd, persistentHandle);   // persistentHandle parameter

    auto resp = SendCommand(cmd);
    if (resp.size() < 10) {
        RH_LOG_WARN("[EvictControl] Response too short\n");
        return false;
    }
    uint32_t rc = ReadU32(resp.data() + 6);
    if (rc != TPM2_RC_SUCCESS) {
        RH_LOG_WARN("[EvictControl] TPM error: 0x%08X\n", rc);
        return false;
    }
    return true;
}

bool TpmCommands::ReadNvCertificate(uint32_t nvIndex, std::vector<uint8_t>& outCert)
{
    outCert.clear();

    // Step 1: TPM2_NV_ReadPublic to discover the data size.
    // Layout (no sessions):
    //   tag | size | cc=NV_ReadPublic | nvIndex
    // Response: header | TPM2B_NV_PUBLIC | TPM2B_NAME
    //   TPM2B_NV_PUBLIC: size(2) + TPMS_NV_PUBLIC { nvIndex(4), nameAlg(2),
    //     attributes(4), authPolicy(TPM2B), dataSize(2) }
    {
        std::vector<uint8_t> cmd;
        BeginCommand(cmd, TPM2_ST_NO_SESSIONS, TPM2_CC_NV_ReadPublic);
        WriteU32(cmd, nvIndex);

        auto resp = SendCommand(cmd);
        if (resp.size() < 10) return false;

        uint32_t rc = ReadU32(resp.data() + 6);
        if (rc != TPM2_RC_SUCCESS) {
            // TPM_RC_HANDLE etc. — index undefined; silent failure.
            return false;
        }

        // Parse TPM2B_NV_PUBLIC.
        size_t offset = 10;
        if (offset + 2 > resp.size()) return false;
        uint16_t nvPubSize = ReadU16(resp.data() + offset);
        offset += 2;
        if (offset + nvPubSize > resp.size()) return false;

        // TPMS_NV_PUBLIC: nvIndex(4) + nameAlg(2) + attributes(4)
        //               + authPolicy(TPM2B) + dataSize(2)
        size_t inner = offset;
        if (inner + 4 + 2 + 4 + 2 > resp.size()) return false;
        inner += 4; // nvIndex
        inner += 2; // nameAlg
        inner += 4; // attributes
        uint16_t policySize = ReadU16(resp.data() + inner);
        inner += 2;
        if (inner + policySize + 2 > resp.size()) return false;
        inner += policySize;
        uint16_t dataSize = ReadU16(resp.data() + inner);

        if (dataSize == 0) return false;

        // Step 2: TPM2_NV_Read (auth = nvIndex itself, password auth, empty).
        // Layout:
        //   tag=ST_SESSIONS | size | cc=NV_Read
        //   authHandle = nvIndex
        //   nvIndex    = nvIndex
        //   authArea (password)
        //   size (UINT16) | offset (UINT16)
        //
        // Some NV indices may exceed TPM_MAX_NV_BUFFER_SIZE per call; loop
        // in chunks of 1024 bytes (TPM minimum is 512; 1024 is broadly safe
        // — TPM2_GetCapability TPM_PT_NV_BUFFER_MAX would be more precise
        // but is overkill for cert-sized reads).
        const uint16_t kChunk = 1024;
        uint16_t readOffset = 0;
        outCert.reserve(dataSize);
        while (readOffset < dataSize) {
            uint16_t want = (uint16_t)((dataSize - readOffset) > kChunk
                                       ? kChunk
                                       : (dataSize - readOffset));

            std::vector<uint8_t> rcmd;
            BeginCommand(rcmd, TPM2_ST_SESSIONS, TPM2_CC_NV_Read);
            WriteU32(rcmd, nvIndex); // authHandle
            WriteU32(rcmd, nvIndex); // nvIndex
            WritePasswordAuth(rcmd);
            WriteU16(rcmd, want);
            WriteU16(rcmd, readOffset);

            auto rresp = SendCommand(rcmd);
            if (rresp.size() < 10) {
                outCert.clear();
                return false;
            }
            uint32_t rrc = ReadU32(rresp.data() + 6);
            if (rrc != TPM2_RC_SUCCESS) {
                outCert.clear();
                return false;
            }

            // Response: header(10) | parameterSize(4) | TPM2B_MAX_NV_BUFFER (size+data) | auth area
            size_t roff = 10 + 4;
            if (roff + 2 > rresp.size()) {
                outCert.clear();
                return false;
            }
            uint16_t got = ReadU16(rresp.data() + roff);
            roff += 2;
            if (got == 0 || roff + got > rresp.size()) {
                outCert.clear();
                return false;
            }
            outCert.insert(outCert.end(),
                           rresp.data() + roff,
                           rresp.data() + roff + got);
            readOffset = (uint16_t)(readOffset + got);
        }

        return !outCert.empty();
    }
}

void TpmCommands::ReadIntelOdcaIntermediates(std::vector<std::vector<uint8_t>>& outCerts)
{
    // Intel PTT (11th-gen+) caches its on-die ICA chain in the platform
    // manufacturer reserved NV range. The RSA chain is 0x01C00100..0x01C001FF
    // — in practice 1-3 intermediates are present. Bound the iteration at
    // 16 handles to stay well clear of pathological cases.
    for (uint32_t i = 0; i < 16; ++i) {
        std::vector<uint8_t> cert;
        if (ReadNvCertificate(0x01C00100u + i, cert) && !cert.empty()) {
            outCerts.push_back(std::move(cert));
        }
    }
}

} // namespace RootHerald
