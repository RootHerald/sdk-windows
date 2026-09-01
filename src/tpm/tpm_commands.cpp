/*
 * Command/response byte layout, big-endian throughout:
 *   command  tag(2) | commandSize(4)  | commandCode(4)  | handles | parameters
 *   response tag(2) | responseSize(4) | responseCode(4) | parameters
 */

#include "tpm_commands.h"

#include <cstring>

#include "win_status.h"

#pragma comment(lib, "tbs.lib")

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

#define TPM2_ST_NO_SESSIONS       0x8001
#define TPM2_ST_SESSIONS          0x8002

#define TPM2_ALG_SHA256           0x000B
#define TPM2_ALG_RSASSA           0x0014
#define TPM2_ALG_NULL             0x0010

#define TPM2_RH_OWNER             0x40000001
#define TPM2_RH_ENDORSEMENT       0x40000009

#define TPM2_RC_SUCCESS           0x00000000

namespace RootHerald {

namespace {

void WriteU16(std::vector<uint8_t>& buf, uint16_t v)
{
    buf.push_back((v >> 8) & 0xFF);
    buf.push_back(v & 0xFF);
}

void WriteU32(std::vector<uint8_t>& buf, uint32_t v)
{
    buf.push_back((v >> 24) & 0xFF);
    buf.push_back((v >> 16) & 0xFF);
    buf.push_back((v >> 8) & 0xFF);
    buf.push_back(v & 0xFF);
}

void WriteBytes(std::vector<uint8_t>& buf, _In_reads_bytes_(len) const uint8_t* data, size_t len)
{
    buf.insert(buf.end(), data, data + len);
}

void WriteTPM2B(std::vector<uint8_t>& buf, _In_reads_bytes_(len) const uint8_t* data, size_t len)
{
    WriteU16(buf, (uint16_t)len);
    if (len > 0) WriteBytes(buf, data, len);
}

/* SendCommand back-patches commandSize from the final buffer length, so
 * callers only ever append parameters. */
void BeginCommand(std::vector<uint8_t>& buf, uint16_t tag, uint32_t commandCode)
{
    WriteU16(buf, tag);
    WriteU32(buf, 0);
    WriteU32(buf, commandCode);
}

uint16_t ReadU16(_In_reads_bytes_(2) const uint8_t* p)
{
    return ((uint16_t)p[0] << 8) | p[1];
}

uint32_t ReadU32(_In_reads_bytes_(4) const uint8_t* p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

/* TPM_RS_PW with an empty password and continueSession set. */
void WritePasswordAuth(std::vector<uint8_t>& buf)
{
    std::vector<uint8_t> auth;
    WriteU32(auth, 0x40000009); // sessionHandle = TPM_RS_PW
    WriteU16(auth, 0);          // nonceCaller
    auth.push_back(0x01);       // sessionAttributes = continueSession
    WriteU16(auth, 0);          // hmac

    WriteU32(buf, (uint32_t)auth.size());
    WriteBytes(buf, auth.data(), auth.size());
}

/* RSA-2048 restricted signing key, RSASSA-SHA256. stClear (bit 2) MUST stay
 * clear: an stClear object cannot be made persistent by TPM2_EvictControl
 * (TPM_RC_ATTRIBUTES), which would break AK persistence for Quote. */
void WriteAkTemplate(std::vector<uint8_t>& buf)
{
    std::vector<uint8_t> pub;

    WriteU16(pub, 0x0001);      // type = TPM_ALG_RSA
    WriteU16(pub, 0x000B);      // nameAlg = SHA256
    uint32_t attrs = (1u << 1)   // fixedTPM
                   | (1u << 4)   // fixedParent
                   | (1u << 5)   // sensitiveDataOrigin
                   | (1u << 6)   // userWithAuth
                   | (1u << 16)  // restricted
                   | (1u << 18); // sign
    WriteU32(pub, attrs);
    WriteU16(pub, 0);           // authPolicy: empty
    WriteU16(pub, 0x0010);      // symmetric = TPM_ALG_NULL
    WriteU16(pub, 0x0014);      // scheme = TPM_ALG_RSASSA
    WriteU16(pub, 0x000B);      //          SHA256
    WriteU16(pub, 2048);        // keyBits
    WriteU32(pub, 0);           // exponent: default
    WriteU16(pub, 256);         // unique: TPM2B_PUBLIC_KEY_RSA
    for (int i = 0; i < 256; i++) pub.push_back(0);

    WriteU16(buf, (uint16_t)pub.size());
    WriteBytes(buf, pub.data(), pub.size());
}

/* RSA-2048 restricted decrypt, AES-128-CFB, standard EK auth policy. */
void WriteEkTemplate(std::vector<uint8_t>& buf)
{
    std::vector<uint8_t> pub;

    WriteU16(pub, 0x0001);      // type = TPM_ALG_RSA
    WriteU16(pub, 0x000B);      // nameAlg = SHA256
    // fixedTPM | fixedParent | sensitiveDataOrigin | adminWithPolicy
    // | restricted | decrypt
    uint32_t attrs = (1 << 1) | (1 << 4) | (1 << 5) | (1 << 7) | (1 << 16) | (1 << 17);
    WriteU32(pub, attrs);

    // authPolicy = TPM2_PolicySecret(TPM_RH_ENDORSEMENT)
    WriteU16(pub, 32);
    static const uint8_t EK_POLICY[] = {
        0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xB3, 0xF8,
        0x1A, 0x90, 0xCC, 0x8D, 0x46, 0xA5, 0xD7, 0x24,
        0xFD, 0x52, 0xD7, 0x6E, 0x06, 0x52, 0x0B, 0x64,
        0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14, 0x69, 0xAA
    };
    WriteBytes(pub, EK_POLICY, 32);

    WriteU16(pub, 0x0006);      // symmetric = AES
    WriteU16(pub, 128);         //             keyBits
    WriteU16(pub, 0x0043);      //             CFB
    WriteU16(pub, 0x0010);      // scheme = TPM_ALG_NULL
    WriteU16(pub, 2048);        // keyBits
    WriteU32(pub, 0);           // exponent: default 65537
    WriteU16(pub, 256);         // unique
    for (int i = 0; i < 256; i++) pub.push_back(0);

    WriteU16(buf, (uint16_t)pub.size());
    WriteBytes(buf, pub.data(), pub.size());
}

} // namespace

HRESULT TpmCommands::Open()
{
    if (_context) return S_OK;

    TBS_CONTEXT_PARAMS2 params = {};
    params.version = TBS_CONTEXT_VERSION_TWO;
    params.includeTpm20 = 1;

    TBS_RESULT result = Tbsi_Context_Create((PCTBS_CONTEXT_PARAMS)&params, _context.Put());
    if (result != TBS_SUCCESS) {
        return HrFromTbs(result);
    }
    return S_OK;
}

void TpmCommands::Close()
{
    _context.Reset();
}

_Use_decl_annotations_
HRESULT TpmCommands::SendCommand(std::vector<uint8_t>* command,
                                 std::vector<uint8_t>* out_response)
{
    out_response->clear();
    if (!_context) return RH_E_NOT_OPEN;

    if (command->size() >= 6) {
        uint32_t size = (uint32_t)command->size();
        (*command)[2] = (size >> 24) & 0xFF;
        (*command)[3] = (size >> 16) & 0xFF;
        (*command)[4] = (size >> 8) & 0xFF;
        (*command)[5] = size & 0xFF;
    }

    std::vector<uint8_t> response(4096);
    UINT32 responseLen = (UINT32)response.size();

    TBS_RESULT result = Tbsip_Submit_Command(
        _context.Get(),
        TBS_COMMAND_LOCALITY_ZERO,
        TBS_COMMAND_PRIORITY_NORMAL,
        command->data(), (UINT32)command->size(),
        response.data(), &responseLen);

    if (result != TBS_SUCCESS) {
        return HrFromTbs(result);
    }

    response.resize(responseLen);
    *out_response = std::move(response);
    return S_OK;
}

_Use_decl_annotations_
HRESULT TpmCommands::PcrRead(uint32_t pcrIndex, std::vector<uint8_t>* out_digest)
{
    out_digest->clear();

    std::vector<uint8_t> cmd;
    BeginCommand(cmd, TPM2_ST_NO_SESSIONS, TPM2_CC_PCR_Read);

    // pcrSelectionIn (TPML_PCR_SELECTION)
    WriteU32(cmd, 1);                   // count
    WriteU16(cmd, TPM2_ALG_SHA256);     // hash
    cmd.push_back(3);                   // sizeofSelect
    uint8_t bitmap[3] = {0, 0, 0};
    if (pcrIndex < 24) bitmap[pcrIndex / 8] = (uint8_t)(1 << (pcrIndex % 8));
    WriteBytes(cmd, bitmap, 3);

    std::vector<uint8_t> resp;
    HRESULT hr = SendCommand(&cmd, &resp);
    if (FAILED(hr)) return hr;
    if (resp.size() < 10) return RH_E_MALFORMED_RESPONSE;

    uint32_t rc = ReadU32(resp.data() + 6);
    if (rc != TPM2_RC_SUCCESS) {
        return HrFromTpmRc(rc);
    }

    size_t offset = 10 + 4; // header + pcrUpdateCounter

    // TPML_PCR_SELECTION
    if (offset + 4 > resp.size()) return RH_E_MALFORMED_RESPONSE;
    uint32_t selectionCount = ReadU32(resp.data() + offset);
    offset += 4;
    for (uint32_t i = 0; i < selectionCount; i++) {
        offset += 2; // hash
        if (offset >= resp.size()) return RH_E_MALFORMED_RESPONSE;
        uint8_t selectSize = resp[offset];
        offset += 1 + selectSize;
    }

    // TPML_DIGEST
    if (offset + 4 > resp.size()) return RH_E_MALFORMED_RESPONSE;
    uint32_t digestCount = ReadU32(resp.data() + offset);
    offset += 4;

    if (digestCount > 0 && offset + 2 <= resp.size()) {
        uint16_t digestSize = ReadU16(resp.data() + offset);
        offset += 2;
        if (offset + digestSize <= resp.size()) {
            out_digest->assign(resp.data() + offset, resp.data() + offset + digestSize);
            return S_OK;
        }
    }

    return RH_E_MALFORMED_RESPONSE;
}

_Use_decl_annotations_
HRESULT TpmCommands::Quote(uint32_t akHandle,
                           const std::vector<uint8_t>& nonce,
                           const std::vector<uint32_t>& pcrIndices,
                           std::vector<uint8_t>* out_quoted,
                           std::vector<uint8_t>* out_signature)
{
    out_quoted->clear();
    out_signature->clear();

    std::vector<uint8_t> cmd;
    BeginCommand(cmd, TPM2_ST_SESSIONS, TPM2_CC_Quote);

    WriteU32(cmd, akHandle);            // signHandle
    WritePasswordAuth(cmd);
    WriteTPM2B(cmd, nonce.data(), nonce.size());  // qualifyingData

    // inScheme (TPMT_SIG_SCHEME)
    WriteU16(cmd, TPM2_ALG_RSASSA);
    WriteU16(cmd, TPM2_ALG_SHA256);

    // PCRselect (TPML_PCR_SELECTION)
    WriteU32(cmd, 1);
    WriteU16(cmd, TPM2_ALG_SHA256);
    cmd.push_back(3);
    uint8_t bitmap[3] = {0, 0, 0};
    for (uint32_t index : pcrIndices) {
        if (index < 24) bitmap[index / 8] |= (uint8_t)(1 << (index % 8));
    }
    WriteBytes(cmd, bitmap, 3);

    std::vector<uint8_t> resp;
    HRESULT hr = SendCommand(&cmd, &resp);
    if (FAILED(hr)) return hr;
    if (resp.size() < 10) return RH_E_MALFORMED_RESPONSE;

    uint32_t rc = ReadU32(resp.data() + 6);
    if (rc != TPM2_RC_SUCCESS) {
        return HrFromTpmRc(rc);
    }

    size_t offset = 10;
    if (offset + 4 > resp.size()) return RH_E_MALFORMED_RESPONSE;
    offset += 4; // parameterSize

    // TPM2B_ATTEST
    if (offset + 2 > resp.size()) return RH_E_MALFORMED_RESPONSE;
    uint16_t attestSize = ReadU16(resp.data() + offset);
    offset += 2;
    if (offset + attestSize > resp.size()) return RH_E_MALFORMED_RESPONSE;
    out_quoted->assign(resp.data() + offset, resp.data() + offset + attestSize);
    offset += attestSize;

    // TPMT_SIGNATURE — the server parses it, so the remainder travels verbatim.
    if (offset < resp.size()) {
        out_signature->assign(resp.data() + offset, resp.data() + resp.size());
    }

    return S_OK;
}

HRESULT TpmCommands::FlushContext(uint32_t handle)
{
    std::vector<uint8_t> cmd;
    BeginCommand(cmd, TPM2_ST_NO_SESSIONS, TPM2_CC_FlushContext);
    WriteU32(cmd, handle);

    std::vector<uint8_t> resp;
    return SendCommand(&cmd, &resp);
}

_Use_decl_annotations_
HRESULT TpmCommands::CreateAndLoadAk(uint32_t parentHandle,
                                     uint32_t* out_handle,
                                     std::vector<uint8_t>* out_publicArea)
{
    *out_handle = 0;
    if (out_publicArea) out_publicArea->clear();

    // TPM2_CreatePrimary under a hierarchy, rather than Create + Load, because
    // parentHandle here is always a hierarchy handle.
    std::vector<uint8_t> cmd;
    BeginCommand(cmd, TPM2_ST_SESSIONS, TPM2_CC_CreatePrimary);

    WriteU32(cmd, parentHandle);
    WritePasswordAuth(cmd);

    // inSensitive: empty
    WriteU16(cmd, 4);
    WriteU16(cmd, 0);
    WriteU16(cmd, 0);

    WriteAkTemplate(cmd);

    WriteU16(cmd, 0);   // outsideInfo: empty
    WriteU32(cmd, 0);   // creationPCR: empty

    std::vector<uint8_t> resp;
    HRESULT hr = SendCommand(&cmd, &resp);
    if (FAILED(hr)) return hr;
    if (resp.size() < 14) return RH_E_MALFORMED_RESPONSE;

    uint32_t rc = ReadU32(resp.data() + 6);
    if (rc != TPM2_RC_SUCCESS) {
        return HrFromTpmRc(rc);
    }

    *out_handle = ReadU32(resp.data() + 10);

    // header(10) + objectHandle(4) + parameterSize(4) + TPM2B_PUBLIC
    if (out_publicArea && resp.size() >= 20) {
        uint32_t paramSize = ReadU32(resp.data() + 14);
        if (paramSize > 0 && 18 + (size_t)paramSize <= resp.size()) {
            uint16_t pubSize = ReadU16(resp.data() + 18);
            if (pubSize > 0 && 20 + pubSize <= resp.size()) {
                out_publicArea->assign(resp.data() + 18, resp.data() + 20 + pubSize);
            }
        }
    }

    return S_OK;
}

_Use_decl_annotations_
HRESULT TpmCommands::CreateEk(uint32_t* out_handle)
{
    *out_handle = 0;

    std::vector<uint8_t> cmd;
    BeginCommand(cmd, TPM2_ST_SESSIONS, TPM2_CC_CreatePrimary);

    WriteU32(cmd, 0x4000000B);  // primaryHandle = TPM_RH_ENDORSEMENT
    WritePasswordAuth(cmd);

    // inSensitive: empty
    WriteU16(cmd, 4);
    WriteU16(cmd, 0);
    WriteU16(cmd, 0);

    WriteEkTemplate(cmd);

    WriteU16(cmd, 0);   // outsideInfo: empty
    WriteU32(cmd, 0);   // creationPCR: empty

    std::vector<uint8_t> resp;
    HRESULT hr = SendCommand(&cmd, &resp);
    if (FAILED(hr)) return hr;
    if (resp.size() < 14) return RH_E_MALFORMED_RESPONSE;

    uint32_t rc = ReadU32(resp.data() + 6);
    if (rc != TPM2_RC_SUCCESS) {
        return HrFromTpmRc(rc);
    }

    *out_handle = ReadU32(resp.data() + 10);
    return S_OK;
}

_Use_decl_annotations_
HRESULT TpmCommands::ActivateCredential(uint32_t akHandle,
                                        uint32_t ekHandle,
                                        const std::vector<uint8_t>& credentialBlob,
                                        const std::vector<uint8_t>& encryptedSecret,
                                        std::vector<uint8_t>* out_secret)
{
    out_secret->clear();
    uint32_t sessionHandle = 0;

    auto run = [&]() -> HRESULT {
        // TPM2_StartAuthSession — a policy session to satisfy EK auth.
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
            startCmd.push_back(0x01);         // sessionType = TPM_SE_POLICY
            WriteU16(startCmd, 0x0010);       // symmetric = TPM_ALG_NULL
            WriteU16(startCmd, 0x000B);       // authHash = SHA-256

            std::vector<uint8_t> startResp;
            HRESULT hr = SendCommand(&startCmd, &startResp);
            if (FAILED(hr)) return hr;
            if (startResp.size() < 14) return RH_E_MALFORMED_RESPONSE;

            uint32_t rc = ReadU32(startResp.data() + 6);
            if (rc != TPM2_RC_SUCCESS) {
                return HrFromTpmRc(rc);
            }

            // TPM_ST_NO_SESSIONS puts the session handle at offset 10;
            // TPM_ST_SESSIONS interposes parameterSize(4), pushing it to 14.
            size_t handleOffset =
                (ReadU16(startResp.data()) == TPM2_ST_SESSIONS) ? 14 : 10;
            if (startResp.size() < handleOffset + 4) return RH_E_MALFORMED_RESPONSE;
            sessionHandle = ReadU32(startResp.data() + handleOffset);
        }

        // TPM2_PolicySecret(TPM_RH_ENDORSEMENT) satisfies the EK policy.
        {
            std::vector<uint8_t> policyCmd;
            BeginCommand(policyCmd, TPM2_ST_SESSIONS, TPM2_CC_PolicySecret);
            WriteU32(policyCmd, 0x4000000B);    // authHandle = TPM_RH_ENDORSEMENT
            WriteU32(policyCmd, sessionHandle); // policySession
            WritePasswordAuth(policyCmd);       // ENDORSEMENT auth, empty password
            WriteU16(policyCmd, 0);             // nonceTPM: empty
            WriteU16(policyCmd, 0);             // cpHashA: empty
            WriteU16(policyCmd, 0);             // policyRef: empty
            WriteU32(policyCmd, 0);             // expiration

            std::vector<uint8_t> policyResp;
            HRESULT hr = SendCommand(&policyCmd, &policyResp);
            if (FAILED(hr)) return hr;
            if (policyResp.size() < 10) {
                return RH_E_MALFORMED_RESPONSE;
            }
            uint32_t rc = ReadU32(policyResp.data() + 6);
            if (rc != TPM2_RC_SUCCESS) {
                return HrFromTpmRc(rc);
            }
        }

        // TPM2_ActivateCredential — password auth for the AK, the policy
        // session for the EK.
        {
            std::vector<uint8_t> authArea;
            WriteU32(authArea, 0x40000009);    // AK: TPM_RS_PW
            WriteU16(authArea, 0);             // nonceCaller
            authArea.push_back(0x01);          // continueSession
            WriteU16(authArea, 0);             // hmac
            WriteU32(authArea, sessionHandle); // EK: policy session
            WriteU16(authArea, 0);             // nonceCaller
            authArea.push_back(0x01);          // continueSession
            WriteU16(authArea, 0);             // hmac

            std::vector<uint8_t> actCmd;
            BeginCommand(actCmd, TPM2_ST_SESSIONS, TPM2_CC_ActivateCredential);
            WriteU32(actCmd, akHandle);        // activateHandle
            WriteU32(actCmd, ekHandle);        // keyHandle
            WriteU32(actCmd, (uint32_t)authArea.size());
            WriteBytes(actCmd, authArea.data(), authArea.size());

            // Both blobs arrive from the server already TPM2B-framed; sending
            // them as-is is what makes the server's MakeCredential output
            // decrypt here. Do not re-wrap.
            WriteBytes(actCmd, credentialBlob.data(), credentialBlob.size());
            WriteBytes(actCmd, encryptedSecret.data(), encryptedSecret.size());

            std::vector<uint8_t> actResp;
            HRESULT hr = SendCommand(&actCmd, &actResp);
            if (FAILED(hr)) return hr;
            if (actResp.size() < 10) return RH_E_MALFORMED_RESPONSE;

            uint32_t rc = ReadU32(actResp.data() + 6);
            if (rc != TPM2_RC_SUCCESS) {
                // TBS surfaces Windows HRESULTs here too; 0x80280400
                // (TPM_E_COMMAND_BLOCKED) means a non-elevated caller.
                return HrFromTpmRc(rc);
            }

            // parameterSize(4) + TPM2B_DIGEST holding the recovered secret.
            if (actResp.size() < 16) return RH_E_MALFORMED_RESPONSE;
            if (ReadU32(actResp.data() + 10) < 2) return RH_E_MALFORMED_RESPONSE;
            uint16_t secretSize = ReadU16(actResp.data() + 14);
            if (16 + secretSize > actResp.size()) return RH_E_MALFORMED_RESPONSE;
            out_secret->assign(actResp.data() + 16, actResp.data() + 16 + secretSize);

            SecureZeroMemory(actResp.data(), actResp.size());
            return S_OK;
        }
    };

    HRESULT hr = run();
    if (sessionHandle) FlushContext(sessionHandle);
    return hr;
}

bool TpmCommands::IsPersistentPresent(uint32_t persistentHandle)
{
    std::vector<uint8_t> cmd;
    BeginCommand(cmd, TPM2_ST_NO_SESSIONS, TPM2_CC_ReadPublic);
    WriteU32(cmd, persistentHandle);

    std::vector<uint8_t> resp;
    HRESULT hr = SendCommand(&cmd, &resp);
    if (FAILED(hr)) {
        return false;
    }
    if (resp.size() < 10) return false;

    // An empty slot answers TPM_RC_HANDLE, which is the answer, not a fault.
    return ReadU32(resp.data() + 6) == TPM2_RC_SUCCESS;
}

HRESULT TpmCommands::EvictControl(uint32_t transientHandle, uint32_t persistentHandle)
{
    if (IsPersistentPresent(persistentHandle)) {
        std::vector<uint8_t> clearCmd;
        BeginCommand(clearCmd, TPM2_ST_SESSIONS, TPM2_CC_EvictControl);
        WriteU32(clearCmd, TPM2_RH_OWNER);
        WriteU32(clearCmd, persistentHandle);  // objectHandle = slot to clear
        WritePasswordAuth(clearCmd);
        WriteU32(clearCmd, persistentHandle);

        std::vector<uint8_t> clearResp;
        HRESULT hr = SendCommand(&clearCmd, &clearResp);
        if (FAILED(hr)) return hr;
        if (clearResp.size() < 10) {
            return RH_E_MALFORMED_RESPONSE;
        }
        uint32_t clearRc = ReadU32(clearResp.data() + 6);
        if (clearRc != TPM2_RC_SUCCESS) {
            return HrFromTpmRc(clearRc);
        }
    }

    std::vector<uint8_t> cmd;
    BeginCommand(cmd, TPM2_ST_SESSIONS, TPM2_CC_EvictControl);
    WriteU32(cmd, TPM2_RH_OWNER);
    WriteU32(cmd, transientHandle);
    WritePasswordAuth(cmd);
    WriteU32(cmd, persistentHandle);

    std::vector<uint8_t> resp;
    HRESULT hr = SendCommand(&cmd, &resp);
    if (FAILED(hr)) return hr;
    if (resp.size() < 10) {
        return RH_E_MALFORMED_RESPONSE;
    }
    uint32_t rc = ReadU32(resp.data() + 6);
    if (rc != TPM2_RC_SUCCESS) {
        return HrFromTpmRc(rc);
    }
    return S_OK;
}

_Use_decl_annotations_
HRESULT TpmCommands::ReadNvData(uint32_t nvIndex, std::vector<uint8_t>* out_data)
{
    out_data->clear();

    // TPM2_NV_ReadPublic first, to discover dataSize.
    // Response: header | TPM2B_NV_PUBLIC | TPM2B_NAME, where TPMS_NV_PUBLIC is
    // nvIndex(4) nameAlg(2) attributes(4) authPolicy(TPM2B) dataSize(2).
    std::vector<uint8_t> cmd;
    BeginCommand(cmd, TPM2_ST_NO_SESSIONS, TPM2_CC_NV_ReadPublic);
    WriteU32(cmd, nvIndex);

    std::vector<uint8_t> resp;
    HRESULT hr = SendCommand(&cmd, &resp);
    if (FAILED(hr)) return hr;
    if (resp.size() < 10) return RH_E_MALFORMED_RESPONSE;

    uint32_t rc = ReadU32(resp.data() + 6);
    if (rc != TPM2_RC_SUCCESS) return HrFromTpmRc(rc); // undefined index is normal

    size_t offset = 10;
    if (offset + 2 > resp.size()) return RH_E_MALFORMED_RESPONSE;
    uint16_t nvPublicSize = ReadU16(resp.data() + offset);
    offset += 2;
    if (offset + nvPublicSize > resp.size()) return RH_E_MALFORMED_RESPONSE;

    size_t inner = offset;
    if (inner + 4 + 2 + 4 + 2 > resp.size()) return RH_E_MALFORMED_RESPONSE;
    inner += 4 + 2 + 4; // nvIndex, nameAlg, attributes
    uint16_t policySize = ReadU16(resp.data() + inner);
    inner += 2;
    if (inner + policySize + 2 > resp.size()) return RH_E_MALFORMED_RESPONSE;
    inner += policySize;
    uint16_t dataSize = ReadU16(resp.data() + inner);
    if (dataSize == 0) return RH_E_MALFORMED_RESPONSE;

    // TPM2_NV_Read, auth = the index itself with an empty password. Chunked at
    // 1024 because an index may exceed TPM_MAX_NV_BUFFER_SIZE in one call (the
    // TPM 2.0 floor is 512; querying TPM_PT_NV_BUFFER_MAX is overkill here).
    const uint16_t CHUNK = 1024;
    uint16_t readOffset = 0;
    out_data->reserve(dataSize);
    while (readOffset < dataSize) {
        uint16_t want = (uint16_t)((dataSize - readOffset) > CHUNK
                                   ? CHUNK
                                   : (dataSize - readOffset));

        std::vector<uint8_t> readCmd;
        BeginCommand(readCmd, TPM2_ST_SESSIONS, TPM2_CC_NV_Read);
        WriteU32(readCmd, nvIndex); // authHandle
        WriteU32(readCmd, nvIndex); // nvIndex
        WritePasswordAuth(readCmd);
        WriteU16(readCmd, want);
        WriteU16(readCmd, readOffset);

        std::vector<uint8_t> readResp;
        hr = SendCommand(&readCmd, &readResp);
        if (FAILED(hr)) {
            out_data->clear();
            return hr;
        }
        if (readResp.size() < 10) {
            out_data->clear();
            return RH_E_MALFORMED_RESPONSE;
        }
        uint32_t readRc = ReadU32(readResp.data() + 6);
        if (readRc != TPM2_RC_SUCCESS) {
            out_data->clear();
            return HrFromTpmRc(readRc);
        }

        // header(10) | parameterSize(4) | TPM2B_MAX_NV_BUFFER | auth area
        size_t bufferOffset = 10 + 4;
        if (bufferOffset + 2 > readResp.size()) {
            out_data->clear();
            return RH_E_MALFORMED_RESPONSE;
        }
        uint16_t got = ReadU16(readResp.data() + bufferOffset);
        bufferOffset += 2;
        if (got == 0 || bufferOffset + got > readResp.size()) {
            out_data->clear();
            return RH_E_MALFORMED_RESPONSE;
        }
        out_data->insert(out_data->end(),
                                readResp.data() + bufferOffset,
                                readResp.data() + bufferOffset + got);
        readOffset = (uint16_t)(readOffset + got);
    }

    return out_data->empty() ? RH_E_MALFORMED_RESPONSE : S_OK;
}

namespace {

/* Byte length of the DER object starting at `offset`, or 0 when the bytes there
 * are not a well-formed SEQUENCE that fits inside `data`. Definite-length only:
 * a certificate is always definite-length DER, so refusing the indefinite form
 * keeps a malformed buffer from being walked as though it were a chain. */
size_t DerObjectSize(const std::vector<uint8_t>& data, size_t offset)
{
    if (offset + 2 > data.size() || data[offset] != 0x30) return 0;

    const uint8_t lengthByte = data[offset + 1];
    if ((lengthByte & 0x80) == 0) {
        const size_t total = 2u + lengthByte;
        return offset + total <= data.size() ? total : 0;
    }

    const size_t lengthBytes = lengthByte & 0x7Fu;
    if (lengthBytes == 0 || lengthBytes > 4) return 0;
    if (offset + 2 + lengthBytes > data.size()) return 0;

    size_t length = 0;
    for (size_t i = 0; i < lengthBytes; ++i) {
        length = (length << 8) | data[offset + 2 + i];
    }

    const size_t total = 2 + lengthBytes + length;
    return offset + total <= data.size() ? total : 0;
}

} // namespace

_Use_decl_annotations_
void TpmCommands::ReadIntelOdcaIntermediates(std::vector<std::vector<uint8_t>>* certificates)
{
    // Intel writes the on-die chain as ONE byte stream and splits it across as
    // many NV indices as it needs, so a certificate straddles the boundary
    // whenever the stream reaches an index's capacity mid-certificate. Reading
    // each index as a certificate yields fragments that parse as nothing, which
    // is why the whole range is concatenated before it is cut.
    //
    // Measured on an Intel Core Ultra 9 185H (Meteor Lake): 0x01C00100 holds
    // 2048 bytes and 0x01C00101 holds 124, carrying three certificates of 806,
    // 677 and 689 bytes. The third begins at 1483 and runs through the 2048-byte
    // index boundary.
    std::vector<uint8_t> stream;
    for (uint32_t i = 0; i < 16; ++i) {
        std::vector<uint8_t> slot;
        if (SUCCEEDED(ReadNvData(0x01C00100u + i, &slot)) && !slot.empty()) {
            stream.insert(stream.end(), slot.begin(), slot.end());
        }
    }
    if (stream.empty()) return;

    // Real chains are 2-3 deep; 8 bounds a pathological NV layout.
    constexpr size_t MAX_CERTIFICATES = 8;
    size_t offset = 0;
    while (offset < stream.size() && certificates->size() < MAX_CERTIFICATES) {
        const size_t size = DerObjectSize(stream, offset);
        // A chain that does not exactly fill its last index is padded, so the
        // first byte that does not open a SEQUENCE ends the chain rather than
        // failing it.
        if (size == 0) break;
        certificates->emplace_back(stream.begin() + offset,
                                   stream.begin() + offset + size);
        offset += size;
    }
}

} // namespace RootHerald
