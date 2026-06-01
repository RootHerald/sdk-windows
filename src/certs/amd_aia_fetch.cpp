/**
 * AMD fTPM EK certificate fetch — implementation.
 *
 * Hashes the EK RSA modulus with SHA-256 (via BCrypt), hex-encodes the
 * digest lowercase, and HTTP-GETs https://ftpm.amd.com/pki/aia/<hex>.
 */

#include "amd_aia_fetch.h"
#include "http_winhttp.h"
#include "log.h"

#include <windows.h>
#include <bcrypt.h>

#include <cstdio>
#include <cstring>
#include <string>

#pragma comment(lib, "bcrypt.lib")

namespace RootHerald {

namespace {

// BCRYPT_RSAKEY_BLOB layout (see ncrypt.h / bcrypt.h):
//   ULONG Magic;        // 'RSA1' = 0x31415352 for public
//   ULONG BitLength;
//   ULONG cbPublicExp;
//   ULONG cbModulus;
//   ULONG cbPrime1;     // zero for public blobs
//   ULONG cbPrime2;     // zero for public blobs
// Followed by: PublicExponent[cbPublicExp], Modulus[cbModulus].
constexpr uint32_t kBcryptRsaPublicMagic = 0x31415352u; // 'RSA1'

uint32_t ReadU32Le(const uint8_t* p)
{
    return  (uint32_t)p[0]
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

bool Sha256(const uint8_t* data, size_t len, uint8_t out[32])
{
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    NTSTATUS s = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (s != 0) return false;

    BCRYPT_HASH_HANDLE hHash = nullptr;
    s = BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0);
    if (s != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    bool ok = true;
    if (BCryptHashData(hHash, (PUCHAR)data, (ULONG)len, 0) != 0) ok = false;
    if (ok && BCryptFinishHash(hHash, out, 32, 0) != 0) ok = false;

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

std::string HexLower(const uint8_t* data, size_t len)
{
    static const char hex[] = "0123456789abcdef";
    std::string s;
    s.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        s += hex[data[i] >> 4];
        s += hex[data[i] & 0x0F];
    }
    return s;
}

} // namespace

std::vector<uint8_t> ExtractRsaModulusFromEkPub(const std::vector<uint8_t>& ekPubBlob)
{
    // The NCrypt PCP_EKPUB property returns a BCRYPT_RSAKEY_BLOB. Validate
    // and slice out the modulus. We tolerate larger blobs (trailing data).
    if (ekPubBlob.size() < 24) return {};
    uint32_t magic       = ReadU32Le(ekPubBlob.data() + 0);
    /* uint32_t bitLength */
    uint32_t cbPublicExp = ReadU32Le(ekPubBlob.data() + 8);
    uint32_t cbModulus   = ReadU32Le(ekPubBlob.data() + 12);

    if (magic != kBcryptRsaPublicMagic) return {};
    if (cbModulus == 0 || cbModulus > 1024) return {};

    size_t modOffset = 24 + cbPublicExp;
    if (modOffset + cbModulus > ekPubBlob.size()) return {};

    return std::vector<uint8_t>(
        ekPubBlob.data() + modOffset,
        ekPubBlob.data() + modOffset + cbModulus);
}

std::vector<uint8_t> FetchAmdAiaEkCert(const std::vector<uint8_t>& ekPubModulus)
{
    if (ekPubModulus.empty()) return {};

    uint8_t digest[32] = {};
    if (!Sha256(ekPubModulus.data(), ekPubModulus.size(), digest)) {
        RH_LOG_WARN("[amd-aia] SHA-256 of modulus failed\n");
        return {};
    }

    std::string hex = HexLower(digest, sizeof(digest));
    std::string url = "https://ftpm.amd.com/pki/aia/" + hex;

    RH_LOG_WARN("[amd-aia] GET %s\n", url.c_str());
    HttpResponse resp = HttpGet(url);
    if (resp.statusCode != 200) {
        RH_LOG_WARN("[amd-aia] HTTP %d (body=%zu bytes)\n",
                resp.statusCode, resp.body.size());
        return {};
    }

    return std::vector<uint8_t>(resp.body.begin(), resp.body.end());
}

} // namespace RootHerald
