#include "amd_aia_fetch.h"

#include <windows.h>
#include <bcrypt.h>
#include <intsafe.h>
#include <sal.h>

#include <cstring>
#include <string>

#include "http_winhttp.h"
#include "log.h"
#include "unique_handle.h"

#pragma comment(lib, "bcrypt.lib")

namespace RootHerald {

namespace {

/* BCRYPT_RSAKEY_BLOB: Magic, BitLength, cbPublicExp, cbModulus, cbPrime1,
 * cbPrime2 (all ULONG), then PublicExponent[cbPublicExp], Modulus[cbModulus].
 * The cb* names mirror the Win32 field names deliberately. */
constexpr uint32_t BCRYPT_RSA_PUBLIC_MAGIC = 0x31415352u; // 'RSA1'
constexpr uint32_t MAX_MODULUS_BYTES = 1024;

uint32_t ReadU32Le(_In_reads_bytes_(4) const uint8_t* p)
{
    return  (uint32_t)p[0]
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

_Success_(return)
bool Sha256(_In_reads_bytes_(len) const uint8_t* data, size_t len, _Out_writes_bytes_all_(32) uint8_t* out)
{
    UniqueBcryptAlg algorithm;
    if (BCryptOpenAlgorithmProvider(algorithm.Put(), BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0)
        return false;

    UniqueBcryptHash hash;
    if (BCryptCreateHash(algorithm.Get(), hash.Put(), nullptr, 0, nullptr, 0, 0) != 0)
        return false;

    if (BCryptHashData(hash.Get(), (PUCHAR)data, (ULONG)len, 0) != 0) return false;
    return BCryptFinishHash(hash.Get(), out, 32, 0) == 0;
}

std::string HexLower(_In_reads_bytes_(len) const uint8_t* data, size_t len)
{
    static const char HEX[] = "0123456789abcdef";
    std::string s;
    s.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        s += HEX[data[i] >> 4];
        s += HEX[data[i] & 0x0F];
    }
    return s;
}

} // namespace

std::vector<uint8_t> ExtractRsaModulusFromEkPub(const std::vector<uint8_t>& ekPubBlob)
{
    // A larger blob with trailing data is tolerated.
    if (ekPubBlob.size() < 24) return {};

    uint32_t magic       = ReadU32Le(ekPubBlob.data() + 0);
    uint32_t cbPublicExp = ReadU32Le(ekPubBlob.data() + 8);
    uint32_t cbModulus   = ReadU32Le(ekPubBlob.data() + 12);

    if (magic != BCRYPT_RSA_PUBLIC_MAGIC) return {};
    if (cbModulus == 0 || cbModulus > MAX_MODULUS_BYTES) return {};

    // Both lengths come straight off the wire, so the offsets are computed
    // with checked arithmetic rather than trusted to wrap benignly.
    size_t modulusOffset = 0;
    size_t modulusEnd = 0;
    if (FAILED(SizeTAdd(24, cbPublicExp, &modulusOffset))) return {};
    if (FAILED(SizeTAdd(modulusOffset, cbModulus, &modulusEnd))) return {};
    if (modulusEnd > ekPubBlob.size()) return {};

    return std::vector<uint8_t>(
        ekPubBlob.data() + modulusOffset,
        ekPubBlob.data() + modulusEnd);
}

std::vector<uint8_t> FetchAmdAiaEkCert(const std::vector<uint8_t>& ekPubModulus)
{
    if (ekPubModulus.empty()) return {};

    uint8_t digest[32] = {};
    if (!Sha256(ekPubModulus.data(), ekPubModulus.size(), digest)) {
        RH_LOG_WARN("[amd-aia] SHA-256 of modulus failed\n");
        return {};
    }

    std::string url = "https://ftpm.amd.com/pki/aia/" + HexLower(digest, sizeof(digest));

    RH_LOG_WARN("[amd-aia] GET %s\n", url.c_str());
    HttpResponse response = HttpGet(url);
    if (response.statusCode != 200) {
        RH_LOG_WARN("[amd-aia] HTTP %d (body=%zu bytes)\n",
                    response.statusCode, response.body.size());
        return {};
    }

    return std::vector<uint8_t>(response.body.begin(), response.body.end());
}

} // namespace RootHerald
