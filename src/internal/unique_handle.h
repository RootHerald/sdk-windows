/*
 * Move-only ownership for the Win32 / NCrypt / TBS / CryptoAPI handles this
 * library acquires, so no success path has to remember a close call.
 *
 * Deliberately hand-rolled rather than taken from WIL: RootHerald.lib is a
 * static archive third parties link, and WIL ships "live at head" with no
 * versioned stability contract.
 */

#pragma once

#include <windows.h>
#include <ncrypt.h>
#include <tbs.h>
#include <wincrypt.h>
#include <winhttp.h>

namespace RootHerald {

template <typename Traits>
class UniqueHandle {
public:
    using ValueType = typename Traits::ValueType;

    UniqueHandle() = default;
    explicit UniqueHandle(ValueType value) : _value(value) {}
    ~UniqueHandle() { Reset(); }

    UniqueHandle(const UniqueHandle&) = delete;
    UniqueHandle& operator=(const UniqueHandle&) = delete;

    UniqueHandle(UniqueHandle&& other) noexcept : _value(other.Release()) {}
    UniqueHandle& operator=(UniqueHandle&& other) noexcept
    {
        if (this != &other) Reset(other.Release());
        return *this;
    }

    ValueType Get() const { return _value; }
    explicit operator bool() const { return _value != Traits::Invalid(); }

    /* Address for an out-parameter API. Releases any handle already held. */
    _Ret_notnull_ ValueType* Put()
    {
        Reset();
        return &_value;
    }

    ValueType Release()
    {
        ValueType previous = _value;
        _value = Traits::Invalid();
        return previous;
    }

    void Reset(ValueType value = Traits::Invalid())
    {
        if (_value != Traits::Invalid()) Traits::Close(_value);
        _value = value;
    }

private:
    ValueType _value = Traits::Invalid();
};

struct NcryptProviderTraits {
    using ValueType = NCRYPT_PROV_HANDLE;
    static ValueType Invalid() { return 0; }
    static void Close(ValueType h) { NCryptFreeObject(h); }
};

struct NcryptKeyTraits {
    using ValueType = NCRYPT_KEY_HANDLE;
    static ValueType Invalid() { return 0; }
    static void Close(ValueType h) { NCryptFreeObject(h); }
};

struct TbsContextTraits {
    using ValueType = TBS_HCONTEXT;
    static ValueType Invalid() { return 0; }
    static void Close(ValueType h) { Tbsip_Context_Close(h); }
};

struct KernelHandleTraits {
    using ValueType = HANDLE;
    static ValueType Invalid() { return nullptr; }
    static void Close(ValueType h) { CloseHandle(h); }
};

struct RegKeyTraits {
    using ValueType = HKEY;
    static ValueType Invalid() { return nullptr; }
    static void Close(ValueType h) { RegCloseKey(h); }
};

struct InternetTraits {
    using ValueType = HINTERNET;
    static ValueType Invalid() { return nullptr; }
    static void Close(ValueType h) { WinHttpCloseHandle(h); }
};

struct BcryptAlgTraits {
    using ValueType = BCRYPT_ALG_HANDLE;
    static ValueType Invalid() { return nullptr; }
    static void Close(ValueType h) { BCryptCloseAlgorithmProvider(h, 0); }
};

struct BcryptHashTraits {
    using ValueType = BCRYPT_HASH_HANDLE;
    static ValueType Invalid() { return nullptr; }
    static void Close(ValueType h) { BCryptDestroyHash(h); }
};

struct CertContextTraits {
    using ValueType = PCCERT_CONTEXT;
    static ValueType Invalid() { return nullptr; }
    static void Close(ValueType h) { CertFreeCertificateContext(h); }
};

struct CryptProvTraits {
    using ValueType = HCRYPTPROV;
    static ValueType Invalid() { return 0; }
    static void Close(ValueType h) { CryptReleaseContext(h, 0); }
};

struct CryptHashTraits {
    using ValueType = HCRYPTHASH;
    static ValueType Invalid() { return 0; }
    static void Close(ValueType h) { CryptDestroyHash(h); }
};

using UniqueNcryptProvider = UniqueHandle<NcryptProviderTraits>;
using UniqueNcryptKey      = UniqueHandle<NcryptKeyTraits>;
using UniqueTbsContext     = UniqueHandle<TbsContextTraits>;
using UniqueKernelHandle   = UniqueHandle<KernelHandleTraits>;
using UniqueRegKey         = UniqueHandle<RegKeyTraits>;
using UniqueInternet       = UniqueHandle<InternetTraits>;
using UniqueBcryptAlg      = UniqueHandle<BcryptAlgTraits>;
using UniqueBcryptHash     = UniqueHandle<BcryptHashTraits>;
using UniqueCertContext    = UniqueHandle<CertContextTraits>;
using UniqueCryptProv      = UniqueHandle<CryptProvTraits>;
using UniqueCryptHash      = UniqueHandle<CryptHashTraits>;

} // namespace RootHerald
