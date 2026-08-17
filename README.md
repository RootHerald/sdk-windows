# sdk-windows

The Root Herald native SDK for windows. Ships as a **static archive plus headers**:
you link it into your own binary, and your own code-signing certificate covers
the result.

This repo is public so a security reviewer can read the code that runs on their
users' machines. It contains only the shipped path — the implementation, the C
ABI headers it exposes, and the native messaging host. Developer diagnostics
live in the private `RootHerald/sdk-native-tools`.

## Why one repo per OS

The three platform implementations share a C ABI and nothing else: no shared
source at all. Windows is C++ over NCrypt/TBS, Linux is C over tpm2-tss, macOS
is Objective-C over the Secure Enclave. Keeping them together meant a Linux
reviewer had to read roughly 9,800 lines to reach the ~2,900 that run on their
machine. Split, that reviewer reads only what ships to them.

The cost is that `common/rootherald.h` and `common/protocol.h` are vendored
into all three repos. That duplication is intentional — the contract belongs
beside the implementation it describes — and `.github/workflows/abi-drift.yml`
compares all three on every change to `common/` and nightly, so they cannot
diverge silently.

## Install

Download an archive from [Releases](https://github.com/RootHerald/sdk-windows/releases).
Each contains `lib/RootHerald.lib`, `include/rootherald.h`, `include/protocol.h` and
`SHA256SUMS`.

```bash
sha256sum -c SHA256SUMS
gh attestation verify rootherald-windows-x64.tar.gz --repo RootHerald/sdk-windows
```

The archive is not code-signed and does not need to be: a static library is not
an executable image. You link it, and your certificate signs the result.

## Linking

`RootHerald.lib` is built against the **dynamic C runtime** (`/MD`, or `/MDd`
for Debug). Because this is a static archive that ends up inside your binary,
your own translation units have to use the same CRT model.

```
cl /MD /I include your_app.c /link lib\RootHerald.lib ^
   winhttp.lib crypt32.lib ncrypt.lib tbs.lib bcrypt.lib advapi32.lib
```

A mismatch does not fail cleanly. You get a pile of `LNK4286` warnings and then
an unresolved CRT symbol such as `__imp_toupper`, none of which names the actual
problem. Watch for two easy ways to hit it:

- bare `cl` with no runtime flag defaults to `/MT` (static) and will not link
- an MSBuild project set to *Multi-threaded (/MT)* rather than the default
  *Multi-threaded DLL (/MD)*

## Build from source

```bash

cmake -B build -S . -A x64
cmake --build build --config Release
```

## History

Extracted from `RootHerald/sdk-native` with per-file history preserved.
