# sdk-windows

The Root Herald native SDK for Windows. Ships as a **static archive plus
headers**: you link it into your own binary, and your own code-signing
certificate covers the result.

The source is public so a security reviewer can read the code that runs on
their users' machines.

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
problem. Two easy ways to hit it:

- bare `cl` with no runtime flag defaults to `/MT` (static) and will not link
- an MSBuild project set to *Multi-threaded (/MT)* rather than the default
  *Multi-threaded DLL (/MD)*

## Build from source

```bash
cmake -B build -S . -A x64
cmake --build build --config Release
```

## Other platforms

- Linux — [sdk-linux](https://github.com/RootHerald/sdk-linux)
- macOS — [sdk-macos](https://github.com/RootHerald/sdk-macos)

All three expose the same C ABI (`common/rootherald.h`), so the same
integration code works across them.
