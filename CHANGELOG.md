# Changelog

All notable changes to Vapor will be documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-04-04

### Added
- ChaCha20-Poly1305 AEAD encryption (RFC 8439) in pure x86_64 assembly
- Position-independent shellcode implant (~3.6 KB)
- PEB walking with ror13 hash-based API resolution
- Random nonce generation via SystemFunction036 (RtlGenRandom)
- Piped command execution with CreateProcessA and PeekNamedPipe polling
- Dual output: raw shellcode (vapor.bin) and minimal PE (vapor.exe)
- Hell's Gate syscall number extraction from ntdll stubs
- Halo's Gate fallback for hooked stubs
- Indirect syscall execution via ntdll gadget (0F 05 C3)
- Early Bird APC injection into suspended processes
- Configurable injection target process at build time
- Python listener with Catppuccin Mocha themed CLI
- Build script with automatic PSK generation
- Makefile with NASM + MinGW-w64 toolchain
