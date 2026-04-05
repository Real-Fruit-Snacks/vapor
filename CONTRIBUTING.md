# Contributing to Vapor

Thank you for your interest in contributing to Vapor! This document provides guidelines and instructions for contributing.

## Development Environment Setup

### Prerequisites

- **NASM:** Latest version for x86_64 assembly
- **MinGW-w64:** `x86_64-w64-mingw32-ld` for linking
- **Python 3.8+:** For the listener and build script
- **Git:** For version control

### Getting Started

```bash
# Fork and clone the repository
git clone https://github.com/<your-username>/Vapor.git
cd Vapor

# Build everything (generates random PSK)
./build.sh 127.0.0.1 443

# Or use make directly
make LHOST=127.0.0.1 LPORT=443 all

# Clean build artifacts
make clean
```

## Code Style

Vapor is written in x86_64 NASM assembly. Follow these conventions:

- **Labels:** Lowercase with underscores (`resolve_api`, `chacha20_block`)
- **Constants:** Uppercase with underscores (`CALLBACK_IP`, `BUFFER_SIZE`)
- **Comments:** Explain intent, not mechanics. Every function gets a header comment.
- **Indentation:** Consistent 4-space or tab indentation for instructions
- **Sections:** Clearly delimit `.text`, `.data`, `.bss` sections

## Testing

Test changes against a local listener before submitting:

```bash
# Build with test key
./build.sh 127.0.0.1 4444

# Start listener in one terminal
python3 listener.py --lport 4444 --key <key-from-build>

# Run implant or injector in another terminal
```

## Pull Request Process

1. **Fork** the repository and create a feature branch:
   ```bash
   git checkout -b feat/my-feature
   ```

2. **Make your changes** with clear, focused commits.

3. **Test thoroughly** against a local listener.

4. **Push** your branch and open a Pull Request against `main`.

5. **Describe your changes** in the PR using the provided template.

6. **Respond to review feedback** promptly.

## Commit Message Format

This project follows [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<optional scope>): <description>

[optional body]

[optional footer(s)]
```

### Types

| Type       | Description                          |
| ---------- | ------------------------------------ |
| `feat`     | New feature                          |
| `fix`      | Bug fix                              |
| `docs`     | Documentation changes                |
| `style`    | Formatting, no code change           |
| `refactor` | Code restructuring, no behavior change |
| `test`     | Adding or updating tests             |
| `ci`       | CI/CD changes                        |
| `chore`    | Maintenance, dependencies            |
| `perf`     | Performance improvements             |

### Examples

```
feat(crypto): add Poly1305 MAC verification on receive
fix(injector): handle hooked ntdll stubs via Halo's Gate fallback
docs: update build instructions for NASM 2.16
```

### Important

- Do **not** include AI co-author signatures in commits.
- Keep commits focused on a single logical change.

## Questions?

If you have questions about contributing, feel free to open a discussion or issue on GitHub.
