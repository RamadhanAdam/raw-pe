# NASM x64 Cheat Sheet (Windows PE Focus)

## Sections
```nasm
section .text   ; code (read-only)
section .data   ; initialized data
section .bss    ; uninitialized data (use resb, resw, resq)
```

## Data Directives
```nasm
db   ; define 1 byte
dw   ; define 2 bytes (word)
dd   ; define 4 bytes (doubleword)
dq   ; define 8 bytes (quadword)

resb 64   ; reserve 64 bytes (bss only)
resw 1    ; reserve 1 word (bss only)
resq 10   ; reserve 10 quadwords (bss only)

equ   ; constant, not stored in memory — assembler replaces it
```

## Registers

### Integer Registers
```
RAX   64-bit  -> EAX  32-bit  -> AX   16-bit  -> AH/AL  8-bit
RCX   64-bit  -> ECX  32-bit  -> CX   16-bit  -> CH/CL  8-bit
RDX   64-bit  -> EDX  32-bit  -> DX   16-bit  -> DH/DL  8-bit
RBX   64-bit  -> EBX  32-bit  -> BX   16-bit  -> BH/BL  8-bit
RSP   64-bit  -> ESP  32-bit  -> SP   16-bit  (stack pointer)
RBP   64-bit  -> EBP  32-bit  -> BP   16-bit  (base pointer)
RSI   64-bit  -> ESI  32-bit  -> SI   16-bit  (source)
RDI   64-bit  -> EDI  32-bit  -> DI   16-bit  (destination)
R8  - R15     -> R8D - R15D   -> R8W - R15W   -> R8B - R15B
```

### Register Roles (Windows x64)
```
RAX   return value
RCX   1st argument
RDX   2nd argument
R8    3rd argument
R9    4th argument
RSP   stack pointer — never touch carelessly
RBP   base pointer — tracks stack frame
```

### Volatile vs Nonvolatile (Windows)
```
Volatile   (caller saves if needed): RAX, RCX, RDX, R8, R9, R10, R11
Nonvolatile (callee must preserve):  RBX, RBP, RDI, RSI, RSP, R12-R15
```

## RFLAGS
```
ZF   zero flag     — result was zero
CF   carry flag    — unsigned overflow
SF   sign flag     — result was negative
OF   overflow flag — signed overflow
DF   direction flag — string operation direction (cld = forward, std = backward)
```

## Memory Addressing
```nasm
[750]                ; fixed address
[rbx]                ; address stored in register
[rbx + 8]            ; register + offset
[rcx + rsi*4]        ; base + index * scale (scale: 1, 2, 4, or 8)
[rax + rdi*8 + 500]  ; base + index * scale + displacement
```

## Common Instructions
```nasm
mov  dst, src        ; copy src into dst
lea  dst, [src]      ; load address of src into dst (not the value)
add  dst, src        ; dst = dst + src
sub  dst, src        ; dst = dst - src
inc  dst             ; dst = dst + 1
dec  dst             ; dst = dst - 1
xor  dst, src        ; dst = dst XOR src  (xor rax, rax = set rax to 0)
cmp  a, b            ; subtract b from a, set flags, discard result
test a, b            ; AND a and b, set flags, discard result
imul dst, src        ; signed multiply
push src             ; RSP -= 8, [RSP] = src
pop  dst             ; dst = [RSP], RSP += 8
call label           ; push return address, jump to label
ret                  ; pop return address into RIP, jump there
syscall              ; invoke OS
```

## Conditional Jumps
```nasm
je   ; jump if equal         (ZF = 1)
jne  ; jump if not equal     (ZF = 0)
jz   ; jump if zero          (ZF = 1)
jnz  ; jump if not zero      (ZF = 0)
jl   ; jump if less          (signed)
jg   ; jump if greater       (signed)
jle  ; jump if less or equal (signed)
jge  ; jump if greater or equal (signed)
jb   ; jump if below         (unsigned)
ja   ; jump if above         (unsigned)
jng  ; jump if not greater   (same as jle)
```

## Stack
```
Stack grows downward (toward lower addresses)
RSP always points to top of stack (lowest used address)

push rax  ->  RSP = RSP - 8, [RSP] = rax
pop  rax  ->  rax = [RSP], RSP = RSP + 8
```

## Windows x64 Calling Convention
```
Arguments:    RCX, RDX, R8, R9 (first 4), rest pushed on stack
Return value: RAX
Shadow space: 32 bytes must be reserved before every call
Alignment:    RSP must be 16-byte aligned before call
```

### Calling a Function on Windows
```nasm
sub  rsp, 40        ; 32 bytes shadow space + 8 for alignment (return addr already pushed)
mov  rcx, arg1      ; first argument
mov  rdx, arg2      ; second argument
call SomeFunction
add  rsp, 40        ; restore stack
```

### Calling ExitProcess
```nasm
sub  rsp, 40        ; shadow space + alignment
xor  rcx, rcx      ; exit code 0 = success
call ExitProcess
add  rsp, 40        ; never reached but good practice
```

## Local Variables on Windows
```nasm
; No red zone on Windows — must move RSP explicitly
example:
    sub  rsp, 24          ; make room for 3 local variables (3 x 8 bytes)
    mov  qword [rsp], 0   ; variable a at RSP+0
    mov  qword [rsp+8], 7 ; variable b at RSP+8
    mov  qword [rsp+16], 0; variable c at RSP+16
    ; ... do work ...
    add  rsp, 24          ; restore RSP before returning
    ret
```

## Stack Alignment Rule
```
When your function starts: RSP is misaligned by 8 (return address was pushed)
Before any call:           RSP must end in 0 (divisible by 16)
Fix:                       sub rsp, 40  (32 shadow + 8 alignment)
                           add rsp, 40  before ret
```

## Hex Quick Reference
```
1 hex digit  = 4 bits
2 hex digits = 1 byte
4 hex digits = 2 bytes (word)
8 hex digits = 4 bytes (doubleword)
16 hex digits = 8 bytes (quadword)

16-byte aligned = address ends in 0 in hex
```

## Number Formats in NASM
```nasm
200       ; decimal
0xc8      ; hex
0c8h      ; hex (NASM style, needs leading 0 if starts with letter)
11001000b ; binary
```

## macOS vs Linux vs Windows
```
Format:       macOS = macho64   Linux = elf64    Windows = win64
Entry point:  macOS = _main     Linux = _start   Windows = main
Syscall nos:  macOS ≠ Linux (totally different)
C functions:  macOS prefix _    Linux no prefix  Windows no prefix
Calling conv: macOS/Linux = RDI RSI RDX RCX R8 R9
              Windows     = RCX RDX R8  R9
Shadow space: Windows only (32 bytes before every call)
Red zone:     macOS/Linux only (128 bytes below RSP safe without moving RSP)
              Windows has NO red zone — always sub rsp first
```

## Program Skeleton (Windows PE)
```nasm
global main
extern ExitProcess

section .text
main:
    sub  rsp, 40        ; shadow space + alignment
    ; your code here
    xor  rcx, rcx      ; exit code 0
    call ExitProcess
    add  rsp, 40
    ret
```

## PE File Injection References

### IMAGE_FILE_HEADER: Machine & Sections
```nasm
; 32-bit x86 Configuration
dw      0x014C     ; Machine: Intel 386 / x86 (Flipped from 4C 01 in memory)
dw      0x0001     ; NumberOfSections: 1 section (Flipped from 01 00 in memory)

; 64-bit x64 Configuration
dw      0x8664     ; Machine: AMD64 / x64 (Flipped from 64 86 in memory)
dw      0x0001     ; NumberOfSections: 1 section (Flipped from 01 00 in memory)
```
