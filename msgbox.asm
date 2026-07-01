; msgbox
; Author :  Ramadhan Adam
; Educational : this PE is built to understsand PE file internals from scratch.
; Pops a MessageBox saying " I built this from scratch" then exits.
; Imports: MessageBoxA (user32.dll), ExitProcess (kernel32.dll)
; Assemble : nasm -f bin msgbox.asm -o msgbox.exe
; Verify: open msgbox.exe in PE-bear

; DOS HEADER (64 bytes)
;-----------------------------

db      0x4D, 0x5A ; MZ magic number (2 bytes)
dw      0x00       ; e_blp  bytes on last page of file (2 bytes)
dw      0x00       ; e_cp   Pages in file (2 bytes)
dw      0x00       ; e_crlc Relocations (2 bytes)
dw      0x00       ; e_cparhdr Size of header in paragraphs (2 bytes)
dw      0x00       ; e_minalloc Minimum extra paragraphs needed (2 bytes)
dw      0x00       ; e_maxalloc Maximum extra paragraphs needed (2 bytes)
dw      0x00       ; e_ss Initial (relative ) SS value (2 bytes)
dw      0x00       ; e_sp Initial SP value (2 bytes)
dw      0x00       ; e_csum Checksum (2 bytes)
dw      0x00       ; e_ip Initial IP value (2 bytes)
dw      0x00       ; e_cs Initial (relative) CS value (2 bytes)
dw      0x00       ; e_lfarlc File address of relocation table (2 bytes)
dw      0x00       ; e_ovno Overlay number (2 bytes)
times 4 dw  0x0000     ; e_res[4] Reserved word (8 bytes)
dw      0x0000     ; e_oemid OEM identifier (2 bytes)
dw      0x0000     ; o_eminfo OEM information (2 bytes)
times 10 dw  0x0000     ; e_res2 (20 bytes)
dd      0x00000080 ; e_lfanew Offset to NT header - 128 bytes offset (4 bytes)

; DOS STUB (64 bytes) - I wrote both cases for reference
;-------------------------------------------------------

db      "This program must be run under Win32."
times 27 db 0x00
; times 64 db 0x00   ; Stub of pure zeros

; PE SIGNATURE & FILE HEADER (IMAGE_NT_HEADERS) (264 bytes)
;-----------------------------------------------

; Signature (4 bytes)
; -------------------
dd      0x00004550  ;"PE\0\0" Identifies file image 

; File Header (20 bytes)
; ----------------------

dw      0x8664      ; Machine : AMD64 (64) (2 bytes)
dw      0x0001      ; Number of sections 1 (2 bytes)
dd      0x6A443E92  ; TimeDateStamp ( 4 bytes)
dd      0x00000000  ; PointerToSymbolTable (4 bytes)
dd      0x00000000  ; NumberOfSymbols (4 bytes)
dw      0x00F0      ; SizeOfOptionalHeader (2 bytes) = 24 (standard) + 88 (Windows-specific) + 128 (16 data directories × 8 bytes)
dw      0x0223      ; Characteristics: RELOCS_STRIPPED | EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE | DEBUG_STRIPPED


; Optional Header PE32+ (240 bytes - 0x00F0)
;-----------------------------------------------
; Standard fields (24 bytes)
dw      0x020B      ; Magic - 0x20B identifies PE32+ (2 bytes)
db      0x00        ; MajorLinkerVersion - arbitrary, cosmetic (1 byte)
db      0x00        ; MinorLinkerVersion - arbitrary, cosmetic (1 byte)
dd      0x00000200  ; SizeOfCode - total code size, file-aligned (4 bytes) [PLACEHOLDER, fix once code written]
dd      0x00000000  ; SizeOfInitializedData (4 bytes) [PLACEHOLDER, revisit once import table built]
dd      0x00000000  ; SizeOfUninitializedData - no .bss section (4 bytes)
; AddressOfEntryPoint - RVA of first instruction executed (4 bytes) [PENDING - needs section table]
; BaseOfCode - RVA where code section begins (4 bytes) [PENDING - needs section table]

; Windows-specific fields (88 bytes)
; ImageBase - preferred load address in memory (8 bytes, dq, 64-bit)
; SectionAlignment - alignment of sections in memory, e.g. 0x1000 (4 bytes)
; FileAlignment - alignment of sections on disk, e.g. 0x200 (4 bytes)
; MajorOperatingSystemVersion - min OS version required (2 bytes)
; MinorOperatingSystemVersion - min OS version required (2 bytes)
; MajorImageVersion - version of your own image, cosmetic (2 bytes)
; MinorImageVersion - version of your own image, cosmetic (2 bytes)
; MajorSubsystemVersion - min subsystem version required (2 bytes)
; MinorSubsystemVersion - min subsystem version required (2 bytes)
; Win32VersionValue - reserved, must be 0 (4 bytes)
; SizeOfImage - total image size in memory, SectionAlignment-rounded (4 bytes)
; SizeOfHeaders - total header size, FileAlignment-rounded (4 bytes)
; CheckSum - usually 0 for non-driver/non-boot files (4 bytes)
; Subsystem - e.g. WINDOWS_GUI=2, WINDOWS_CUI=3 (2 bytes)
; DllCharacteristics - ASLR/DEP-related flags (2 bytes)
; SizeOfStackReserve - max stack size reserved (8 bytes)
; SizeOfStackCommit - stack size committed at startup (8 bytes)
; SizeOfHeapReserve - max default heap size reserved (8 bytes)
; SizeOfHeapCommit - default heap size committed at startup (8 bytes)
; LoaderFlags - obsolete, must be 0 (4 bytes)
; NumberOfRvaAndSizes - count of data directory entries (16) (4 bytes)

; Data directories (128 bytes = 16 × 8)
; 0  ExportTable           - functions this image exports
; 1  ImportTable           - functions this image imports
; 2  ResourceTable         - icons, strings, dialogs, version info
; 3  ExceptionTable        - SEH/unwind info (x64)
; 4  CertificateTable      - digital signature
; 5  BaseRelocationTable   - relocation entries
; 6  Debug                 - debug info pointer
; 7  Architecture          - reserved, must be zero
; 8  GlobalPtr             - global pointer register value (unused x86/x64)
; 9  TLSTable              - thread-local storage
; 10 LoadConfigTable       - extra loader config
; 11 BoundImport           - precomputed import binding info
; 12 IAT                   - Import Address Table location/size
; 13 DelayImportDescriptor - delay-loaded imports
; 14 CLRRuntimeHeader      - .NET header
; 15 Reserved              - must be zero


; SECTION HEADERS (40 bytes per entry)
;-------------------------------------
; .text section header (40 bytes)

db      ".text",0,0,0   ; Name (8 bytes)
dd      (code_end - code_start); VirtualSize (4 bytes) 
dd 0x00001000           ; VirtualAddress: Memory offset where code is loaded in RAM (RVA) (4 bytes)
dd ((code_end - code_start + 0x1FF) / 0x200) * 0x200   ; SizeOfRawData: Rounds up size to next 512-byte boundary (e.g., 512, 1024, etc.) (4 bytes)
dd 0x00000200           ; PointerToRawData: File offset on disk where code bytes start
times 4 db 0x00         ; PointerToRelocations (4 bytes)
times 4 db 0x00         ; PointerToLinenumbers (4 bytes)
dw      0x0000          ; NumberOfRelocations (2 bytes)
dw      0x0000          ; NumberOfLinenumbers (2 bytes)
dd      0x60000020      ; Characteristics (4 bytes)

; .data section header (40 bytes)
db      ".data",0,0,0   ; Name (8 bytes)
dd      0x00000021      ; VirtualSize: 33 bytes in hex (4 bytes)
dd      0x00002000      ; VirtualAddress: Memory offset in RAM (RVA) (4 bytes)
dd      0x00000200      ; SizeOfRawData: 512 bytes in hex (4 bytes)
dd      0x00000400      ; PointerToRawData: File offset on disk (4 bytes)
times 4 db 0x00         ; PointerToRelocations (4 bytes)
times 4 db 0x00         ; PointerToLinenumbers (4 bytes)
dw      0x0000          ; NumberOfRelocations (2 bytes)
dw      0x0000          ; NumberOfLinenumbers (2 bytes)
dd      0xC0000040      ; Characteristics: Read + Write + Initialized Data (4 bytes)

; .bss section header (40 bytes)
db      ".bss",0,0,0,0  ; Name (8 bytes)
dd      0x00000008      ; VirtualSize: 8 bytes in hex (4 bytes)
dd      0x00003000      ; VirtualAddress: Memory offset in RAM (RVA) (4 bytes)
dd      0x00000000      ; SizeOfRawData: 0 bytes on disk (4 bytes)
dd      0x00000000      ; PointerToRawData: 0 because it doesn't exist on disk (4 bytes)
times 4 db 0x00         ; PointerToRelocations (4 bytes)
times 4 db 0x00         ; PointerToLinenumbers (4 bytes)
dw      0x0000          ; NumberOfRelocations (2 bytes)
dw      0x0000          ; NumberOfLinenumbers (2 bytes)
dd      0xC0000080      ; Characteristics: Read + Write + Uninitialized Data (4 bytes)


; SECTIONS (.text, .bss , .data)
;-------------------------------------

; External Windows API
extern MessageBoxA
extern ExitProcess

; Data Section (Initialized variables) (33 bytes)
section .data 
    title       db "Confirm", 0 ; 0 for null byte at the end of a string ( 8 bytes)
    message     db "Do you want to continue?", 0 ; (25 bytes)

; BSS Section (Block Started by Symbol) Uninitialized RAM Reservation (0 bytes disk / 8 bytes RAM - reserved space)
section .bss    
    result      resq    1 ; resq because it is 64 bit (quad-word) slot

; CODE SEGMENT (.text)
segment .text
        global main 

code_start:                 ; Track start for PE Header calculations

main: 
        ; --- SETUP REGISTERS & CALL MESSAGEBOXA ---
        sub rsp, 40         ; 4 bytes - Allocate 32 shadow space + 8 alignment pad
        mov rcx, 0          ; 7 bytes - Argument 1: hWnd = NULL
        mov rdx, message    ; 7 bytes - Argument 2: lpText (RIP-relative pointer)
        mov r8,  title      ; 7 bytes - Argument 3: lpCaption (RIP-relative pointer)
        mov r9,  4          ; 7 bytes - Argument 4: uType = MB_YESNO
        call MessageBoxA    ; 5 bytes
        add rsp, 40         ; 4 bytes - Free stack space

        ; --- EVALUATE USER CLICK ---
        mov [result], rax   ; 7 bytes - Save 64-bit return value to BSS slot
        cmp eax, 6          ; 3 bytes - Check if return value matches IDYES (6)
        je  yes_branch      ; 2 bytes - Jump to success logic if equal

        ; --- "NO" BRANCH ---
        sub rsp, 40         ; 4 bytes - Reallocate space for next API call
        mov rcx, 1          ; 7 bytes - Argument 1: Exit code 1 (Failure/No)
        call ExitProcess    ; 5 bytes

    yes_branch:
        ; --- "YES" BRANCH ---
        sub rsp, 40         ; 4 bytes - Reallocate space for next API call
        mov rcx, 0          ; 7 bytes - Argument 1: Exit code 0 (Success/Yes)
        call ExitProcess    ; 5 bytes

code_end:                   ; Track end for PE Header calculations
