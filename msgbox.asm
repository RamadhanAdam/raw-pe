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

; PE SIGNATURE & FILE HEADER (IMAGE_NT_HEADERS)
;-----------------------------------------------

; Signature (4 bytes)
dd      0x00004550  ;"PE\0\0" Identifies file image 

; File Header (20 bytes)
dw      0x8664      ; Machine : AMD64 (64) (2 bytes)
dw      0x0001      ; Number of sections 1 (2 bytes)
dd      0x6A443E92  ; TimeDateStamp ( 4 bytes)
dd      0x00000000  ; PointerToSymbolTable (4 bytes)
dd      0x00000000  ; NumberOfSymbols (4 bytes)
dw      0x00F0      ; SizeOfOptionalHeader (2 bytes) = 24 (standard) + 88 (Windows-specific) + 128 (16 data directories × 8 bytes)
dw      0x0223      ; Characteristics: RELOCS_STRIPPED | EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE | DEBUG_STRIPPED