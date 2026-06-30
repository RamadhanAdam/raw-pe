; msgbox
; Author :  Ramadhan Adam
; Educational : this PE is built to understsand PE file internals from scratch.
; Pops a MessageBox saying " I built this from scratch" then exits.
; Imports: MessageBoxA (user32.dll), ExitProcess (kernel32.dll)
; Assemble : nasm -f bin msgbox.asm -o msgbox.exe
; Verify: open msgbox.exe in PE-bear

; DOS header bytes (64 bytes)
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
dd      0x00000040 ; e_lfanew Offset to NT header (4 bytes)

; PE SIGNATURE & FILE HEADER (IMAGE_NT_HEADERS  )