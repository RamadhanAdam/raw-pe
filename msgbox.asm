; msgbox
; Author :  Ramadhan Adam
; Educational : this PE is built to understsand PE file internals from scratch.
; Pops a MessageBox saying " I built this from scratch" then exits.
; Imports: MessageBoxA (user32.dll), ExitProcess (kernel32.dll)
; Assemble : nasm -f bin msgbox.asm -o msgbox.exe
; Verify: open msgbox.exe in PE-bear

; DOS header bytes (64 bytes)
db      0x4D, 0x5A ; MZ magic
dd      0x00000040 ; e_lfanew

; PE SIGNATURE & FILE HEADER (IMAGE_NT_HEADERS  )