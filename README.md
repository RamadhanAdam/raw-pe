# raw-pe

I created this Windows PE from scratch to understand in depth how Windows PE
(Portable Executable) files work and how they're built. This helps me for
malware analysis.

## What this is

A Win64 GUI executable, hand-assembled byte-by-byte with NASM — every DOS
header field, NT header field, section header, and import table entry
written manually, no linker.

It shows a Yes/No `MessageBoxA` ("Do you want to continue?") and exits with
code `0` (Yes) or `1` (No).

## Structure

```
.
├── docs/Nasm_cheatsheet.md   # notes kept while building this
├── images/                   # crash screenshots referenced below
├── msgbox.asm                # the whole PE, hand-written
├── msgbox.exe                # assembled output
├── LICENSE
└── README.md
```

## Build

```bash
nasm -f bin msgbox.asm -o msgbox.exe
```

Requires NASM. Output should be exactly 2560 bytes (0xA00).

## Run

Copy `msgbox.exe` to a Windows machine or VM and run it:

```powershell
.\msgbox.exe
```
Or just simply double-click the .exe file and you will see this :

![main-app](images/main-app.png)

For users running in powershell:

Click Yes/No, then check the exit code:
```powershell
$LASTEXITCODE   # 0 = Yes, 1 = No
```

If PowerShell returns immediately without waiting (common for GUI-subsystem
processes), use:
```powershell
Start-Process -FilePath .\msgbox.exe -Wait
$LASTEXITCODE
```

This is an unsigned, hand-built binary — Windows SmartScreen will flag it as
uncommon. Run it in a VM or sandbox you control.

## Challenges I faced

- Wrote `dd x, dd y` on one line in the data directories — NASM needs one
  `dd` per value.
- Forgot the `bits 64` directive, so NASM defaulted to 16-bit mode.
- Forgot the null-terminator entry at the end of the Import Directory
  Table (a zeroed 20-byte entry marking the end of the DLL list), which
  the loader needs to know where the import descriptors stop.
- Got the padding wrong between sections more than once — `.text`,
  `.data`, `.bss`, and `.idata` need to land at exact file offsets matching
  their section headers' `PointerToRawData`, so I added explicit
  `times (X - ($ - $$)) db 0` padding between each one.
- `SizeOfImage` didn't cover `.idata`'s virtual address range.
- `SizeOfInitializedData` didn't include `.idata`.
- After adding the `.idata` section header, `SizeOfHeaders` and the other
  sections' `PointerToRawData` values were stale and had to be recalculated.
- Typo: `call[rel ...]`, missing a space, blocked assembly entirely.
- The big one: used `call [rel user32_iat]` to call through the IAT and
  `mov rdx, message` to reference strings in `.data`, both relying on
  RIP-relative addressing. NASM's `-f bin` output computes that using flat
  file-offset deltas, not RVA deltas — wrong across sections, since
  `SectionAlignment` and `FileAlignment` diverge. Didn't fail to assemble,
  crashed the binary at runtime instead. Full writeup below.

Full commit history: [github.com/RamadhanAdam/raw-pe/commits/main](https://github.com/RamadhanAdam/raw-pe/commits/main)

## Debugging the 0xc0000005 crash

**Symptom:** first build that compiled clean, sized correctly, and passed
PE-bear inspection produced no dialog on launch. No window, no error.

**Checking if it was running:**
```powershell
.\msgbox.exe
$LASTEXITCODE
```
No output. GUI-subsystem processes detach immediately, so `$LASTEXITCODE`
alone wasn't enough, I switched to `Start-Process -Wait` to block on it.

**Event Viewer:** checked Event Viewer -> Windows Logs -> Application. First
entry was a `Windows Error Reporting` event (ID 1001, type `BEX64` — a
generic crash bucket Windows uses when it can't classify the fault more
precisely):

![Event 1001 - BEX64 crash bucket](images/01-crash-bex64-event.webp)

Next to it, the `Application Error` (Event ID 1000) with the actual
exception details:

![Event 1000 - access violation details](images/02-crash-application-error.webp)

```
Faulting application name: msgbox.exe
Exception code: 0xc0000005      (access violation)
Fault offset: 0x0000000000000000
Faulting module name: unknown
```

`Fault offset 0x0` and `module unknown` meant the CPU jumped straight to
address `0x0` — consistent with calling through a null or garbage pointer.

**Root cause:** `.text` called imported functions like this:
```asm
call [rel user32_iat]
```
`[rel label]` is RIP-relative addressing. NASM's `-f bin` output has no
concept of sections — it computes every relative offset as a flat file byte
delta. Accurate within one section, but sections are laid out differently on
disk (`FileAlignment = 0x200`) than in memory (`SectionAlignment = 0x1000`).
A reference from `.text` (file offset `0x400`, RVA `0x1000`) to `.idata`
(file offset `0x800`, RVA `0x4000`) has a file delta of `0x400` but a
runtime delta of `0x3000`. NASM baked in the wrong one, so the `call` landed
on garbage — in this case, effectively `0x0`.

**Fix:** replaced every cross-section symbolic reference with an absolute
64-bit VA, computed as `ImageBase + section_RVA + intra_section_offset`,
loaded with `mov reg, imm64` and dereferenced with `call [reg]`:
```asm
; before (broken — file-offset delta != runtime RVA delta)
call [rel user32_iat]

; after (correct — absolute VA, computed at assemble time)
mov rax, 0x140000000 + 0x4000 + (user32_iat - idata_start)
call [rax]
```
Intra-section symbolic math (e.g. `import_dir - idata_start`, both inside
`.idata`) was safe to leave as-is, since file-offset delta and RVA delta
agree when both labels live in the same section.

**Verified:**

![Fixed - dialog rendering correctly](images/03-fixed-dialog-working.webp)

Dialog appeared, exit code matched Yes/No correctly.

**Follow-up intermittent crash:** same `0xc0000005` crash recurred on a
later run:

![Follow-up crash - Details tab](images/04-followup-crash-details.webp)
![Follow-up crash - General tab](images/05-followup-crash-general.webp)

Checked `AppTimeStamp` in Event Viewer's Details tab against the PE header's
`TimeDateStamp` — confirmed it was the current fixed binary crashing, not a
stale copy. Two hypotheses:

1. Most likely: two files were sitting in Downloads (`msgbox.exe` and a
   leftover `msgbox (1).exe` from an earlier download), and the old one got
   run by accident.
2. Worth flagging regardless: this binary has no `.reloc` section and
   hardcodes absolute VAs against a fixed `ImageBase` (`0x140000000`). If
   Windows can't map the image at that exact preferred base and silently
   relocates it, every hardcoded VA in `.text` would point to stale
   addresses — same symptom, intermittent depending on memory conditions
   at load time.

Deleted the duplicate file, reran several times cleanly with no recurrence —
consistent with hypothesis #1. Hypothesis #2 stays documented here since
adding a `.reloc` section (or explicitly handling non-preferred-base loads)
is the correct long-term fix.

## Known limitations

- No `.reloc` section — the binary only works if the loader can map it at
  its preferred `ImageBase` (`0x140000000`). No ASLR support.
- No error handling if either DLL/import fails to resolve.
- Written for learning, not for production use of any kind.

## License

MIT — see [LICENSE](LICENSE).