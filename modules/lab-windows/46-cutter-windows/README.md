# 46 * Cutter (Rizin) RE on Windows -- LAB-WINDOWS

## Overview (plain language)
Cutter is a free, point-and-click reverse-engineering workbench built on the Rizin analysis engine. It opens a compiled program (an EXE or DLL) and shows you the raw machine instructions, a visual flow-chart of the code, the text strings inside the file, and the list of imported Windows functions the program relies on. Instead of running a suspicious program, you read it — like studying a machine's blueprint rather than switching it on. capa is a companion tool from Mandiant/FLARE that scans the same file and translates low-level details into plain statements of *capability* — for example "writes to a file", "communicates over HTTP", or "queries the registry" — so you get a quick summary of what a program can do before you dig deeper in Cutter. (Cutter is documented at https://cutter.re/ and is a Rizin GUI per https://github.com/rizinorg/cutter; capa's rule-based capability detection is described at https://github.com/mandiant/capa.)

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| Cutter | Included in FLARE-VM (Rizin-based) | GUI reverse-engineering platform: disassembly, graph view, strings, imports, decompiler |
| capa | Included in FLARE-VM | Detects program capabilities from a PE/shellcode via a rule engine and maps them to MITRE ATT&CK |

- Cutter is a free/open-source GUI for the Rizin reverse-engineering framework: https://github.com/rizinorg/cutter and https://cutter.re/
- capa is Mandiant/FLARE's tool that "identifies capabilities in executable files" and maps them to ATT&CK: https://github.com/mandiant/capa
- Both ship in Mandiant's FLARE-VM tooling distribution: https://github.com/mandiant/flare-vm

## Learning objectives
- Load a benign PE into Cutter and identify its entry point, imports, and strings.
- Navigate the disassembly and graph views to locate a function of interest by cross-reference.
- Run capa against the same sample and interpret the capability + ATT&CK output.
- Correlate a capa capability (e.g., file writes) back to a concrete function in Cutter.
- Produce a short static triage summary combining Cutter and capa findings.

## Environment check
```powershell
# Confirm Cutter and capa are on the PATH of this FLARE-VM
cutter --version
capa --version
```
Expected output: Cutter prints its version string and the bundled Rizin version (e.g., `Cutter version 2.x.x` / `rizin x.y.z`); capa prints a version line such as `capa 7.x.x`. If a command is not found, open a new terminal so the FLARE-VM PATH is loaded, or launch Cutter from the Start Menu shortcut.

Notes on the flags:
- Cutter supports `-v`/`--version` on its command line; see the Cutter CLI options in the documentation at https://cutter.re/ and the project repo https://github.com/rizinorg/cutter.
- `capa --version` is a standard capa flag documented in the usage/README at https://github.com/mandiant/capa (the current stable line is capa 7.x per the project's releases at https://github.com/mandiant/capa/releases).

## Guided walkthrough
1. Generate the benign sample (see Hands-on exercise) so `exercise\sample.exe` exists, then confirm its hash.
```powershell
Get-FileHash -Algorithm SHA256 .\exercise\sample.exe
```
Expected: a 64-character hex digest matching the value in the Answer key. **Why:** hashing first pins the exact artifact you will analyze so every later finding (capa output, Cutter dashboard values) is tied to one immutable file; `Get-FileHash` defaults to SHA256 but we pass `-Algorithm SHA256` explicitly for clarity (see Microsoft Learn: https://learn.microsoft.com/powershell/module/microsoft.powershell.utility/get-filehash).

2. Do a fast capability triage with capa before opening the GUI.
```powershell
capa -v .\exercise\sample.exe
```
Expected: capa prints a table of matched capabilities (e.g., "print debug messages", "write to console") each with an ATT&CK technique tag and the rule name; a small benign program yields only a handful of rows. **Why:** running capa first gives you a hypothesis-driven map of *what to look for* in Cutter. `-v` (verbose) prints the matched rules and their ATT&CK/MBC tags per the capa usage docs at https://github.com/mandiant/capa/blob/master/doc/usage.md. **Nuance:** capa reasons over static structure only — a small statically linked CRT program can still surface a few generic rules; sparse or empty output on a larger binary is itself a signal of packing/obfuscation (see the capa README at https://github.com/mandiant/capa).

3. Open the sample in Cutter from the command line (or via the GUI file picker) and let Rizin auto-analyze.
```powershell
cutter .\exercise\sample.exe
```
Expected: Cutter's load dialog appears; accept the default analysis level and click OK. After analysis the Dashboard shows file format (PE32/PE32+), architecture (x86/x64), entry point address, and section list. **Why:** the auto-analysis runs Rizin's `aaa`-style analysis to recover functions, cross-references, and strings before you browse; the Dashboard aggregates the PE header facts (format, bits, entrypoint, sections) that Rizin extracts. See the Cutter analysis docs at https://cutter.re/ and Rizin analysis commands at https://rizin.re/. **Nuance:** entry point for a console PE points at the CRT startup stub (e.g., `mainCRTStartup`), not directly at your `main`; you follow a cross-reference to reach user code.

4. In the Cutter GUI, use the left-hand panels: open **Strings** to list embedded text, open **Imports** to see called Win32 APIs, and double-click the entry point in **Functions** to view disassembly and press `space` to toggle the graph view. Use the **Decompiler** panel (Rizin's built-in decompiler, jsdec/rz-ghidra) to read pseudo-C for the selected function. **Why:** Strings and Imports are the fastest triage signals (encoded strings and dynamically resolved imports hint at evasion), while the graph view exposes control flow to spot conditionals, loops, and anti-analysis checks. Toggling disassembly/graph with `space` is a documented Cutter shortcut (https://cutter.re/). The decompiler is a Rizin plugin (rz-ghidra) surfaced in Cutter per https://github.com/rizinorg/rz-ghidra.

## Hands-on exercise
Reverse the benign artifact `exercise\sample.exe` and answer:
- What is the file's architecture and entry-point address (from the Cutter Dashboard)?
- Name one Win32 import shown in Cutter's Imports view.
- What capability does capa report, and which ATT&CK technique is it tagged with?

Sample declaration:
- **Type:** Windows PE console executable (x64), compiled from a tiny C source.
- **Safe origin:** Benign/inert. It only prints a fixed string to the console and exits. No network, no persistence, no live malware. Built locally by you with the FLARE-VM VC build tools.
- **Reproducible generator** (creates `exercise\sample.exe`):
```powershell
New-Item -ItemType Directory -Force -Path .\exercise | Out-Null
@'
#include <stdio.h>
int main(void) {
    printf("LAB-WINDOWS benign sample - inert\n");
    return 0;
}
'@ | Set-Content -Encoding ASCII .\exercise\sample.c
cl /nologo /Fe:.\exercise\sample.exe .\exercise\sample.c
Get-FileHash -Algorithm SHA256 .\exercise\sample.exe
```
Expected: `cl` compiles the source and emits `sample.exe`; `Get-FileHash` prints the sha256 you will confirm against the Answer key. (Compiler output can vary by toolchain version, so treat the printed hash as authoritative for *your* build.) The `cl` flags used are `/nologo` (suppress the banner) and `/Fe:` (name the output executable), both documented on Microsoft Learn: https://learn.microsoft.com/cpp/build/reference/nologo-suppress-startup-banner-c-cpp and https://learn.microsoft.com/cpp/build/reference/fe-name-exe-file.

## SOC analyst perspective
When Security Onion surfaces a suspicious binary — for example a file carved by Zeek's `file_extract` from an HTTP/SMB transfer or flagged by a Sysmon `Event ID 1` (ProcessCreate) or `Event ID 11` (FileCreate) alert — an analyst can pivot to Cutter and capa on FLARE-VM for static triage without detonating it. (Zeek file extraction: https://docs.zeek.org/en/master/frameworks/file-analysis.html; Sysmon event IDs: https://learn.microsoft.com/sysinternals/downloads/sysmon.)

Turn static findings into detection language:
- If capa reports **registry Run-key persistence** (**T1547.001**, https://attack.mitre.org/techniques/T1547/001/), hunt Sysmon `Event ID 13` (RegistryValueSet) targeting `HKLM\...\CurrentVersion\Run` / `HKCU\...\CurrentVersion\Run` in Security Onion's Elastic/Kibana, and pivot on the process image hash.
- If capa reports **HTTP C2 / application-layer protocol** (**T1071.001**, https://attack.mitre.org/techniques/T1071/001/), pivot to Zeek `http.log` (URIs, user-agents, host headers) and Suricata HTTP alerts; write/tune a Suricata rule for the observed URI or user-agent (Suricata rules: https://docs.suricata.io/en/latest/rules/index.html; Security Onion analyst tools: https://docs.securityonion.net/en/2.4/).
- If capa reports **command/scripting interpreter** use (**T1059**, https://attack.mitre.org/techniques/T1059/), correlate Sysmon `Event ID 1` command lines and parent/child chains.
- Sparse/empty capa output on a non-trivial binary suggests **packing/obfuscation** (**T1027**, https://attack.mitre.org/techniques/T1027/) — pivot on section entropy and unusual section names visible in the Cutter Dashboard.

Cutter confirms *where* in the code those behaviors live (by cross-reference from the imported API to its call sites), giving IR the evidence to justify containment and to build IOCs (strings, imported APIs, file hash) for enterprise-wide sweeps in Elastic. See SANS FOR610 for the static-triage methodology: https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/.

## Attacker perspective
Attackers reverse-engineer with the same free tooling to study licensed or defensive software, locate weak checks, and craft bypasses. Using Cutter they trace API-import patterns and string constants that AV/EDR key on, then apply concrete evasion TTPs:
- **Obfuscated/packed files (T1027, https://attack.mitre.org/techniques/T1027/):** pack with UPX-style compressors or custom crypters so the on-disk import table and strings are hidden until runtime — this yields sparse capa output and high-entropy sections.
- **Dynamic API resolution / import hashing:** resolve APIs at runtime via `GetProcAddress`/`LoadLibrary` or hashed lookups so the static import table (visible in Cutter's Imports view) is empty — this breaks capa's import-name rules by design (capa reasons over static structure; see https://github.com/mandiant/capa).
- **String encryption:** XOR/RC4-encode strings so Cutter's Strings panel shows only ciphertext; the FLOSS tool exists specifically to recover such strings.

Artifacts left for defenders regardless of evasion: the on-disk PE (hashable with `Get-FileHash`), any unencrypted strings and resources, the import table (or the *absence* of one — itself suspicious), and section anomalies (high entropy, non-standard section names, mismatched raw/virtual sizes) that Cutter's Dashboard and section view expose during triage. These PE-structure indicators tie back to **T1027** and its packing sub-technique context on the ATT&CK page above.

## Answer key
- **Architecture / entry point:** x64 (PE32+); the entry-point address is shown on the Cutter Dashboard and reproduced by the CLI check below (address value depends on the compiler/build).
- **An import:** `printf` (via the CRT) and standard kernel imports such as those from `KERNEL32.dll` appear in the Imports view.
- **capa capability:** a benign console-print sample typically matches rules such as *"write to console"* / *"print debug messages"*; capa tags each match with its ATT&CK technique in the output header. (capa rule/tag output format: https://github.com/mandiant/capa/blob/master/doc/usage.md.)

Commands that produce the findings:
```powershell
# Confirm hash of your build
Get-FileHash -Algorithm SHA256 .\exercise\sample.exe

# Capability + ATT&CK mapping
capa -v .\exercise\sample.exe

# Headless Rizin confirmation of format, arch, entry, imports
rizin -q -c "iI; ie; ii~printf" .\exercise\sample.exe
```
Expected: `Get-FileHash` prints the 64-hex sha256 of *your* locally compiled `sample.exe` (record it in your notes as the module sample hash); `capa -v` lists capabilities with technique tags; the `rizin` one-liner prints file info (`bintype pe`, `bits 64`), the entry address, and the `printf` import line. **Command notes:** `-q` runs quietly and `-c` executes a command then continues (Rizin CLI options: https://rizin.re/); the info commands `iI` (binary info), `ie` (entrypoints), and `ii` (imports) are documented Rizin analysis/info commands, and `~printf` is Rizin's internal grep filter (see https://rizin.re/ and the Rizin book at https://book.rizin.re/).

## MITRE ATT&CK & DFIR phase
- **DFIR phase:** Identification and Examination (static malware triage / analysis), aligned with the SANS FOR610 static-analysis methodology (https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/).
- **Techniques an analyst may attribute during this workflow:**
  - **T1059** — Command and Scripting Interpreter (if scripting/interpreter APIs seen): https://attack.mitre.org/techniques/T1059/
  - **T1547.001** — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder (if persistence writes seen): https://attack.mitre.org/techniques/T1547/001/
  - **T1071.001** — Application Layer Protocol: Web Protocols (HTTP/S C2): https://attack.mitre.org/techniques/T1071/001/
  - **T1027** — Obfuscated Files or Information (sparse capa output / packing as an indicator): https://attack.mitre.org/techniques/T1027/

  The benign lab sample itself matches only trivial capabilities; the technique IDs above illustrate how capa's ATT&CK-tagged output feeds ATT&CK mapping in real triage (capa's ATT&CK mapping is described at https://github.com/mandiant/capa).

## Sources
Claim → source mapping (all URLs are official/authoritative):

- **Cutter is a GUI for the Rizin RE framework; disassembly, graph, decompiler, CLI `--version`, `space` toggle** → Cutter site https://cutter.re/ and repo https://github.com/rizinorg/cutter
- **Rizin analysis engine, `iI`/`ie`/`ii` info commands, `~` internal grep, `-q`/`-c` flags** → Rizin docs https://rizin.re/ and the Rizin book https://book.rizin.re/
- **Cutter decompiler = rz-ghidra plugin** → https://github.com/rizinorg/rz-ghidra
- **capa identifies capabilities and maps them to ATT&CK; `-v` verbose; `--version`; static-only reasoning; packing → sparse output** → capa repo https://github.com/mandiant/capa, usage doc https://github.com/mandiant/capa/blob/master/doc/usage.md, releases https://github.com/mandiant/capa/releases
- **Cutter and capa ship in FLARE-VM** → https://github.com/mandiant/flare-vm
- **`Get-FileHash` defaults to SHA256; `-Algorithm SHA256`** → Microsoft Learn https://learn.microsoft.com/powershell/module/microsoft.powershell.utility/get-filehash
- **`cl` flags `/nologo` and `/Fe:`** → Microsoft Learn https://learn.microsoft.com/cpp/build/reference/nologo-suppress-startup-banner-c-cpp and https://learn.microsoft.com/cpp/build/reference/fe-name-exe-file
- **Sysmon event IDs (1 ProcessCreate, 11 FileCreate, 13 RegistryValueSet)** → Microsoft Learn https://learn.microsoft.com/sysinternals/downloads/sysmon
- **Zeek file extraction / http.log** → https://docs.zeek.org/en/master/frameworks/file-analysis.html
- **Suricata rule writing** → https://docs.suricata.io/en/latest/rules/index.html
- **Security Onion analyst workflow (Zeek/Suricata/Elastic)** → https://docs.securityonion.net/en/2.4/
- **MITRE ATT&CK techniques** → T1059 https://attack.mitre.org/techniques/T1059/ ; T1547.001 https://attack.mitre.org/techniques/T1547/001/ ; T1071.001 https://attack.mitre.org/techniques/T1071/001/ ; T1027 https://attack.mitre.org/techniques/T1027/ ; ATT&CK Enterprise index https://attack.mitre.org/
- **Static-analysis / triage methodology** → SANS FOR610 https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/

## Related modules
- [Static reverse engineering](../12-static-re/README.md) -- shares capa for capability-driven static triage.
- [Ghidra decompiler & scripting deep-dive](../27-ghidra-scripting/README.md) -- shares capa and complements Cutter's rz-ghidra decompiler.
- [FLOSS obfuscated-string extraction](../42-floss-strings/README.md) -- shares capa and recovers encrypted strings Cutter's Strings panel cannot show.
- [Scenario: .NET malware analysis](../53-dotnet-malware-case/README.md) -- shares capa for capability mapping on managed-code samples.

<!-- cyberlab-enriched: v1 -->
