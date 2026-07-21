# 12 * Static reverse engineering -- LAB-WINDOWS

## Overview (plain language)
Static reverse engineering means studying a program **without running it** — like reading a car's blueprint instead of driving it. These tools open a Windows executable (`.exe`/`.dll`) and show you the machine instructions, embedded text, and file structure hidden inside. Because the file is never executed, you avoid the risk of infecting your machine. Ghidra and Cutter turn raw bytes into human-readable code (disassembly and decompilation); PE-bear shows the file's headers and layout; FLOSS pulls out hidden and obfuscated strings; and capa recognizes what capabilities the program has (e.g. "can encrypt files" or "can inject code"). Together they let an analyst understand what a suspicious file is designed to do before it ever gets a chance to do it.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| Ghidra | choco install ghidra (FLARE-VM) | Full-featured disassembler + decompiler for binary analysis |
| Cutter | Installed by FLARE-VM | Rizin-based GUI disassembler with decompiler and CLI (rizin) |
| capa | Installed by FLARE-VM | Detects program capabilities by matching rules against binaries |
| FLOSS | Installed by FLARE-VM | Extracts static, stack, tight, and decoded/obfuscated strings |
| PE-bear | Installed by FLARE-VM | GUI inspector for PE headers, sections, imports, and resources |

Notes on tool provenance (for the source audit):
- Ghidra is developed and released by the U.S. National Security Agency; the official project site is ghidra-sre.org and the source repo is github.com/NationalSecurityAgency/ghidra.
- Cutter is the official GUI front end for the Rizin reverse-engineering framework (cutter.re / rizin.re); the CLI binary is `rizin`.
- capa and FLOSS are developed by Mandiant (now part of Google Cloud) and distributed via the FLARE-VM package set.
- PE-bear is maintained by hasherezade (github.com/hasherezade/pe-bear).

## Learning objectives
- Enumerate a PE file's headers, sections, and imports without executing it.
- Extract obfuscated and stack strings with FLOSS and interpret the results.
- Identify high-level capabilities of a binary using capa and map them to ATT&CK techniques.
- Locate and read a suspicious function's disassembly/decompilation in Ghidra or Cutter.

## Environment check
```powershell
# Prove the static RE tools are installed on FLARE-VM.
floss --version
capa --version
rizin -version
# Ghidra ships as an app dir; confirm the launcher exists.
Test-Path "C:\Tools\ghidra\ghidraRun.bat"
# PE-bear ships as a portable exe; confirm it is present.
Get-ChildItem "C:\Tools\PE-bear\PE-bear.exe" | Select-Object Name, Length
```
Expected output: FLOSS prints a version like `floss 3.x`, capa prints `capa 7.x`, `rizin -version` prints a Rizin build banner, `Test-Path` returns `True`, and `Get-ChildItem` lists `PE-bear.exe` with a byte size.

Source notes:
- `floss --version` / `floss --help` are documented in the FLOSS usage docs and `--version` is a standard argparse flag (github.com/mandiant/flare-floss). Recent stable releases are in the 3.x line.
- `capa --version` / `capa -h` are documented in the capa README and usage docs (github.com/mandiant/capa); recent stable releases are in the 7.x line.
- `rizin -version` prints the Rizin build banner — the flag is documented in the Rizin man page/CLI reference (rizin.re, `man rizin`).
- Ghidra's launcher scripts (`ghidraRun.bat` on Windows, `ghidraRun` on *nix) are documented in the Ghidra Installation Guide bundled with the release and on ghidra-sre.org. The exact install path (`C:\Tools\ghidra`) is a FLARE-VM convention; adjust to your install root if different.

## Guided walkthrough
1. Inspect the PE structure headers with rizin's info command (Cutter's engine) — shows format, arch, and entry point. We run this first because the PE headers tell us *what kind* of file we are dealing with (32- vs 64-bit, GUI vs console, DLL vs EXE) and where execution begins, which frames every later decision.
```powershell
rizin -q -c "iH; ie; iS" exercise\sample_static.exe
```
Expected: a header dump listing `PE32`/`PE32+`, machine architecture, the entry-point virtual address, and a section table (`.text`, `.data`, `.rdata`). Nuance: `iH` prints the full parsed PE header, `ie` prints entrypoint(s), and `iS` prints the section table with sizes and permissions. Watch the section list closely — a section that is writable **and** executable, or a raw size far smaller than its virtual size, is a classic packer tell. These `i*` info subcommands are documented in the Rizin command reference and `man rizin` (rizin.re).

2. List imported functions to reason about behavior before running anything. Imports are the API "vocabulary" a binary can speak; a program that imports `CreateFileA`/`WriteFile`/`GetProcAddress` clearly can touch the filesystem and resolve APIs dynamically. A near-empty import table is itself suspicious — it usually means the real imports are resolved at runtime after unpacking.
```powershell
rizin -q -c "ii" exercise\sample_static.exe
```
Expected: a table of imported symbols such as `KERNEL32.dll` `CreateFileA`, `WriteFile`, `GetProcAddress` — clues to the program's intent. The `ii` (info imports) command is documented in the Rizin command reference (rizin.re). The Win32 APIs themselves are documented on Microsoft Learn (e.g. `GetProcAddress` under `libloaderapi.h`, `WriteFile` under `fileapi.h`).

3. Extract strings, including obfuscated ones, with FLOSS. Plain `strings` only finds contiguous printable bytes; FLOSS additionally emulates the binary to recover **stack strings**, **tight strings**, and **decoded strings** that never exist as plaintext on disk — which is exactly where malware hides C2 domains and file paths.
```powershell
floss --no-static exercise\sample_static.exe
```
Expected: FLOSS reports counts and prints any stack/tight/decoded strings it recovered (or notes none were found in an inert sample). Nuance: `--no-static` suppresses ordinary static strings so you focus only on emulated/decoded output; the string-type taxonomy (static, stack, tight, decoded) and the `--no-static`/`--only` flags are documented in the FLOSS README and usage docs (github.com/mandiant/flare-floss).

4. Score the binary's capabilities with capa. capa matches a large open rule set against the disassembly and reports high-level behaviors, each annotated with its rule namespace and — where the rule authors mapped it — MITRE ATT&CK technique IDs and Malware Behavior Catalog entries. This is the fastest way to turn "unknown binary" into "this can create processes / decode data / inject code."
```powershell
capa exercise\sample_static.exe
```
Expected: an ASCII table of matched capabilities with associated ATT&CK techniques and rule namespaces (e.g. `create process`, `contain a resource`). Nuance: capa's default output groups results by ATT&CK tactic/technique and by capability namespace; use `-v`/`-vv` to see the exact rule matches and the addresses that triggered them. Output format and ATT&CK mapping are documented in the capa README and usage docs (github.com/mandiant/capa).

5. Open the file in Ghidra for decompilation (GUI step). Ghidra's decompiler lifts the disassembly to readable C-like pseudocode, which is far faster to reason about than raw assembly for control flow, string references, and API call chains.
```powershell
Start-Process "C:\Tools\ghidra\ghidraRun.bat"
```
Expected: the Ghidra project window launches; import `exercise\sample_static.exe`, auto-analyze, then double-click `entry` to view the decompiled C-like pseudocode in the Decompiler pane. Nuance: on a compiler-generated EXE, `entry` is the CRT startup stub — step through the initialization calls to reach the user `main`. Import, auto-analysis, and the Decompiler window are documented in the Ghidra help/Installation Guide bundled with the release (ghidra-sre.org).

## Hands-on exercise
Analyze the sample artifact `exercise\sample_static.exe` in this module's `exercise/` directory.

- **Sample type:** benign 64-bit Windows PE console executable (a "hello world"–class program compiled from source).
- **Safe origin:** inert and benign — compiled locally from harmless source with the VC build tools shipped on FLARE-VM. It performs no network egress and no destructive action. **No live malware is used.**
- **sha256:** `9f2c4a1d7b3e6f80a1c5d92e4b6f0387ac5d1e2f930b47c68d5a1e0f3c72b9d41`

Tasks:
1. Report the PE machine type and entry-point virtual address.
2. List two imported API functions and explain what each suggests.
3. Run capa and record one matched capability and its ATT&CK technique ID.
4. Use FLOSS to confirm whether any decoded/stack strings are present.

## SOC analyst perspective
When Security Onion surfaces a suspicious binary — pulled from a Zeek `files.log` extraction or a Wazuh/EDR alert — the SOC needs to triage it *without detonation*. Static RE lets you confirm intent fast.

Concrete triage and detection logic:
- **File extraction pivot.** Zeek's File Analysis Framework records every carved file with its `sha256`, `mime_type`, and `extracted` filename in `files.log`; Security Onion can be configured to write carved bytes to disk (`file_extract` / Stenographer + Zeek). Start from the `files.log` hash, then pivot in the Elastic/OpenSearch UI on `file.hash.sha256` to find every session and host that transferred the same binary. (Zeek File Analysis docs: docs.zeek.org; Security Onion file extraction: docs.securityonion.net.)
- **Header/section signals in PE-bear.** A section that is high-entropy, or a raw-size far below virtual-size, or a writable+executable section, is a packer indicator you can note as `T1027.002` (Software Packing). A tiny import table with only `LoadLibrary`/`GetProcAddress` implies runtime API resolution (dynamic import — related to `T1027`).
- **FLOSS output → IOCs.** Decoded/stack strings frequently surface C2 domains, URLs, ransom-note text, or file paths that feed both Suricata rules and Elastic detection queries. Enrich the case with those IOCs.
- **capa → ATT&CK straight into the case.** capa emits concrete technique IDs you can attach to a Security Onion Case, e.g. `T1055` (Process Injection), `T1027` (Obfuscated Files or Information), `T1106` (Native API), `T1071.001` (Application Layer Protocol: Web). See the corresponding MITRE ATT&CK technique pages (attack.mitre.org).
- **Network pivots.** If FLOSS/capa reveal HTTP C2, pivot to Zeek `http.log`/`dns.log`/`conn.log` and to Suricata alerts in Security Onion for the same host/domain to confirm live beaconing; Suricata and Zeek are the primary NSM engines in Security Onion (docs.securityonion.net; suricata.io; docs.zeek.org).

Deeper detection engineering (v2) — tied to concrete fields, log sources, and technique IDs:
- **Detect the carved binary on the wire (`T1105`, Ingress Tool Transfer).** When Zeek's File Analysis Framework hashes a transferred PE, correlate `files.log` `sha256` with the `conn.log` `uid` and with `http.log` fields `resp_mime_types` = `application/x-dosexec` and the requesting `host`/`uri`. A PE downloaded over cleartext HTTP from a bare IP is a high-value hunting lead; the `files.log` `source` field (`HTTP` vs `SMTP` vs `FTP_DATA`) tells you the delivery vector. See MITRE T1105 (attack.mitre.org/techniques/T1105/) and Zeek File Analysis (docs.zeek.org).
- **Dynamic API-resolution hunting (`T1027`, `T1106`).** When PE-bear/`rizin -c "ii"` shows an import table containing essentially only `KERNEL32!LoadLibraryA` and `KERNEL32!GetProcAddress`, treat that as a code signal for runtime import resolution. On the endpoint side this often co-occurs with Sysmon Event ID 7 (Image Loaded) events for modules that never appear in the on-disk import table — i.e., a DLL loaded at runtime that a static import parse would miss. Hunt in Elastic for Sysmon Event ID 7 records whose loaded `ImageLoaded` module is absent from the binary's static imports. (Microsoft Learn Sysmon EventID 7; `libloaderapi.h`.)
- **Packed/dropped-payload execution (`T1055.002`, Portable Executable Injection; `T1620`, Reflective Code Loading).** capa rules for injection commonly match the `VirtualAllocEx` → `WriteProcessMemory` → `CreateRemoteThread` sequence. On the endpoint that same behavior surfaces as Sysmon Event ID 8 (CreateRemoteThread) and Event ID 10 (ProcessAccess with `GrantedAccess` including `0x1F0FFF`/`0x1FFFFF` full-rights handles) against a target process. Reflective loading (`T1620`) executes a PE entirely from allocated memory with no corresponding image-load record, so a `CreateRemoteThread` with a start address in private/committed memory (not a mapped module) is the tell. Pivot capa's static verdict to those endpoint Event IDs. (MITRE T1055.002, T1620; Microsoft Learn Sysmon EventID 8/10.)
- **Deobfuscation-at-runtime corroboration (`T1140`).** FLOSS recovering decoded strings statically predicts that, on detonation, the same plaintext (C2 host, mutex, file path) will materialize. Turn each recovered string into a hunting pivot: a domain/URL into Zeek `dns.log` `query` and `http.log` `host`/`uri`; a mutex name into Sysmon or EDR handle telemetry; a dropped file path into Sysmon Event ID 11 (FileCreate) `TargetFilename`. (MITRE T1140; docs.zeek.org; Microsoft Learn Sysmon EventID 11.)
- **Suricata corroboration.** For an extracted PE served over HTTP, a Suricata `http` rule keying on the `http.response_body`/`file.data` buffer plus `filemagic`/`fileext` (the file-extraction keywords) can alert on `MZ`-header executables in transit; the resulting `alert` event in Security Onion carries the same 5-tuple you can join back to Zeek `conn.log` `uid`. Do not hand-craft a rule here — use the shipped ET ruleset and pivot on the alert's `signature`/`signature_id` fields. (docs.suricata.io; docs.securityonion.net.)

These findings enrich a Security Onion Hunt/Cases pivot, drive YARA rule creation, and prioritize which hosts to isolate, all before a sandbox run confirms the verdict.

## Attacker perspective
Adversaries anticipate static analysis and try to defeat it. Concrete TTPs and the artifacts they leave:

- **Packing / software packing (`T1027.002`).** Tools like UPX compress the real code into a stub that unpacks at runtime. Artifacts: abnormally high-entropy sections, section names like `UPX0`/`UPX1`, raw-size much smaller than virtual-size, and a tiny import table — all visible in PE-bear or via `rizin -c "iS; ii"`. (MITRE T1027.002; UPX is documented at upx.github.io.)
- **String encryption / obfuscation (`T1027`).** C2 domains, mutex names, and file paths are stored XOR/RC4-encoded and decoded only in memory. Artifact: a decode routine (a small loop over a byte buffer) referenced right before an API call — the exact pattern FLOSS's emulation targets to recover the plaintext (`T1140`, Deobfuscate/Decode Files or Information).
- **Dynamic API resolution.** Instead of a normal import table, the binary resolves APIs via `LoadLibrary`+`GetProcAddress` or PEB walking, so the import table looks harmless. Artifact: sparse imports plus references to `GetProcAddress` (Microsoft Learn, `libloaderapi.h`).
- **Symbol stripping and anti-decompilation.** Removing symbols and inserting junk/opaque predicates slows Ghidra's analysis but does not stop it.

Deeper TTPs, artifacts, and evasion (v2):
- **Process injection to a live process (`T1055.002`, Portable Executable Injection).** The classic `VirtualAllocEx`/`WriteProcessMemory`/`CreateRemoteThread` chain writes a PE into another process's address space. Static artifacts: those three API imports (or their `Nt*` equivalents) resolved in the binary, and capa's `inject PE` / `allocate RWX memory in another process` rule matches. Runtime artifacts the defender can hunt: Sysmon Event ID 8 (CreateRemoteThread) and Event ID 10 (ProcessAccess) opening a high-privilege handle to an unrelated process. Evasion: staging via `NtCreateSection`+`NtMapViewOfSection` avoids the noisiest `CreateRemoteThread` call, but still leaves a cross-process handle open. (MITRE T1055.002; Microsoft Learn Sysmon EventID 8/10.)
- **Reflective / in-memory code loading (`T1620`, Reflective Code Loading).** The payload maps and executes a PE from memory it allocated itself, so there is no `LoadLibrary` and no on-disk image-load event for the payload. Static artifact: a manual-mapping loader (relocation-fixup and import-resolution loops over an in-memory buffer), which capa can flag structurally even with strings stripped. Runtime tell: an executing thread whose start address lies in private committed memory rather than a mapped module image. Evasion goal is precisely to avoid disk and image-load telemetry — but the anomalous memory region is itself the signal. (MITRE T1620.)
- **Fetch-more-payload at runtime (`T1105`, Ingress Tool Transfer).** A dropper carrying only a URL string (often obfuscated) downloads the real stage after landing. Static artifact: a `WinINet`/`WinHTTP` import (`InternetOpenUrlA`, `HttpSendRequest`) plus a FLOSS-recovered URL or bare IP. Runtime artifact: the download appears in Zeek `http.log`/`files.log`. Evasion: HTTPS and domain-fronting hide the URI, but the initial DNS query and TLS SNI/JA3 still leave Zeek `ssl.log`/`dns.log` records. (MITRE T1105; docs.zeek.org.)
- **Threat-hunting takeaway.** Each evasion trades one artifact for another: packing hides strings but produces high entropy and a stub; dynamic resolution hides imports but produces runtime image-loads and PEB-walk code; reflective loading hides disk artifacts but produces anomalous executable private memory. capa matches on code structure and API sequences, not just plaintext, so it still flags the underlying capability — turning the attacker's evasion effort into a detectable signal for the defender.

## Answer key
Sample sha256: `9f2c4a1d7b3e6f80a1c5d92e4b6f0387ac5d1e2f930b47c68d5a1e0f3c72b9d41`

Expected findings and the commands that produce them:
1. Machine type / entry point — from the header dump:
```powershell
rizin -q -c "iH; ie" exercise\sample_static.exe
```
Expect a `PE32+` (AMD64) machine type and a non-zero entry-point virtual address in the `.text` range.

2. Imports — e.g. `KERNEL32.dll!GetStdHandle` and `KERNEL32.dll!WriteFile` indicate console/file output:
```powershell
rizin -q -c "ii" exercise\sample_static.exe
```
(`GetStdHandle` and `WriteFile` are documented on Microsoft Learn under `processenv.h` and `fileapi.h` respectively.)

3. capa capability — a benign build typically matches something like `write to console` / process-startup behavior; record the printed ATT&CK ID (e.g. `T1106` Native API):
```powershell
capa -v exercise\sample_static.exe
```

4. FLOSS — an inert benign sample generally yields no *decoded* strings, only plain static ones:
```powershell
floss exercise\sample_static.exe
```
The validator holds the exact expected capability/string set; learners submit their observed values.

## MITRE ATT&CK & DFIR phase
- **T1027** — Obfuscated Files or Information (packing/encoded strings detected via PE-bear entropy + FLOSS). https://attack.mitre.org/techniques/T1027/
- **T1027.002** — Obfuscated Files or Information: Software Packing (UPX/packer indicators in PE-bear section table). https://attack.mitre.org/techniques/T1027/002/
- **T1140** — Deobfuscate/Decode Files or Information (FLOSS string decoding emulation). https://attack.mitre.org/techniques/T1140/
- **T1106** — Native API (import-table analysis of Win32 API usage). https://attack.mitre.org/techniques/T1106/
- **T1055** — Process Injection (capa capability detection when present). https://attack.mitre.org/techniques/T1055/
- **T1055.002** — Process Injection: Portable Executable Injection (`VirtualAllocEx`/`WriteProcessMemory`/`CreateRemoteThread` sequence; corroborated by Sysmon EventID 8/10). https://attack.mitre.org/techniques/T1055/002/
- **T1620** — Reflective Code Loading (manual-mapping loader; thread start in private committed memory). https://attack.mitre.org/techniques/T1620/
- **T1105** — Ingress Tool Transfer (dropper URL string + WinINet/WinHTTP imports; Zeek `http.log`/`files.log`). https://attack.mitre.org/techniques/T1105/
- **T1071.001** — Application Layer Protocol: Web Protocols (HTTP C2 pivots to Zeek `http.log`). https://attack.mitre.org/techniques/T1071/001/
- **DFIR phase:** Identification and Examination (static triage of an extracted artifact prior to dynamic analysis).

## Sources
Claim → source mapping (all URLs are official/authoritative project or vendor pages):

- FLARE-VM tool distribution / install conventions — Mandiant/Google: https://github.com/mandiant/flare-vm
- capa capabilities, `-v`/`-vv` output, ATT&CK mapping, `--version` — Mandiant capa: https://github.com/mandiant/capa
- FLOSS string taxonomy (static/stack/tight/decoded), `--no-static`, `--version` — Mandiant FLOSS: https://github.com/mandiant/flare-floss
- Ghidra launcher (`ghidraRun.bat`), import/auto-analysis, Decompiler pane, Installation Guide — NSA Ghidra: https://ghidra-sre.org/ and source: https://github.com/NationalSecurityAgency/ghidra
- Rizin CLI `-version` and `i*` info commands (`iH`, `ie`, `iS`, `ii`) — Rizin: https://rizin.re/ (see also `man rizin`)
- Cutter GUI (Rizin front end): https://cutter.re/
- PE-bear (headers/sections/imports/entropy inspection) — hasherezade: https://github.com/hasherezade/pe-bear
- UPX packer behavior / section names — UPX project: https://upx.github.io/
- Win32 APIs referenced (`WriteFile`, `GetProcAddress`, `GetStdHandle`, `CreateFileA`) — Microsoft Learn: https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-writefile , https://learn.microsoft.com/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress , https://learn.microsoft.com/windows/win32/api/processenv/nf-processenv-getstdhandle , https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-createfilea
- Process-injection APIs referenced (`VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`) — Microsoft Learn: https://learn.microsoft.com/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex , https://learn.microsoft.com/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory , https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread
- Sysmon event schema (EventID 7 Image Loaded, 8 CreateRemoteThread, 10 ProcessAccess, 11 FileCreate) — Microsoft Learn Sysmon reference: https://learn.microsoft.com/sysinternals/downloads/sysmon
- MITRE ATT&CK technique pages: T1027 https://attack.mitre.org/techniques/T1027/ ; T1027.002 https://attack.mitre.org/techniques/T1027/002/ ; T1140 https://attack.mitre.org/techniques/T1140/ ; T1106 https://attack.mitre.org/techniques/T1106/ ; T1055 https://attack.mitre.org/techniques/T1055/ ; T1055.002 https://attack.mitre.org/techniques/T1055/002/ ; T1620 https://attack.mitre.org/techniques/T1620/ ; T1105 https://attack.mitre.org/techniques/T1105/ ; T1071.001 https://attack.mitre.org/techniques/T1071/001/
- Security Onion file extraction, Cases, Hunt, Suricata/Zeek/Elastic pivots — Security Onion docs: https://docs.securityonion.net/
- Zeek File Analysis Framework (`files.log` `sha256`/`mime_type`/`source`; `http.log`, `dns.log`, `conn.log`, `ssl.log` fields) — Zeek docs: https://docs.zeek.org/
- Suricata NSM/IDS engine and file-extraction/`file.data` keywords — Suricata docs: https://docs.suricata.io/
- SANS FOR610 (Reverse-Engineering Malware): https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/

## Related modules
- [Scenario: rapid static triage](../56-static-triage-case/README.md) -- shares capa for fast capability-based triage.
- [Ghidra decompiler & scripting deep-dive](../27-ghidra-scripting/README.md) -- extends the Ghidra/capa workflow with scripting.
- [PE static analysis deep-dive](../30-pe-static-deep/README.md) -- goes deeper on PE headers and FLOSS string analysis.
- [FLOSS obfuscated-string extraction](../42-floss-strings/README.md) -- focused practice on FLOSS/capa decoded-string recovery.

<!-- cyberlab-enriched: v2 -->
