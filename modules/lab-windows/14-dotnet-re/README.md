# 14 * .NET reverse engineering -- LAB-WINDOWS

## Overview (plain language)
Many Windows programs today are written in the .NET framework (languages like C# and VB.NET). Instead of compiling straight to raw machine code, these programs compile to an intermediate language (IL) that keeps a lot of the original structure — method names, class names, and readable logic. That makes .NET malware much easier to reverse engineer than native code, because the right tools can turn the compiled file back into something very close to the original source code. This module covers three free tools that decompile .NET binaries so you can read them like source, step through them in a debugger, and strip away obfuscation that malware authors add to hide their intent. In short: you take a suspicious `.exe` or `.dll`, and these tools show you what it actually does in near-source form.

The IL is defined by ECMA-335 (Common Language Infrastructure) and executed by the Common Language Runtime (CLR); managed PE files carry a CLR header and import `mscoree.dll` (see Microsoft Learn, "Overview of .NET Framework": https://learn.microsoft.com/en-us/dotnet/framework/get-started/overview and "Managed Execution Process": https://learn.microsoft.com/en-us/dotnet/standard/managed-execution-process).

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| dnSpyEx | Preinstalled via FLARE-VM (`choco install dnspyex`) | Decompile, edit, and debug .NET assemblies interactively (fork of the original dnSpy). |
| ILSpy | Preinstalled via FLARE-VM (`choco install ilspy`) | Open-source .NET decompiler/assembly browser with CLI (`ilspycmd`) support. |
| de4dot | Preinstalled via FLARE-VM (de4dot-cex) | Deobfuscator/unpacker that cleans obfuscated .NET assemblies back to readable form. |

Sourcing notes for this table:
- dnSpyEx is the actively maintained fork of dnSpy and supports assembly editing plus a debugger for IL and decompiled C# — see the project README: https://github.com/dnSpyEx/dnSpy
- ILSpy ships a cross-platform command-line front end named `ilspycmd`, documented in the repo: https://github.com/icsharpcode/ILSpy and on NuGet: https://www.nuget.org/packages/ilspycmd
- de4dot is a .NET deobfuscator and unpacker; the widely distributed maintained build is the "de4dot-cex" fork. Original project: https://github.com/de4dot/de4dot ; cex fork: https://github.com/ViRb3/de4dot-cex . FLARE-VM installs it via the de4dot package: https://github.com/mandiant/VM-Packages

## Learning objectives
- Confirm a target file is a managed (.NET) assembly and identify its compiler/obfuscator.
- Decompile a .NET binary to near-source C# using dnSpyEx and ILSpy (`ilspycmd`).
- Run de4dot to remove common obfuscation and produce a cleaned assembly.
- Locate suspicious behavior (network, process, crypto) in decompiled code and record artifacts.

## Environment check
```powershell
# Prove the three .NET RE tools are present on FLARE-VM.
# dnSpyEx is a GUI app - confirm the executable exists:
Get-Command dnSpy.exe -ErrorAction SilentlyContinue | Select-Object Source
Test-Path "C:\Tools\dnSpyEx\dnSpy.exe"

# ILSpy ships a command-line front end:
ilspycmd --version

# de4dot (de4dot-cex) prints its banner when run with no target:
de4dot.exe
```
Expected output: `Test-Path` returns `True` (or `Get-Command` resolves a path), `ilspycmd --version` prints a version string, and `de4dot.exe` prints its `de4dot v3.x ... Copyright` banner and usage text.

Notes on expected values (verify against your own install; do not assume a fixed version):
- `ilspycmd --version` is a documented flag of the ILSpy CLI (see `ilspycmd --help` and the repo docs: https://github.com/icsharpcode/ILSpy/blob/master/README.md). The exact version reported depends on the installed NuGet/Chocolatey package.
- de4dot's banner and its no-argument usage output are described in the project README: https://github.com/de4dot/de4dot#readme . The de4dot-cex fork prints the same banner/usage.
- FLARE-VM install paths are package-defined and can vary between hosts; treat `C:\Tools\...` as the FLARE-VM default and rely on `Get-Command`/`Test-Path` to resolve the real location. See VM-Packages: https://github.com/mandiant/VM-Packages

## Guided walkthrough
1. Verify the sample is a managed assembly before decompiling — a native PE will not decompile. This matters because feeding a native (unmanaged) PE to a .NET decompiler yields nothing useful; managed assemblies carry a CLR header and metadata tables (`#Strings`, `#Blob`, `#~`) that the decompiler reads.
```powershell
# ILSpy's CLI can emit disassembled IL with --il; a managed file shows an
# .assembly directive and references to its target framework attribute.
ilspycmd --il "exercise\sample_dotnet.exe" | Select-String -Pattern "TargetFramework|.assembly" | Select-Object -First 5
```
Expected: lines referencing `.assembly` and (for modern .NET SDK builds) a `TargetFrameworkAttribute`, confirming a .NET assembly. Note: the `TargetFrameworkAttribute` is emitted by the SDK build and is present in most real-world assemblies but is not guaranteed for every legacy binary; the presence of the `.assembly` directive in IL is the reliable managed-code indicator. IL disassembly semantics follow ECMA-335 (https://ecma-international.org/publications-and-standards/standards/ecma-335/) and the ILSpy CLI options (`ilspycmd --help`: https://github.com/icsharpcode/ILSpy).

2. Decompile the whole assembly to C# source files with ILSpy's CLI. The `-p` flag emits a reconstructable Visual Studio project structure (multiple `.cs` files plus a `.csproj`), which is easier to read and grep than a single blob; `-o` sets the output directory. See `ilspycmd --help` / repo docs: https://github.com/icsharpcode/ILSpy
```powershell
New-Item -ItemType Directory -Force -Path "exercise\decompiled" | Out-Null
ilspycmd -p -o "exercise\decompiled" "exercise\sample_dotnet.exe"
Get-ChildItem -Recurse "exercise\decompiled" -Filter *.cs | Select-Object Name
```
Expected: a project folder populated with `.cs` files (e.g. `Program.cs`) you can open and read. Decompiled names will be readable only if the assembly is not obfuscated; obfuscated assemblies show mangled/renamed identifiers, which is your cue to run step 4.

3. Search decompiled source for suspicious API usage. Each pattern maps to a behavior class: `WebClient`/`DownloadString` = network fetch/staging, `Process.Start` = child-process execution, `FromBase64String` = encoded-payload decoding. These map to MITRE ATT&CK T1105 (Ingress Tool Transfer), T1059 (Command and Scripting Interpreter), and T1140 (Deobfuscate/Decode Files or Information) respectively.
```powershell
Select-String -Path "exercise\decompiled\*.cs" -Pattern "WebClient|DownloadString|Process.Start|FromBase64String"
```
Expected: matches (or none) showing which risky APIs the sample references. Absence of matches does not prove innocence — obfuscated code may build API names dynamically via reflection, another reason to deobfuscate first.

4. If the code looks garbled (obfuscated), run de4dot to clean it, then re-decompile. de4dot detects the obfuscator, reverses symbol renaming/string encryption/control-flow tricks where it has a matching handler, and writes a cleaned assembly. The `-f` flag names the input file and `-o` the output; see the de4dot README usage: https://github.com/de4dot/de4dot#readme
```powershell
de4dot.exe -f "exercise\sample_dotnet.exe" -o "exercise\sample_dotnet-cleaned.exe"
```
Expected: de4dot prints a `Detected <obfuscator or Unknown>` line, then `Cleaning ...` and `Saving ...`, producing `sample_dotnet-cleaned.exe`. When the obfuscator is unknown or the file is unobfuscated, de4dot still writes an output file but performs only generic cleanup.

5. Open the (cleaned) assembly in dnSpyEx for interactive review/debugging. dnSpyEx renders IL and decompiled C# side by side and can attach a managed debugger so you can set breakpoints and observe decrypted strings/values at runtime — useful when de4dot cannot statically resolve encrypted strings. See dnSpyEx features: https://github.com/dnSpyEx/dnSpy
```powershell
Start-Process "C:\Tools\dnSpyEx\dnSpy.exe" -ArgumentList "exercise\sample_dotnet-cleaned.exe"
```
Expected: dnSpyEx GUI opens with the assembly tree; you can set breakpoints and step through IL/C#. Only debug/execute malware in an isolated lab — this module's sample is inert (see Hands-on exercise), but the workflow itself runs code.

## Hands-on exercise
Sample artifact: `exercise/sample_dotnet.exe`.
- **Type:** a small benign 64-bit .NET (C#) console executable that prints a greeting and reads an embedded Base64 string — it performs **no network, file-write, or process-spawn activity**.
- **Safe origin:** compiled locally on the FLARE-VM from an inert "Hello, analyst" C# source stub. It is completely benign/inert with no egress; it is **not** live malware.
- **sha256:** `c202132094ab6252e24cea84eac4579de6c57f2338ac58db7eafc526a0e5e84b`

Tasks:
1. Confirm it is a managed assembly.
2. Decompile it with `ilspycmd` and identify the method that decodes the embedded Base64 string.
3. Run de4dot against it and note whether an obfuscator was detected.
4. In dnSpyEx, locate the decoded plaintext string.

## SOC analyst perspective
Defenders reverse .NET malware constantly because commodity loaders, stealers (e.g. AgentTesla, Formbook loaders), and RATs are frequently written in C#. When Security Onion surfaces an alert — a Suricata rule firing on a .NET-generated C2 beacon, or a Zeek `files.log` extraction of a suspicious `.exe` — an analyst pulls that extracted binary and decompiles it with ILSpy/dnSpyEx to read the actual logic: hardcoded C2 URLs, decryption keys, mutex names, and scheduled-task persistence. de4dot removes ConfuserEx/obfuscation so hunting queries and YARA signatures target real strings rather than junk.

Concrete detection logic and Security Onion pivots:
- **Zeek `files.log` → extracted binary:** Zeek's File Analysis Framework can carve transferred executables and record MIME type and a SHA256 in `files.log`; pivot on `files.log` (fields `mime_type`, `sha256`, `fuid`) and correlate to the `conn.log` `uid` to find the source/destination of the transfer. See Zeek File Analysis docs: https://docs.zeek.org/en/master/frameworks/file-analysis.html and Security Onion Zeek logs: https://docs.securityonion.net/en/2.4/zeek.html
- **Suricata alerts on C2:** in Security Onion, Suricata alerts land in the Alerts interface and are queryable in Elastic; pivot from an alert to the full PCAP for the flow (Security Onion supports full packet capture retrieval). See Suricata in Security Onion: https://docs.securityonion.net/en/2.4/suricata.html and Suricata docs: https://docs.suricata.io/en/latest/
- **Elastic / Kibana hunting:** enrich decompiled IOCs (domains, URLs, hashes) back into Elastic queries to find prior contact across stored network and endpoint logs; Security Onion documents this hunt workflow: https://docs.securityonion.net/en/2.4/hunt.html
- **Endpoint corroboration:** if a Windows agent is present, .NET assembly loads and process creation can be observed via Sysmon Event ID 1 (Process Create) and Event ID 7 (Image Loaded, e.g. `clr.dll`/`mscoree.dll`) — Sysmon schema: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon

Findings map to MITRE ATT&CK **T1027** (Obfuscated Files or Information, https://attack.mitre.org/techniques/T1027/), **T1059.003** (Windows Command Shell, https://attack.mitre.org/techniques/T1059/003/), **T1105** (Ingress Tool Transfer, https://attack.mitre.org/techniques/T1105/), **T1140** (Deobfuscate/Decode Files or Information, https://attack.mitre.org/techniques/T1140/), and **T1071.001** (Web Protocols C2, https://attack.mitre.org/techniques/T1071/001/), and feed IOCs (domains, hashes) back into Security Onion for retroactive hunting across PCAP and endpoint logs.

## Attacker perspective
Attackers favor .NET because it enables fast development, in-memory `Assembly.Load` execution, and easy trojanizing of legitimate managed apps. `Assembly.Load`/`Assembly.Load(byte[])` reflective loading is a documented technique for running managed payloads without touching disk (Microsoft Learn: https://learn.microsoft.com/en-us/dotnet/api/system.reflection.assembly.load), corresponding to MITRE ATT&CK **T1620** (Reflective Code Loading, https://attack.mitre.org/techniques/T1620/).

To slow analysis they apply obfuscators (ConfuserEx, .NET Reactor, SmartAssembly) that rename symbols, encrypt strings, and add control-flow flattening — precisely the classes of protection de4dot is designed to reverse (see de4dot's list of supported/detected obfuscators: https://github.com/de4dot/de4dot#readme). This maps to **T1027** (Obfuscated Files or Information, https://attack.mitre.org/techniques/T1027/); string encryption and packing are captured by sub-technique **T1027.002** (Software Packing, https://attack.mitre.org/techniques/T1027/002/).

Offensively, the same decompilers here let a red-teamer study a target's proprietary .NET software for vulnerabilities or patch/crack licensing checks in dnSpyEx (which supports editing and saving modified assemblies), then recompile.

The artifacts left behind for defenders are rich and concrete:
- Managed PE headers with a CLR runtime import (`mscoree.dll`) and a populated CLR/COM descriptor data directory — how tools identify managed code (PE format reference: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format).
- An embedded assembly manifest and metadata `#Strings`/`#Blob` heaps (ECMA-335: https://ecma-international.org/publications-and-standards/standards/ecma-335/).
- Obfuscator marker attributes (e.g. ConfuserEx typically injects module/attribute markers) that de4dot and analysts use for fingerprinting (de4dot README: https://github.com/de4dot/de4dot#readme).
- After execution: .NET assembly-load and JIT-compiled modules visible in memory, and image-load/process-create telemetry (Sysmon Event IDs 7 and 1: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon).

Evasion: reflective in-memory loading avoids on-disk extraction, dynamic API resolution defeats simple string greps, and layered obfuscation (control-flow flattening plus per-string encryption) can leave de4dot unable to statically decrypt — which is exactly why the dnSpyEx debugger (step 5) is used to observe decrypted values at runtime in an isolated lab.

## Answer key
Sample sha256: `c202132094ab6252e24cea84eac4579de6c57f2338ac58db7eafc526a0e5e84b`

1. Managed-assembly confirmation:
```powershell
ilspycmd --il "exercise\sample_dotnet.exe" | Select-String -Pattern ".assembly"
```
Expected: `.assembly` directive present ⇒ it is a .NET assembly.

2. Decompile and find the decoder:
```powershell
ilspycmd -o "exercise\decompiled" "exercise\sample_dotnet.exe"
Select-String -Path "exercise\decompiled\*.cs" -Pattern "FromBase64String"
```
Expected: a match inside a decode method (e.g. `Convert.FromBase64String(...)`), the method that decodes the embedded string. `Convert.FromBase64String` is documented on Microsoft Learn: https://learn.microsoft.com/en-us/dotnet/api/system.convert.frombase64string

3. Deobfuscation check:
```powershell
de4dot.exe -f "exercise\sample_dotnet.exe" -o "exercise\sample_dotnet-cleaned.exe"
```
Expected: de4dot reports `Detected Unknown obfuscator` (this benign sample is unobfuscated) and still writes `sample_dotnet-cleaned.exe`. de4dot usage/behavior: https://github.com/de4dot/de4dot#readme

4. In dnSpyEx, opening the assembly and viewing the string decode method reveals the decoded plaintext greeting (the inert "Hello, analyst" payload) — confirming the sample performs no malicious action.

## MITRE ATT&CK & DFIR phase
- **T1027** — Obfuscated Files or Information (de4dot deobfuscation): https://attack.mitre.org/techniques/T1027/
- **T1027.002** — Software Packing / string encryption commonly seen in .NET loaders: https://attack.mitre.org/techniques/T1027/002/
- **T1059.003** — Command and Scripting Interpreter: Windows Command Shell (for spawned commands found in code): https://attack.mitre.org/techniques/T1059/003/
- **T1071.001** — Application Layer Protocol: Web Protocols (hardcoded C2 URLs recovered from source): https://attack.mitre.org/techniques/T1071/001/
- **T1105** — Ingress Tool Transfer (`WebClient`/`DownloadString` staging): https://attack.mitre.org/techniques/T1105/
- **T1140** — Deobfuscate/Decode Files or Information (`FromBase64String` decoding): https://attack.mitre.org/techniques/T1140/
- **T1620** — Reflective Code Loading (`Assembly.Load(byte[])`): https://attack.mitre.org/techniques/T1620/
- **DFIR phase:** Examination / Analysis (static reverse engineering of an extracted artifact), feeding Identification of IOCs.

> Note on prior text: the earlier "T1027.009" reference was corrected — T1027.009 is *Embedded Payloads* on MITRE ATT&CK. The packing/string-encryption behavior described here is captured by **T1027.002 (Software Packing)**; embedded-payload behavior, where present, would be **T1027.009** (https://attack.mitre.org/techniques/T1027/009/).

## Sources
Claim → source mapping (all URLs are official/authoritative):

- .NET IL / CLR / managed-execution model, `mscoree.dll` import — Microsoft Learn: https://learn.microsoft.com/en-us/dotnet/standard/managed-execution-process and https://learn.microsoft.com/en-us/dotnet/framework/get-started/overview ; ECMA-335 CLI (IL, metadata heaps): https://ecma-international.org/publications-and-standards/standards/ecma-335/
- PE header / CLR data directory used to identify managed PEs — Microsoft Learn PE format: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
- FLARE-VM tool distribution and package definitions (Mandiant/Google) — https://github.com/mandiant/flare-vm and https://github.com/mandiant/VM-Packages
- dnSpyEx (maintained fork; editing + debugger, opening assemblies) — https://github.com/dnSpyEx/dnSpy
- ILSpy / `ilspycmd` (`--il`, `-p`, `-o`, `--version` flags) — https://github.com/icsharpcode/ILSpy ; NuGet package: https://www.nuget.org/packages/ilspycmd
- de4dot behavior, `-f`/`-o` usage, detected-obfuscator output — https://github.com/de4dot/de4dot ; de4dot-cex fork: https://github.com/ViRb3/de4dot-cex
- `Convert.FromBase64String` API — Microsoft Learn: https://learn.microsoft.com/en-us/dotnet/api/system.convert.frombase64string
- `Assembly.Load` reflective loading — Microsoft Learn: https://learn.microsoft.com/en-us/dotnet/api/system.reflection.assembly.load
- Sysmon Event IDs (Process Create 1, Image Loaded 7) — Microsoft Learn: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- Zeek File Analysis Framework (`files.log`, `mime_type`, `sha256`) — https://docs.zeek.org/en/master/frameworks/file-analysis.html
- Suricata engine — https://docs.suricata.io/en/latest/
- Security Onion (Zeek, Suricata, Hunt, PCAP) — https://docs.securityonion.net/ , https://docs.securityonion.net/en/2.4/zeek.html , https://docs.securityonion.net/en/2.4/suricata.html , https://docs.securityonion.net/en/2.4/hunt.html
- SANS FOR610 — Reverse-Engineering Malware: https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/
- MITRE ATT&CK techniques cited above: T1027 https://attack.mitre.org/techniques/T1027/ ; T1027.002 https://attack

<!-- cyberlab-enriched: v1 -->
