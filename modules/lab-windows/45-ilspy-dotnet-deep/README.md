# 45 * ILSpy .NET decompilation deep-dive -- LAB-WINDOWS

## Overview (plain language)
Many Windows programs are written in .NET languages like C#. When compiled, they are not turned into raw machine code but into an intermediate form (IL, or "Common Intermediate Language") that still contains a lot of the original structure. Because of this, tools can turn a compiled .NET file back into readable source code that looks almost like what the developer wrote. ILSpy is one such tool: it opens a `.exe` or `.dll`, reads its internal instructions, and shows you human-readable C# so you can understand exactly what the program does. de4dot is a companion tool that cleans up files that malware authors deliberately scrambled (obfuscated) to make reading them harder — it renames gibberish symbols, decrypts hidden strings, and removes junk so ILSpy can show clearer code. Together they let an analyst recover the logic of a .NET sample without ever running it.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| ILSpy | Included in FLARE-VM (`choco install ilspy`) | Open-source .NET assembly browser and C#/IL decompiler |
| de4dot | Included in FLARE-VM (de4dot-cex build) | .NET deobfuscator/unpacker that cleans obfuscated assemblies before decompilation |

ILSpy ships both a WPF GUI and a cross-platform command-line front end, `ilspycmd`, distributed as a .NET global tool (see the ILSpy repo and the [`ilspycmd` README](https://github.com/icsharpcode/ILSpy/blob/master/ILSpy.CommandLine/README.md)). de4dot is the open-source deobfuscator originally by 0xd4d; FLARE-VM installs the maintained "de4dot-cex" fork (see [flare-vm packages](https://github.com/mandiant/VM-Packages)).

## Learning objectives
- Load a .NET assembly into ILSpy and identify its entry point, namespaces, and referenced assemblies.
- Decompile a method to C# and export the entire assembly to a compilable project.
- Recognize obfuscation indicators (renamed symbols, encrypted strings) in a .NET sample.
- Run de4dot to produce a cleaned assembly and compare it against the original in ILSpy.
- Extract embedded resources and hard-coded indicators (URLs, keys) from a managed binary.

## Environment check
```powershell
# Confirm ILSpy command-line decompiler is available (FLARE-VM installs ilspycmd)
ilspycmd --version

# Confirm de4dot is on PATH
de4dot --help | Select-Object -First 5
```
Expected output: `ilspycmd` prints a version string such as `ilspycmd 8.x` (the `--version` flag is documented in the [`ilspycmd` README](https://github.com/icsharpcode/ILSpy/blob/master/ILSpy.CommandLine/README.md)). `de4dot` prints its banner (`de4dot vX.X.X`) followed by usage lines (the CLI banner/usage behavior is documented in the [de4dot README](https://github.com/de4dot/de4dot#readme)). If a command is not found, launch the GUI equivalents from the FLARE-VM Start Menu and confirm they open.

## Guided walkthrough
1. `ilspycmd -l c` — list all C# type members of an assembly so you can survey its structure before decompiling. Listing types first is cheaper than a full decompile and immediately reveals whether the sample is obfuscated (meaningless names) and where the interesting code lives, so you can target specific classes instead of dumping everything. The `-l`/`--list` option accepts an entity type (`c` = classes/types) per the [`ilspycmd` README](https://github.com/icsharpcode/ILSpy/blob/master/ILSpy.CommandLine/README.md).
```powershell
# Inspect metadata and list types in the sample assembly
ilspycmd -l c .\exercise\sample.exe
```
Expected observable output: a list of namespaces and class/type names printed to the console. Nuance: a clean sample shows a small, meaningfully named set (here just `Program`); obfuscated samples show meaningless names (e.g., `Class1`, `\u0002`, `a.b.c`) or unprintable Unicode identifiers — a direct visual indicator of ATT&CK T1027.

2. Decompile a single assembly to C# on stdout so you can read the actual logic. Running with no output/project flag makes `ilspycmd` decompile the whole assembly to standard output (default behavior per the [`ilspycmd` README](https://github.com/icsharpcode/ILSpy/blob/master/ILSpy.CommandLine/README.md)); this is the fastest way to read a small binary and grep for indicators without writing files to disk.
```powershell
# Emit decompiled C# to the console
ilspycmd .\exercise\sample.exe
```
Expected observable output: readable C# source for the `Main` method and helper classes. Nuance: ILSpy reconstructs C# from IL, so field initializers and string constants (such as the hard-coded `http://203.0.113.10/beacon` marker) survive intact, while compiler-generated constructs (e.g., iterator state machines, async plumbing) may be rendered close to but not byte-identical to the original source.

3. Export the whole assembly to a project folder for deeper review in VS Code. The `-p` (`--project`) switch tells `ilspycmd` to emit a reconstructed MSBuild project rather than a single stream, and `-o` sets the output directory (both documented in the [`ilspycmd` README](https://github.com/icsharpcode/ILSpy/blob/master/ILSpy.CommandLine/README.md)). A project layout is easier to navigate, cross-reference, and (for supported targets) recompile than a single console dump.
```powershell
New-Item -ItemType Directory -Force -Path .\exercise\decompiled | Out-Null
ilspycmd -p -o .\exercise\decompiled .\exercise\sample.exe
```
Expected observable output: a generated `.csproj` plus per-type `.cs` files under `exercise\decompiled\`. Nuance: the target framework recorded in the `.csproj` is read from the assembly's `TargetFrameworkAttribute`, so it should reflect `net48` for this sample.

4. If names/strings look scrambled, clean the assembly with de4dot, then re-open the cleaned output in ILSpy. de4dot detects the obfuscator from metadata fingerprints and reverses its transforms — symbol renaming, string encryption, and control-flow obfuscation — writing a new assembly (behavior and the `-f`/`-o` options are documented in the [de4dot README](https://github.com/de4dot/de4dot#readme)). Cleaning *before* decompiling is what turns unreadable output into analyzable C#.
```powershell
# Produces sample-cleaned.exe next to the input
de4dot -f .\exercise\sample.exe -o .\exercise\sample-cleaned.exe
ilspycmd .\exercise\sample-cleaned.exe | Select-Object -First 40
```
Expected observable output: de4dot reports the detected obfuscator (or "Unknown obfuscator") and writes the cleaned file; the re-decompiled C# is more readable (recovered strings, simplified control flow). Nuance: on a non-obfuscated sample de4dot reports an unknown obfuscator and the output is effectively a re-serialized copy — a useful negative control that tells you the file was never obfuscated.

## Hands-on exercise
Sample artifact: `exercise/sample.exe` — a **benign, inert .NET console application** (managed PE, target `net48`). It only prints a string and contains one hard-coded marker URL `http://203.0.113.10/beacon`; it performs **no network, file, or registry activity** (no-egress, safe to analyze). It is generated locally from source — no live malware is distributed. (`203.0.113.0/24` is the TEST-NET-3 documentation range reserved by [RFC 5737](https://www.rfc-editor.org/rfc/rfc5737), so the marker cannot route to a real host.)

Safe-origin / reproducible generator (run on FLARE-VM, which ships the VC/.NET build tools):
```powershell
# Build the benign sample from inline C# source using the .NET Framework compiler
$src = @'
using System;
class Program {
    static string Marker = "http://203.0.113.10/beacon";
    static void Main() { Console.WriteLine("benign lab sample " + Marker); }
}
'@
Set-Content -Path .\exercise\sample.cs -Value $src -Encoding ASCII
$csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
& $csc /nologo /out:.\exercise\sample.exe .\exercise\sample.cs
Get-FileHash .\exercise\sample.exe -Algorithm SHA256
```
Note: `csc.exe` under `Microsoft.NET\Framework64\v4.0.30319` is the in-box .NET Framework 4.x C# compiler; the `/nologo` and `/out` switches are documented on [Microsoft Learn — C# compiler options](https://learn.microsoft.com/en-us/dotnet/csharp/language-reference/compiler-options/). `Get-FileHash -Algorithm SHA256` is documented on [Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-filehash).

Tasks:
1. List the types in `sample.exe` with ILSpy and record the entry-point class name.
2. Decompile `Main` and extract the hard-coded marker URL.
3. Run de4dot against the sample and note the reported obfuscator status.
4. Export the assembly to a project and confirm the recovered string constant.

## SOC analyst perspective
During incident response a defender often recovers a suspicious `.exe` or `.dll` from an endpoint or from a Security Onion alert (e.g., a Suricata hit on a beacon URL, or a Zeek `files.log` entry flagging a downloaded PE). Because .NET binaries decompile cleanly, ILSpy lets the analyst read the malware's real logic — command-and-control endpoints, persistence routines, and encryption keys — without detonating it, then feed the extracted indicators (the `203.0.113.10` host, mutex names, registry keys) back into Security Onion as pivots and into detection rules.

Concrete detection logic and pivots:
- **Zeek file carving.** Zeek's [`files.log` and File Analysis Framework](https://docs.zeek.org/en/master/logs/files.html) records `mime_type` and (with the hash plugin) `sha256`; pivot on `application/x-dosexec` transfers and correlate the file hash back to the recovered sample. In Security Onion, hunt these in the `file` dataset (see [Security Onion Zeek docs](https://docs.securityonion.net/en/2.4/zeek.html)).
- **Suricata C2 match.** A rule alerting on the beacon host/URI turns the ILSpy-recovered IOC into a network signature; Suricata `http` and `tls` events surface in Security Onion's Alerts/Hunt views (see [Security Onion Suricata docs](https://docs.securityonion.net/en/2.4/suricata.html) and [Suricata rules docs](https://docs.suricata.io/en/latest/rules/index.html)). Example content match on the recovered URI:
  ```
  alert http any any -> any any (msg:"LAB .NET beacon URI"; flow:established,to_server; http.uri; content:"/beacon"; sid:1000045; rev:1;)
  ```
- **Elastic/host telemetry.** Pivot in Security Onion's Kibana/Hunt on the `dns`, `http`, and `connection` datasets for the `203.0.113.10` indicator, and on process-execution events for managed LOLBin launchers (`installutil.exe`, `regsvcs.exe`, `msbuild.exe`).

Mapping obfuscator findings to ATT&CK: recognizing a de4dot-detected packer (ConfuserEx, .NET Reactor) supports **T1027 Obfuscated Files or Information** ([attack.mitre.org/techniques/T1027](https://attack.mitre.org/techniques/T1027/)) and its sub-technique **T1027.002 Software Packing** ([attack.mitre.org/techniques/T1027/002](https://attack.mitre.org/techniques/T1027/002/)); using signed system utilities to run managed payloads maps to **T1218 System Binary Proxy Execution** — e.g. **T1218.004 InstallUtil** ([attack.mitre.org/techniques/T1218/004](https://attack.mitre.org/techniques/T1218/004/)). Distinguishing commodity vs. bespoke obfuscation helps triage. The recovered strings and IOCs become YARA and Suricata content that closes the detection loop across the estate.

## Attacker perspective
Attackers favor .NET for tradecraft because it loads reflectively in memory, integrates with signed LOLBins, and is easy to weaponize.

Concrete TTPs:
- **Signed-binary proxy execution.** Running managed payloads through `InstallUtil`, `regsvcs`/`regasm`, or `msbuild` evades application controls that trust those signed Microsoft binaries — ATT&CK **T1218.004 InstallUtil** ([attack.mitre.org/techniques/T1218/004](https://attack.mitre.org/techniques/T1218/004/)), **T1218.009 Regsvcs/Regasm** ([attack.mitre.org/techniques/T1218/009](https://attack.mitre.org/techniques/T1218/009/)), and **T1127.001 MSBuild** ([attack.mitre.org/techniques/T1127/001](https://attack.mitre.org/techniques/T1127/001/)).
- **Obfuscation and packing.** ConfuserEx / .NET Reactor rename symbols to unprintable characters, encrypt string tables, and add control-flow junk — **T1027** ([attack.mitre.org/techniques/T1027](https://attack.mitre.org/techniques/T1027/)) and **T1027.002 Software Packing** ([attack.mitre.org/techniques/T1027/002](https://attack.mitre.org/techniques/T1027/002/)). These are the exact transforms de4dot is built to reverse; analysts undo them under **T1140 Deobfuscate/Decode Files or Information** ([attack.mitre.org/techniques/T1140](https://attack.mitre.org/techniques/T1140/)).
- **Reflective in-memory loading.** Loading assemblies via `Assembly.Load(byte[])` avoids touching disk — **T1620 Reflective Code Loading** ([attack.mitre.org/techniques/T1620](https://attack.mitre.org/techniques/T1620/)).

Artifacts the technique leaves for a defender: .NET metadata streams and typedef tables, leftover PDB/source paths in the debug directory, `Mvid`/assembly GUIDs, embedded `.resources` blobs, and — after de4dot deobfuscation — plaintext C2 URLs and keys. Evasion note: even encrypted string tables must be decrypted at runtime, so the decryption routine and its key remain recoverable in the IL; and packers change the file hash but not the observable managed behavior, so hash-only detection is brittle. The very portability that helps the attacker (readable IL, embedded config) is what makes ILSpy-driven analysis so effective at exposing them.

## Answer key
- Entry-point class: `Program`, entry method `Main` (from `ilspycmd -l c .\exercise\sample.exe`).
- Recovered constant / IOC: `http://203.0.113.10/beacon` (from decompiling `Main` / the `Marker` field).
- de4dot result on this sample: reports an **Unknown obfuscator** (the sample is not obfuscated) and still writes `sample-cleaned.exe`; the cleaned decompilation is identical, confirming the file is clean.
- Exact producing commands:
```powershell
ilspycmd -l c .\exercise\sample.exe        # lists type: Program
ilspycmd .\exercise\sample.exe | Select-String "203.0.113.10"   # shows the marker URL
de4dot -f .\exercise\sample.exe -o .\exercise\sample-cleaned.exe # cleaning pass
Get-FileHash .\exercise\sample.exe -Algorithm SHA256            # confirm sample identity
```
Sample identity: the SHA256 printed by the generator's `Get-FileHash` is the authoritative digest for the locally built `exercise/sample.exe` (deterministic for identical source/toolchain; record the value your build emits and store it in `exercise/sample.exe.sha256`).

## MITRE ATT&CK & DFIR phase
- **T1027** Obfuscated Files or Information — detecting/analysing obfuscated .NET assemblies (de4dot) — https://attack.mitre.org/techniques/T1027/
- **T1027.002** Software Packing — packer/obfuscator identified by de4dot (ConfuserEx, .NET Reactor) — https://attack.mitre.org/techniques/T1027/002/
- **T1140** Deobfuscate/Decode Files or Information — recovering strings/logic prior to review — https://attack.mitre.org/techniques/T1140/
- **T1059.001 / T1059** Command and Scripting Interpreter (managed payload execution context) — https://attack.mitre.org/techniques/T1059/001/
- **T1218.004** System Binary Proxy Execution: InstallUtil — managed payload launched via signed system binary — https://attack.mitre.org/techniques/T1218/004/
- **T1620** Reflective Code Loading — reflective in-memory assembly loading — https://attack.mitre.org/techniques/T1620/
- DFIR phases: **Examination / Analysis** (static reverse engineering of the recovered artifact) and **Identification** (extracting IOCs for scoping).

## Sources
Claim → source mapping (all URLs are official tool docs/repos, Microsoft Learn, MITRE ATT&CK, RFC editor, or recognized project docs):

- ILSpy is an open-source .NET decompiler with a WPF GUI — ILSpy project — https://github.com/icsharpcode/ILSpy
- `ilspycmd` command-line front end; `--version`, `-l`/`--list`, default stdout decompile, `-p`/`--project`, `-o`/`--outputdir` flags and behavior — ilspycmd README — https://github.com/icsharpcode/ILSpy/blob/master/ILSpy.CommandLine/README.md
- FLARE-VM ships ILSpy and de4dot(-cex) packages — FLARE-VM — https://github.com/mandiant/flare-vm ; VM package definitions — https://github.com/mandiant/VM-Packages
- de4dot deobfuscator: obfuscator detection, string/symbol/control-flow reversal, `-f` input and `-o` output flags, CLI banner/usage — de4dot README — https://github.com/de4dot/de4dot#readme
- .NET Framework `csc.exe` `/nologo` and `/out` compiler options — Microsoft Learn (C# compiler options) — https://learn.microsoft.com/en-us/dotnet/csharp/language-reference/compiler-options/
- `Get-FileHash -Algorithm SHA256` behavior — Microsoft Learn — https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-filehash
- `203.0.113.0/24` is reserved documentation address space (TEST-NET-3) — RFC 5737 — https://www.rfc-editor.org/rfc/rfc5737
- Zeek `files.log` / File Analysis Framework (`mime_type`, hashes) — Zeek docs — https://docs.zeek.org/en/master/logs/files.html
- Security Onion Zeek data/hunting — Security Onion docs — https://docs.securityonion.net/en/2.4/zeek.html
- Security Onion Suricata alerts/hunting — Security Onion docs — https://docs.securityonion.net/en/2.4/suricata.html
- Suricata rule syntax (`http.uri`, `content`, `flow`) — Suricata docs — https://docs.suricata.io/en/latest/rules/index.html
- MITRE ATT&CK T1027 Obfuscated Files or Information — https://attack.mitre.org/techniques/T1027/
- MITRE ATT&CK T1027.002 Software Packing — https://attack.mitre.org/techniques/T1027/002/
- MITRE ATT&CK T1140 Deobfuscate/Decode Files or Information — https://attack.mitre.org/techniques/T1140/
- MITRE ATT&CK T1059 / T1059.001 Command and Scripting Interpreter — https://attack.mitre.org/techniques/T1059/001/
- MITRE ATT&CK T1218.004 InstallUtil — https://attack.mitre.org/techniques/T1218/004/
- MITRE ATT&CK T1218.009 Regsvcs/Regasm — https://attack.mitre.org/techniques/T1218/009/
- MITRE ATT&CK T1127.001 MSBuild — https://attack.mitre.org/techniques/T1127/001/
- MITRE ATT&CK T1620 Reflective Code Loading — https://attack.mitre.org/techniques/T1620/
- SANS FOR610 Reverse-Engineering Malware (analysis methodology) — https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/

## Related modules
- [NET deobfuscation deep-dive](../29-dotnet-deobf-deep/README.md) -- shares de4dot for advanced deobfuscation workflows.
- [NET reverse engineering](../14-dotnet-re/README.md) -- shares de4dot and covers foundational .NET RE.
- [Scenario: .NET malware analysis](../53-dotnet-malware-case/README.md) -- shares de4dot in a full case-based scenario.
- [Ghidra decompiler & scripting deep-dive](../27-ghidra-scripting/README.md) -- same Deep-dives learning path for decompilation tooling.

<!-- cyberlab-enriched: v1 -->
