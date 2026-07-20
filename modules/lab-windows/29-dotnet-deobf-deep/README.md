# 29 * .NET deobfuscation deep-dive -- LAB-WINDOWS

## Overview (plain language)
Many Windows programs are written in .NET languages like C# and compiled into an easy-to-read intermediate format instead of raw machine code. Because that format is so readable, criminals scramble ("obfuscate") their .NET malware to hide what it does — renaming everything to gibberish, encrypting text, and adding junk. The tools in this module reverse that scrambling. dnSpyEx lets you open a .NET program, read its recovered source code, and even debug it live. ILSpy is a fast, standalone decompiler for browsing that same code. de4dot automatically detects common obfuscators and cleans a file so it reads almost like the original source. Together they turn a confusing, garbled binary back into something a human can understand.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| dnSpyEx | Included in FLARE-VM | .NET assembly decompiler, editor, and debugger for reading/patching managed code |
| ILSpy | Included in FLARE-VM | Standalone open-source .NET decompiler for browsing IL and reconstructed C# |
| de4dot | Included in FLARE-VM | Automated .NET deobfuscator/cleaner that detects and reverses common protectors |

## Learning objectives
- Identify a .NET assembly and determine which obfuscator (if any) was applied using de4dot detection output.
- Produce a cleaned assembly with de4dot and confirm the reduction in obfuscation artifacts.
- Decompile both the original and cleaned assembly with ILSpy and dnSpyEx and compare readability.
- Locate a suspicious string or method in the recovered C# source and explain its behavior.

## Environment check
```powershell
# Confirm the three .NET RE tools are present on FLARE-VM.
# FLARE-VM installs these under the Desktop tools folder or PATH shims.
Get-Command dnSpy.exe   -ErrorAction SilentlyContinue | Select-Object Name, Source
Get-Command ILSpy.exe   -ErrorAction SilentlyContinue | Select-Object Name, Source
Get-Command de4dot.exe  -ErrorAction SilentlyContinue | Select-Object Name, Source

# Also verify the .NET runtime that assemblies target.
dotnet --info
```
Expected output: a `Name`/`Source` row for each of `dnSpy.exe`, `ILSpy.exe`, and `de4dot.exe`, and a `dotnet --info` banner listing installed SDK/runtime versions. If a `Get-Command` line returns nothing, launch the tool once from the FLARE-VM Start menu to register its path.

## Guided walkthrough
1. Run de4dot in detection mode to fingerprint the protector without modifying the file.
```powershell
# -d = detect only. Reports the obfuscator name if recognized.
de4dot.exe -d .\exercise\sample.exe
```
Expected observable output: a line such as `Detected ConfuserEx ...` (or `Unknown obfuscator` / `Cleaning ...` depending on the sample), plus the assembly full name.

2. Clean the assembly. de4dot writes a new `-cleaned` file next to the input.
```powershell
de4dot.exe .\exercise\sample.exe
Get-ChildItem .\exercise\sample-cleaned.exe | Select-Object Name, Length
```
Expected observable output: `Saving "sample-cleaned.exe"` and a listing showing the new `sample-cleaned.exe` with a size close to the original.

3. Browse the cleaned assembly with the ILSpy command-line decompiler to dump C#.
```powershell
# ilspycmd ships with ILSpy; -o writes decompiled source to a folder.
ilspycmd.exe -o .\exercise\decompiled .\exercise\sample-cleaned.exe
Get-ChildItem -Recurse .\exercise\decompiled\*.cs | Select-Object -First 5 FullName
```
Expected observable output: one or more `.cs` files under `exercise\decompiled\` containing readable class and method names.

4. Open the cleaned file interactively in dnSpyEx for method-level inspection and (optionally) debugging.
```powershell
Start-Process dnSpy.exe -ArgumentList ".\exercise\sample-cleaned.exe"
```
Expected observable output: the dnSpy GUI opens with the assembly tree on the left; expand namespaces to read decompiled C# with restored control flow.

## Hands-on exercise
Work against the sample in this module's `exercise/` directory.

- **Sample type:** a benign .NET (C#) console executable, `sample.exe`, that prints a marker string and contains one Base64-encoded string constant.
- **Safe-origin note:** fully benign/inert. It performs NO network egress and NO file/registry writes — it only writes text to stdout. It is generated locally from source you control (below), so no live malware is ever downloaded.
- **Generator (reproducible build):** run this on FLARE-VM to build the exact sample, then compute its hash.
```powershell
# Create source
@'
using System;
using System.Text;
class Program {
    static void Main() {
        string enc = "TGFiRmxhZ3s1YW1wbGVfMjl9";  // Base64
        Console.WriteLine("benign dotnet deobf sample");
        Console.WriteLine(Encoding.UTF8.GetString(Convert.FromBase64String(enc)));
    }
}
'@ | Set-Content -Encoding UTF8 .\exercise\Program.cs

# Compile with the .NET Framework C# compiler bundled on FLARE-VM
& "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe" `
  /nologo /out:.\exercise\sample.exe .\exercise\Program.cs

Get-FileHash .\exercise\sample.exe -Algorithm SHA256
```

**Tasks:**
1. Detect whether `sample.exe` is obfuscated using de4dot.
2. Decompile with ILSpy (`ilspycmd`) and locate the Base64 string constant.
3. Decode the Base64 value (CyberChef or PowerShell) and record the plaintext.
4. Confirm your understanding in dnSpyEx by finding the method that decodes and prints the string.

## SOC analyst perspective
Analysts see .NET malware constantly — droppers, RATs, and commodity stealers frequently ship as managed assemblies wrapped in ConfuserEx or similar packers. When Security Onion surfaces an alert (Suricata/Zeek flagging a suspicious download, or a Sysmon `Image`/`ProcessCreate` event forwarded to the Elastic stack), the pulled binary lands on FLARE-VM for triage. Running de4dot detection quickly tells you which obfuscator was used, and decompiling with ILSpy/dnSpyEx exposes hard-coded C2 URLs, mutex names, or decryption keys that become high-fidelity detection content — YARA rules, Sysmon `NetworkConnect` filters, and Zeek intel matches. Mapping the recovered behavior to ATT&CK (e.g. T1140 de-obfuscation, T1055 injection) lets the SOC pivot from a single sample to hunts across the fleet and enrich the case timeline during examination.

## Attacker perspective
Adversaries obfuscate .NET payloads to slow analysis and evade signatures: they rename symbols to unreadable tokens, encrypt string tables, add control-flow flattening, and pack the assembly so static AV yields nothing useful. Tools like ConfuserEx and .NET Reactor are the offensive counterparts of the cleaners here. Even so, obfuscation leaves artifacts a defender can find: the obfuscator's own metadata and runtime helper methods (which de4dot fingerprints), unusual assembly attributes, decrypted strings materialized in memory at runtime, and the very fact that a heavily-renamed managed binary is anomalous on an endpoint. Because .NET IL is inherently reversible, none of these protections prevent recovery — they only add time, and dnSpyEx debugging can dump decrypted values live, defeating string encryption entirely.

## Answer key
- **de4dot detection:** the generated `sample.exe` is **not obfuscated** — de4dot reports an unknown/none obfuscator and still emits `sample-cleaned.exe`. This is expected for the benign build; the workflow (detect → clean → decompile) is identical for real obfuscated samples.
```powershell
de4dot.exe -d .\exercise\sample.exe
```
- **String constant (ILSpy):** the source contains the Base64 literal `TGFiRmxhZ3s1YW1wbGVfMjl9`.
```powershell
ilspycmd.exe -o .\exercise\decompiled .\exercise\sample-cleaned.exe
Select-String -Path .\exercise\decompiled\*.cs -Pattern "TGFi"
```
- **Decoded plaintext:** `LabFlag{5ample_29}`
```powershell
[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("TGFiRmxhZ3s1YW1wbGVfMjl9"))
```
- **Method (dnSpyEx):** `Program.Main` decodes the constant via `Convert.FromBase64String` + `Encoding.UTF8.GetString` and writes it with `Console.WriteLine`.
- **Sample integrity:** `sample.exe` is built by the generator above; verify with `Get-FileHash .\exercise\sample.exe -Algorithm SHA256`. Because compiler timestamps vary per build, treat the reproducible generator command as the authoritative sample definition and record the SHA256 it emits on your VM for your case notes.

## MITRE ATT&CK & DFIR phase
- **T1027 — Obfuscated Files or Information** (identifying the protector).
- **T1140 — Deobfuscate/Decode Files or Information** (de4dot cleaning, Base64 decoding).
- **T1059.003 / managed code execution context** — analyzing what the decompiled code executes.
- **DFIR phase:** examination / analysis (static and dynamic malware analysis of a recovered artifact), feeding identification and reporting.

## Sources
- dnSpyEx project (maintained fork of dnSpy): https://github.com/dnSpyEx/dnSpy
- ILSpy decompiler & `ilspycmd`: https://github.com/icsharpcode/ILSpy
- de4dot .NET deobfuscator: https://github.com/de4dot/de4dot
- Mandiant FLARE-VM (tool distribution): https://github.com/mandiant/flare-vm
- MITRE ATT&CK T1140 Deobfuscate/Decode Files or Information: https://attack.mitre.org/techniques/T1140/
- MITRE ATT&CK T1027 Obfuscated Files or Information: https://attack.mitre.org/techniques/T1027/
- SANS FOR610 Reverse-Engineering Malware: https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/