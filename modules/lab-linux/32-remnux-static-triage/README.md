# 32 * REMnux static triage (DIE/ssdeep/pefile) -- LAB-LINUX

## Overview (plain language)
When a suspicious file lands on an analyst's desk, the first job is "static triage" — learning as much as possible about the file *without running it*. Think of it like inspecting a sealed package: you weigh it, x-ray it, and read the label instead of opening it. These three REMnux tools do exactly that. **Detect-It-Easy (DIE)** looks at a file and guesses what it is: what compiler built it, whether it was packed or compressed, and what protections it uses. **ssdeep** creates a "fuzzy fingerprint" so you can tell whether two files are *similar* (not just identical), which is great for spotting malware families and slightly-modified variants. **pefile** cracks open Windows programs (EXE/DLL) and reads their internal structure — sections, imports, timestamps — so you can spot odd or malicious behavior before any execution.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| Detect-It-Easy | (preinstalled on REMnux) `diec --version` | Identify file type, compiler, packer, and protector signatures |
| ssdeep | apt install ssdeep | Compute and compare context-triggered piecewise (fuzzy) hashes for similarity |
| pefile | pip3 install pefile | Python library/CLI to parse the structure of Windows PE (EXE/DLL) files |

## Learning objectives
- Use **Detect-It-Easy** to identify a file's type, compiler, and packer status from the command line.
- Generate and compare **ssdeep** fuzzy hashes to quantify similarity between two files.
- Parse a PE file's sections, imports, and compile timestamp with **pefile**.
- Interpret triage findings (packing, suspicious imports, high entropy) to prioritize deeper analysis.

## Environment check
```bash
# Prove each tool is installed on the REMnux side of LAB-LINUX
diec --version
ssdeep -V
python3 -c "import pefile; print('pefile', pefile.__version__)"
```
Expected output: DIE prints a version string (e.g. `Detect It Easy 3.xx`), `ssdeep` prints a version like `ssdeep 2.14.1`, and the Python line prints `pefile 2023.x.x`. If any command errors, install with the commands in the Tools covered table.

## Guided walkthrough
1. Build a small, benign PE test file so nothing dangerous is used (a plain MinGW-compiled "hello world").
```bash
mkdir -p exercise && cd exercise
cat > hello.c <<'EOF'
#include <stdio.h>
int main(void){ printf("hello lab\n"); return 0; }
EOF
# Cross-compile to a Windows PE (MinGW ships on REMnux/Kali)
x86_64-w64-mingw32-gcc hello.c -o sample.exe
ls -l sample.exe
```
Expected output: a `sample.exe` PE binary is produced (tens of KB).

2. `diec` — identify what the file is and whether it is packed.
```bash
diec sample.exe
```
Expected output: DIE reports `PE64`, an entrypoint, and a compiler such as `Compiler: MinGW` — and importantly it will NOT flag a packer for this clean build.

3. `ssdeep` — fingerprint the file, then prove a tiny change produces a *similar* (not identical) hash.
```bash
ssdeep sample.exe > baseline.txt
cp sample.exe sample_mod.exe
printf 'X' >> sample_mod.exe        # append one byte
ssdeep -m baseline.txt sample_mod.exe
```
Expected output: `sample_mod.exe matches baseline.txt:sample.exe (NN)` where NN is a match score below 100 (fuzzy similarity), demonstrating near-duplicate detection.

4. `pefile` — read the PE structure, sections, and imports.
```bash
python3 - <<'EOF'
import pefile
pe = pefile.PE("sample.exe")
print("TimeDateStamp:", hex(pe.FILE_HEADER.TimeDateStamp))
for s in pe.sections:
    print(s.Name.decode(errors="ignore").strip("\x00"),
          "entropy=%.2f" % s.get_entropy())
if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        print("DLL:", entry.dll.decode())
EOF
```
Expected output: section names like `.text`, `.data`, `.idata` with entropy values (roughly 4–6 for normal code), and imported DLLs such as `KERNEL32.dll` and `msvcrt.dll`.

## Hands-on exercise
Using the sample in this module's `exercise/` directory, answer:
1. What compiler does **Detect-It-Easy** report for `sample.exe`, and is a packer detected?
2. What is the **ssdeep** similarity score between `sample.exe` and `sample_mod.exe`?
3. Which imported DLLs does **pefile** list for `sample.exe`?

**Sample declaration:**
- **Type:** Windows PE64 executable (`sample.exe`).
- **Safe origin:** Benign and inert. It is generated locally from the `hello.c` source shown above using `x86_64-w64-mingw32-gcc` — it only prints a string and performs NO network or system-modifying activity. NO live malware is used.
- **Reproducible generator:** run the two code blocks in Guided walkthrough steps 1 and 3 inside `exercise/`.

## SOC analyst perspective
Static triage is the front door of the incident-response examination phase. When an EDR alert or a Security Onion detection (e.g., a Suricata file-extraction or a Zeek `files.log` entry) surfaces an unknown binary, an analyst pulls the extracted file and runs DIE/pefile/ssdeep before ever detonating it. DIE quickly flags packers/protectors (an early indicator of evasion, mapping to MITRE ATT&CK **T1027.002 Software Packing**), pefile reveals suspicious imports and compile timestamps that can be pivoted into hunting queries, and ssdeep clusters the sample against known-bad fuzzy hashes to attribute it to a family and to sweep the fleet for near-duplicates. In Security Onion you can enrich hits by correlating the file hash from `files.log` with your ssdeep-derived clusters, turning one alert into a fleet-wide retrospective hunt.

## Attacker perspective
Attackers know analysts will triage statically, so they deliberately defeat these tools. They **pack or crypt** binaries (raising section entropy toward 8.0 and hiding real imports behind a stub) to fool casual inspection — but DIE and pefile expose exactly those tells: a single high-entropy section, a truncated import table, an unusual entrypoint, or a compile timestamp that has been zeroed or forged. To dodge ssdeep clustering, malware authors add junk bytes, randomize resources, or recompile per-target so fuzzy scores drop; yet minor changes still leave residual similarity (a match score well below 100), which is precisely what ssdeep is designed to catch. The artifacts left behind for defenders include the PE header anomalies, packer signatures, mismatched section characteristics, and consistent fuzzy-hash lineage across a campaign.

## Answer key
Expected findings and the exact commands that produce them:
1. **DIE:** compiler is MinGW / GCC, no packer detected.
```bash
diec exercise/sample.exe | grep -iE "compiler|packer|linker"
```
2. **ssdeep:** the modified copy matches the baseline with a score under 100 (fuzzy match, not identical).
```bash
ssdeep exercise/sample.exe > exercise/baseline.txt
ssdeep -m exercise/baseline.txt exercise/sample_mod.exe
```
3. **pefile imports:** `KERNEL32.dll` and `msvcrt.dll` (MinGW C runtime).
```bash
python3 -c "import pefile; pe=pefile.PE('exercise/sample.exe'); [print(e.dll.decode()) for e in pe.DIRECTORY_ENTRY_IMPORT]"
```
**Sample sha256:** the `sample.exe` is locally generated, so verify your own build with:
```bash
sha256sum exercise/sample.exe
```
(Record this digest in your notes; it is deterministic per toolchain version but differs across MinGW versions, which is why a reproducible generator command is provided instead of a fixed digest.)

## MITRE ATT&CK & DFIR phase
- **T1027 — Obfuscated Files or Information** (detected via DIE/pefile entropy and header analysis).
- **T1027.002 — Software Packing** (DIE packer signatures; pefile section entropy).
- **T1140 — Deobfuscate/Decode Files or Information** (context for follow-on analysis).
- **DFIR phase:** Identification and Examination — static triage prioritizes samples before dynamic analysis.

## Sources
- REMnux tools documentation: https://docs.remnux.org/discover-the-tools
- Detect-It-Easy (horsicq): https://github.com/horsicq/Detect-It-Easy
- ssdeep / fuzzy hashing project: https://ssdeep-project.github.io/ssdeep/
- pefile documentation: https://github.com/erocarrera/pefile
- Kali Tools — ssdeep: https://www.kali.org/tools/ssdeep/
- MITRE ATT&CK T1027 Obfuscated Files or Information: https://attack.mitre.org/techniques/T1027/
- MITRE ATT&CK T1027.002 Software Packing: https://attack.mitre.org/techniques/T1027/002/
- SANS FOR610 Reverse-Engineering Malware: https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/