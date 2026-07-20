# 42 * FLOSS obfuscated-string extraction -- LAB-WINDOWS

## Overview (plain language)
Malware authors often hide the text ("strings") inside their programs so that simple tools cannot read them. These hidden strings might be website addresses, file names, registry keys, or messages the program will eventually use. The classic `strings` utility only shows text stored in the clear, so it misses anything the program scrambles and only unscrambles at run time. FLOSS (FLARE Obfuscated String Solver) goes further: it automatically decodes strings that are XOR-encoded, stack-built one character at a time, or decoded by small functions, and it also lists normal ASCII/Unicode strings. capa is a companion tool that reads a program and reports the capabilities it appears to have (for example "encrypts data" or "communicates over HTTP") in plain language, helping you understand what a sample can do before you ever run it.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| FLOSS | (preinstalled on FLARE-VM) | Automatically extract and de-obfuscate stack, tight-loop, and decoded strings from PE files |
| capa | (preinstalled on FLARE-VM) | Identify program capabilities by matching against a rule set of behaviors |

## Learning objectives
- Run FLOSS against a PE file and distinguish static, stack, tight, and decoded string categories.
- Extract only the decoded/obfuscated strings and interpret them as potential indicators.
- Run capa on the same sample and map reported capabilities to MITRE ATT&CK techniques.
- Produce a JSON report from FLOSS/capa suitable for handing to a SOC ticket.

## Environment check
```powershell
# Prove both tools are installed on FLARE-VM
floss --version
capa --version
```
Expected output: FLOSS prints a version banner (e.g. `floss 3.x`); capa prints its version and rule/signature set count (e.g. `capa 7.x`). If either command is not recognized, re-run the FLARE-VM installer for the `flare-floss` and `flare-capa` packages.

## Guided walkthrough
1. List every string category FLOSS supports so you know what you can filter on.
```powershell
floss --help
```
Expected: usage text showing options such as `--only static decoded stack tight` and output-format flags.

2. Run a full FLOSS pass on the benign sample and let it print static + de-obfuscated strings.
```powershell
floss .\exercise\sample.exe
```
Expected: sections titled `FLOSS STATIC STRINGS`, `FLOSS STACK STRINGS`, `FLOSS TIGHT STRINGS`, and `FLOSS DECODED STRINGS`. The decoded section reveals text that was not visible to plain `strings`.

3. Emit machine-readable JSON and restrict to only the interesting decoded/stack strings.
```powershell
floss --json --only decoded stack .\exercise\sample.exe > .\exercise\floss.json
```
Expected: a JSON file whose `strings` object contains `decoded_strings` and `stack_strings` arrays.

4. Ask capa what the sample can do and get ATT&CK mappings.
```powershell
capa .\exercise\sample.exe
```
Expected: capability tables plus an `ATT&CK` / `MBC` summary column linking matched rules to technique IDs.

## Hands-on exercise
Use the sample in this module's `exercise/` directory.

**Sample declaration**
- Type: 64-bit Windows PE console executable (`sample.exe`).
- Safe origin: **benign/inert**, built locally from source with no network, file-write, or persistence behavior. It merely constructs one obfuscated string on the stack and one XOR-decoded string, then exits.
- No live malware is used and the program performs **no egress**.

**Reproducible generator** (run on FLARE-VM to build the exact sample; requires the VC build tools already in the catalog):
```powershell
$src = @'
#include <stdio.h>
int main(void){
    char stackstr[6];
    stackstr[0]='H'; stackstr[1]='E'; stackstr[2]='L';
    stackstr[3]='L'; stackstr[4]='O'; stackstr[5]='\0';
    char enc[] = {0x64,0x6f,0x65,0x64,0x62,0x62,0x71,0x00}; /* XOR 0x01 -> "eldca cp" style */
    for(int i=0; enc[i]; i++) enc[i]=enc[i]^0x01;
    printf("%s %s\n", stackstr, enc);
    return 0;
}
'@
Set-Content -Path .\exercise\sample.c -Value $src -Encoding ASCII
cl /nologo /Fe:.\exercise\sample.exe .\exercise\sample.c
```

**Tasks**
1. Run plain FLOSS static output and confirm the string `HELLO` is **not** present in the static section.
2. Run full FLOSS and locate `HELLO` in the stack-strings section and the XOR-decoded string in the decoded section.
3. Run capa and record any reported capability related to data obfuscation/encoding.

## SOC analyst perspective
A defender uses FLOSS during triage to pull indicators (C2 domains, mutex names, dropped file paths) that would stay hidden from a plain `strings` sweep, then feeds those decoded strings into Security Onion as pivots — for example searching Zeek `conn.log`/`dns.log` for a decoded domain or hunting Suricata alerts for a decoded URI path. capa output is even more useful for detection engineering because it maps observed capabilities directly to MITRE ATT&CK techniques such as T1027 (Obfuscated Files or Information) and T1573 (Encrypted Channel), letting the analyst prioritize the sample and write or tune correlation rules. Decoded indicators become IOCs that enrich alert triage and threat-intel enrichment inside the SOC workflow.

## Attacker perspective
Attackers deliberately obfuscate strings so that static AV signatures, blue-team `strings` triage, and automated sandboxes miss their real intent — encoding C2 addresses, encrypting configuration blobs, or building strings on the stack byte-by-byte to avoid clear-text artifacts (MITRE T1027 / T1140 Deobfuscate/Decode Files or Information). The trade-off is that the decode routine itself remains in the binary: FLOSS emulates those very routines and recovers the plaintext, and capa fingerprints the presence of XOR loops, RC4 setups, or base64 tables. Those decoding stubs, unusual entropy sections, and stack-string construction patterns are precisely the artifacts a defender can detect and use to attribute or cluster the sample.

## Answer key
- FLOSS static section does **not** contain `HELLO`; it appears only under `FLOSS STACK STRINGS`.
- The XOR-decoded string appears under `FLOSS DECODED STRINGS` after emulation.
- capa reports an encoding/obfuscation capability (e.g. "encode data using XOR", mapped to T1027).

Commands that produce the findings:
```powershell
# Confirm HELLO is absent from static strings
floss --only static .\exercise\sample.exe | Select-String "HELLO"

# Reveal the stack + decoded strings
floss --only stack decoded .\exercise\sample.exe

# Capability + ATT&CK mapping
capa -v .\exercise\sample.exe | Select-String -Pattern "XOR|encode|T1027"
```
Sample sha256: reproduce with `Get-FileHash .\exercise\sample.exe -Algorithm SHA256` after building from the generator above (compiler output is deterministic for a fixed toolchain; record the resulting digest in your lab notes).

## MITRE ATT&CK & DFIR phase
- T1027 — Obfuscated Files or Information (obfuscated/encoded strings).
- T1140 — Deobfuscate/Decode Files or Information (the decode routines FLOSS emulates).
- T1573 — Encrypted Channel (if decoded strings reveal encrypted C2 config).
- DFIR phase: **Examination / Analysis** (static malware triage prior to dynamic detonation).

## Sources
- Mandiant / FLARE, FLOSS project: https://github.com/mandiant/flare-floss
- Mandiant / FLARE, capa project: https://github.com/mandiant/capa
- FLARE-VM install and package set: https://github.com/mandiant/flare-vm
- MITRE ATT&CK T1027 Obfuscated Files or Information: https://attack.mitre.org/techniques/T1027/
- MITRE ATT&CK T1140 Deobfuscate/Decode Files or Information: https://attack.mitre.org/techniques/T1140/
- SANS FOR610 Reverse-Engineering Malware course reference: https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/