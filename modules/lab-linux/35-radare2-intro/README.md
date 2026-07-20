# 35 * radare2 / Cutter reverse engineering -- LAB-LINUX

## Overview (plain language)
Reverse engineering means taking a compiled program — a file the computer already understands but a human cannot easily read — and translating it back into something an analyst can follow. When you double-click a program you only see the icon; underneath it is machine code. radare2 and Cutter are the tools that peel back that layer so you can see the instructions, text strings, and functions inside a file without running it. radare2 is a text/command-line "Swiss army knife" for inspecting, disassembling, and navigating a binary. Cutter is a friendly graphical window built on top of the same engine, showing the same information as clickable panels, function lists, and control-flow diagrams. Together they let a beginner ask simple questions — "what text is hidden in this file?", "what does this function do?", "does it call the network?" — and get answers safely, because inspecting a file (static analysis) does not execute it.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| radare2 | apt install radare2 | Command-line reverse-engineering framework: disassemble, analyze, and navigate binaries |
| Cutter | apt install cutter (REMnux/preinstalled) | GUI front-end over the radare2 engine for visual disassembly and control-flow graphs |

## Learning objectives
- Verify radare2 and Cutter are installed and identify their versions on LAB-LINUX.
- Open a benign ELF binary in radare2 and run auto-analysis (`aaa`) to enumerate functions.
- Extract embedded strings and disassemble the `main` function using radare2 commands.
- Explain how the same static-analysis workflow is performed visually in Cutter.
- Map the reverse-engineering activity to relevant MITRE ATT&CK techniques and DFIR phases.

## Environment check
```bash
# Prove radare2 and Cutter are present on LAB-LINUX
radare2 -v
cutter --version 2>/dev/null || echo "Cutter present (launch GUI: cutter &)"
```
Expected output: radare2 prints a version banner (e.g. `radare2 5.x.x`). Cutter prints its version string, or the fallback message confirms the GUI binary exists.

## Guided walkthrough
1. Build a small benign sample and confirm its type — no live malware is used.
```bash
mkdir -p exercise
cat > exercise/hello.c <<'EOF'
#include <stdio.h>
int secret_check(int x){ return x == 1337; }
int main(void){
    puts("LAB-LINUX radare2 demo string: r2rules");
    if (secret_check(1337)) puts("access granted");
    return 0;
}
EOF
gcc -no-pie -o exercise/hello exercise/hello
file exercise/hello
```
Expected output: `exercise/hello: ELF 64-bit LSB executable, x86-64 ...`.

2. `radare2 -A` opens the file and runs auto-analysis; `afl` lists discovered functions.
```bash
# -A runs analysis on load; commands piped via -qc run then quit
radare2 -A -qc 'afl' exercise/hello
```
Expected output: a table of functions including `main` and `sym.secret_check` with addresses and sizes.

3. Extract strings and disassemble `main` non-interactively.
```bash
# rabin2 (shipped with radare2) lists strings; r2 disassembles main
rabin2 -z exercise/hello
radare2 -A -qc 's main; pdf' exercise/hello
```
Expected output: the string `LAB-LINUX radare2 demo string: r2rules` in the strings table, and a disassembly of `main` showing the `call sym.imp.puts` and the branch into `secret_check`.

4. Open the same file visually in Cutter.
```bash
# Launch the GUI and open the sample; explore the Functions panel and graph view
cutter exercise/hello &
```
Expected output: Cutter opens, auto-analyzes, and shows `main` in the Functions list; double-clicking it renders the control-flow graph containing the `secret_check` branch.

## Hands-on exercise
Use the sample artifact in this module's `exercise/` directory.

- **Sample type:** 64-bit ELF x86-64 executable, `exercise/hello`.
- **Safe origin:** Benign and inert. It is compiled locally from the `exercise/hello.c` source shown above using `gcc`. It only prints text to the terminal, performs no network or file activity, and contains no malicious code. No live malware is ever placed in this lab.
- **Reproducible generator:** run the two commands in Guided walkthrough step 1 (`cat > exercise/hello.c ...` then `gcc -no-pie -o exercise/hello exercise/hello`). Because compiler versions differ, the sha256 is not fixed across systems; compute yours with `sha256sum exercise/hello`.

**Tasks:**
1. List all functions in the binary and record the name of the non-`main` user function.
2. Find the demo string embedded in the binary.
3. Identify the constant value that `secret_check` compares against.

## SOC analyst perspective
When triaging a suspicious file flagged by Security Onion (for example a Zeek `files.log` extraction or a Suricata `fileinfo` alert), an analyst pulls the artifact into radare2 or Cutter to perform static examination before ever detonating it. Function enumeration and string extraction quickly reveal indicators — hardcoded URLs, IP addresses, mutex names, or suspicious API imports — that feed detection rules and threat-intel enrichment. Seeing calls to network or crypto APIs corroborates ATT&CK techniques such as T1071 (Application Layer Protocol) or T1573 (Encrypted Channel). Findings (hashes, strings, YARA-worthy byte patterns) become pivots correlated against Security Onion's PCAP and connection logs, letting the SOC confirm whether the host actually contacted the extracted indicators and scope the incident accordingly.

## Attacker perspective
Attackers use radare2 and Cutter to understand and modify software they do not own: locating a license/authentication check, patching a conditional jump to bypass it, crafting exploits by mapping vulnerable functions, or studying a defender's tooling to evade it. The same disassembly that helps a SOC helps an adversary find where to inject shellcode or where to strip telemetry. Their own malware authors also anticipate this analysis and add obfuscation, packing (e.g. UPX), or anti-analysis checks to slow reverse engineers — techniques mapped to T1027 (Obfuscated Files or Information). Artifacts left behind for defenders include modified/patched binaries with altered hashes, timestamps that no longer match legitimate builds, and tell-tale packer sections or unusually high entropy that static analysis in radare2 readily exposes.

## Answer key
Expected findings and the exact commands that produce them:

1. **Functions** — `sym.secret_check` (plus `main`, `entry0`, imports).
```bash
radare2 -A -qc 'afl~secret' exercise/hello
```
Expected: a line referencing `sym.secret_check`.

2. **Embedded string** — `LAB-LINUX radare2 demo string: r2rules`.
```bash
rabin2 -z exercise/hello | grep r2rules
```

3. **Compared constant** — `1337` (0x539).
```bash
radare2 -A -qc 's sym.secret_check; pdf' exercise/hello | grep -Ei '0x539|1337'
```
Expected: a `cmp` instruction against `0x539` (1337 decimal).

Compute your sample hash for records: `sha256sum exercise/hello` (value is build-specific; the source and generator command above are the authoritative reproducible reference).

## MITRE ATT&CK & DFIR phase
- **T1027 – Obfuscated Files or Information** (identifying packing/obfuscation during examination).
- **T1140 – Deobfuscate/Decode Files or Information** (analyst reversing encoded content).
- **T1620 – Reflective Code Loading** / **T1071 – Application Layer Protocol** (behaviors inferred from imports and strings).
- **DFIR phase:** Examination and Analysis (static malware analysis / reverse engineering of a collected artifact).

## Sources
- radare2 project & documentation — https://rada.re/n/ and https://book.rada.re/
- Cutter reverse-engineering platform — https://cutter.re/
- Kali Tools: radare2 — https://www.kali.org/tools/radare2/
- REMnux docs (static code analysis tools) — https://docs.remnux.org/discover-the-tools/statically+analyze+code
- MITRE ATT&CK — T1027 https://attack.mitre.org/techniques/T1027/ ; T1140 https://attack.mitre.org/techniques/T1140/
- SANS FOR610 Reverse-Engineering Malware — https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/