# 35 * radare2 / Cutter reverse engineering -- LAB-LINUX

## Overview (plain language)
Reverse engineering means taking a compiled program — a file the computer already understands but a human cannot easily read — and translating it back into something an analyst can follow. When you double-click a program you only see the icon; underneath it is machine code. radare2 and Cutter are the tools that peel back that layer so you can see the instructions, text strings, and functions inside a file without running it. radare2 is a text/command-line "Swiss army knife" for inspecting, disassembling, and navigating a binary. Cutter is a friendly graphical window built on top of the same engine, showing the same information as clickable panels, function lists, and control-flow diagrams. Together they let a beginner ask simple questions — "what text is hidden in this file?", "what does this function do?", "does it call the network?" — and get answers safely, because inspecting a file (static analysis) does not execute it.

> Note on the radare2/Cutter relationship: Cutter is developed under the Rizin project umbrella and, in current releases, is built on the **Rizin** engine (a fork of radare2), not radare2 itself. Historically Cutter was a radare2 GUI. The static-analysis concepts and most commands overlap, but be aware the two engines have diverged. See the Cutter and Rizin project docs cited in Sources.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| radare2 | apt install radare2 | Command-line reverse-engineering framework: disassemble, analyze, and navigate binaries |
| Cutter | apt install cutter (REMnux/preinstalled) | GUI front-end (Rizin-based) for visual disassembly and control-flow graphs |

Both radare2 and Cutter are documented as installed/available on REMnux for static code analysis (remnux.org). radare2 is packaged by Kali (kali.org/tools/radare2). Cutter's own documentation describes it as a free and open-source reverse-engineering platform (cutter.re).

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
Expected output: radare2 prints a version banner (e.g. `radare2 5.x.x`). The `-v` flag printing the version/build banner is documented in the radare2 man page / `radare2 -h` (see rada.re docs in Sources). Cutter prints its version string, or the fallback message confirms the GUI binary exists.

## Guided walkthrough
1. Build a small benign sample and confirm its type — no live malware is used. We compile with `-no-pie` so the binary loads at a fixed base address, which keeps the disassembly addresses stable and easier to follow for a beginner (a PIE binary would show relocatable/relative addressing that changes the presentation).
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
gcc -no-pie -o exercise/hello exercise/hello.c
file exercise/hello
```
Expected output: `exercise/hello: ELF 64-bit LSB executable, x86-64 ...`. `file` reads the ELF magic bytes and header to report class (64-bit), endianness (LSB), and machine (x86-64); this confirms the artifact is a native Linux executable before we disassemble it.

2. `radare2 -A` opens the file and runs analysis on load; `afl` (analyze-function-list) lists discovered functions. WHY: auto-analysis walks the code from known entry points, resolves call targets, and names functions/imports so you get a function map instead of raw bytes. The `-q` flag quits after running the `-c` command, and `-c` runs a command at startup — both documented in the radare2 usage/man page.
```bash
# -A runs analysis on load; -qc runs the given command then quits
radare2 -A -qc 'afl' exercise/hello
```
Expected output: a table of functions including `main` and `sym.secret_check` with addresses, sizes, and cross-reference counts. NUANCE: `-A` is roughly equivalent to running the `aaa` analysis command inside the session; heavier analysis (`aaaa`) does more emulation-based reference recovery but is slower. Names like `sym.secret_check` come from the symbol table; if a binary is stripped you will instead see auto-generated names such as `fcn.00401136`.

3. Extract strings and disassemble `main` non-interactively. WHY: strings often carry the fastest indicators (URLs, mutexes, error messages), and `pdf` (print-disassemble-function) gives the instruction-level logic of a single function without paging through the whole binary.
```bash
# rabin2 (shipped with radare2) lists strings from data sections; r2 disassembles main
rabin2 -z exercise/hello
radare2 -A -qc 's main; pdf' exercise/hello
```
Expected output: the string `LAB-LINUX radare2 demo string: r2rules` in the `rabin2 -z` table (the `-z` flag lists strings found in the binary's data sections, per the rabin2 man page), and a disassembly of `main` showing the `call sym.imp.puts` and the conditional branch into `secret_check`. NUANCE: `rabin2 -z` reads only initialized data sections; use `-zz` to scan the whole file (including sections not normally treated as strings). The `s` command seeks to a symbol/address before `pdf` prints that function.

4. Open the same file visually in Cutter. WHY: the graph view makes control flow (branches, loops) obvious in a way linear disassembly does not, which speeds up understanding of decision logic like the `secret_check` comparison.
```bash
# Launch the GUI and open the sample; explore the Functions panel and graph view
cutter exercise/hello &
```
Expected output: Cutter opens, auto-analyzes, and shows `main` in the Functions list; double-clicking it renders the control-flow graph containing the `secret_check` branch. NUANCE: Cutter runs its own analysis on open (analysis depth is configurable in the initial-analysis dialog); the function names and graph reflect the underlying Rizin engine, so they should match the radare2 CLI results for this simple, unstripped binary.

## Hands-on exercise
Use the sample artifact in this module's `exercise/` directory.

- **Sample type:** 64-bit ELF x86-64 executable, `exercise/hello`.
- **Safe origin:** Benign and inert. It is compiled locally from the `exercise/hello.c` source shown above using `gcc`. It only prints text to the terminal, performs no network or file activity, and contains no malicious code. No live malware is ever placed in this lab.
- **Reproducible generator:** run the two commands in Guided walkthrough step 1 (`cat > exercise/hello.c ...` then `gcc -no-pie -o exercise/hello exercise/hello.c`). Because compiler versions differ, the sha256 is not fixed across systems; compute yours with `sha256sum exercise/hello`.

**Tasks:**
1. List all functions in the binary and record the name of the non-`main` user function.
2. Find the demo string embedded in the binary.
3. Identify the constant value that `secret_check` compares against.

## SOC analyst perspective
When triaging a suspicious file flagged by Security Onion (for example a Zeek `files.log` extraction or a Suricata `fileinfo`/file event), an analyst pulls the artifact into radare2 or Cutter to perform static examination before ever detonating it. Zeek's File Analysis Framework logs extracted files and their hashes to `files.log`, and Zeek can carve files to disk via the `extract` file analyzer — the natural handoff point into static RE (see the Zeek documentation in Sources). Function enumeration and string extraction quickly reveal indicators — hardcoded URLs, IP addresses, mutex names, or suspicious API imports — that feed detection rules and threat-intel enrichment.

Concrete detection logic and ATT&CK mapping:
- Imports/strings referencing standard protocols (HTTP/DNS/TLS) corroborate **T1071 – Application Layer Protocol** (and its sub-techniques, e.g. T1071.001 Web Protocols, T1071.004 DNS). Pivot: in Security Onion, search Zeek `http.log`/`dns.log`/`ssl.log` (via Kibana/Elastic) for the extracted host or URI, and check `conn.log` for a matching connection.
- References to crypto APIs or evidence of an encrypted C2 channel map to **T1573 – Encrypted Channel**. Pivot: Zeek `ssl.log` JA3/JA3S fingerprints and long-lived `conn.log` flows.
- High section entropy or a recognizable packer stub (e.g. UPX section names `UPX0`/`UPX1`) maps to **T1027.002 – Software Packing** under T1027. Pivot: hunt for the extracted file's hash across Elastic; correlate to the delivery event.
- Byte patterns discovered in strings/disassembly become YARA rules; matches on subsequently extracted files scope the incident.

Detection logic in radare2 terms: `rabin2 -H` (headers) and `rabin2 -S` (sections, with entropy) surface anomalous sections; `rabin2 -i` lists imports so you can flag network/crypto/process-injection APIs. Findings (hashes via `sha256sum`, strings, imports) become pivots correlated against Security Onion's PCAP and connection logs, letting the SOC confirm whether the host actually contacted the extracted indicators and scope the incident accordingly.

## Attacker perspective
Attackers use radare2 and Cutter to understand and modify software they do not own: locating a license/authentication check, patching a conditional jump to bypass it (in r2, `wa`/write-assembly can overwrite a `jne` with a `je` or `nop`), crafting exploits by mapping vulnerable functions, or studying a defender's tooling to evade it. The same disassembly that helps a SOC helps an adversary find where to inject shellcode or where to strip telemetry.

Concrete TTPs, artifacts, and evasion:
- **Obfuscation / packing — T1027 (and T1027.002 Software Packing):** adversaries pack payloads (e.g. UPX) or encrypt strings to defeat quick triage. Artifacts: abnormally high section entropy, few readable strings, non-standard/renamed sections, small stub with a large compressed region. radare2 readily exposes this via section entropy (`rabin2 -S`) and sparse `rabin2 -z` output. Evasion note: attackers may modify the UPX header so the stock `upx -d` unpacker fails, forcing manual unpacking.
- **Deobfuscation on the analyst side — T1140 – Deobfuscate/Decode Files or Information:** describes the reverse of the above; the analyst decodes/decrypts embedded content that the malware would decode at runtime.
- **Anti-analysis / debugger and VM checks — T1497 – Virtualization/Sandbox Evasion:** timing checks, VM-artifact checks, and debugger detection appear as branches that static analysis can spot and patch out.
- **Reflective/in-memory loading — T1620 – Reflective Code Loading:** payloads loaded from memory rather than disk leave fewer file artifacts; imports hinting at manual mapping or memory-execution APIs are the tell.

Artifacts left behind for defenders: modified/patched binaries with altered hashes (breaking known-good hash allow-lists), timestamps that no longer match legitimate builds, tell-tale packer sections, and unusually high entropy — all of which static analysis in radare2 readily exposes.

## Answer key
Expected findings and the exact commands that produce them:

1. **Functions** — `sym.secret_check` (plus `main`, `entry0`, imports).
```bash
radare2 -A -qc 'afl~secret' exercise/hello
```
Expected: a line referencing `sym.secret_check`. (The `~` operator is radare2's internal grep, documented in the radare2 book.)

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
- **T1027 – Obfuscated Files or Information** (identifying packing/obfuscation during examination) — https://attack.mitre.org/techniques/T1027/
- **T1027.002 – Software Packing** (packers such as UPX; high entropy) — https://attack.mitre.org/techniques/T1027/002/
- **T1140 – Deobfuscate/Decode Files or Information** (analyst reversing encoded content) — https://attack.mitre.org/techniques/T1140/
- **T1620 – Reflective Code Loading** (in-memory execution inferred from imports) — https://attack.mitre.org/techniques/T1620/
- **T1071 – Application Layer Protocol** (network behavior inferred from imports/strings) — https://attack.mitre.org/techniques/T1071/
- **T1573 – Encrypted Channel** (crypto API / encrypted C2 indicators) — https://attack.mitre.org/techniques/T1573/
- **T1497 – Virtualization/Sandbox Evasion** (anti-analysis checks visible in disassembly) — https://attack.mitre.org/techniques/T1497/
- **DFIR phase:** Examination and Analysis (static malware analysis / reverse engineering of a collected artifact), consistent with the SANS FOR610 static-analysis workflow.

## Sources
Claim → source mapping (all URLs are real, authoritative pages):

- radare2 exists, is a CLI RE framework, and its command semantics (`-A` analysis on load, `-q` quit, `-c` run command, `s` seek, `pdf` print-disassemble-function, `afl` list functions, `~` internal grep) — official radare2 book and docs: https://book.rada.re/ ; project home: https://rada.re/n/
- rabin2 usage and flags (`-z` strings in data sections, `-zz` whole-file, `-S` sections, `-i` imports, `-H` headers) — rabin2 is shipped with radare2 and documented in the radare2 book: https://book.rada.re/tools/rabin2/intro.html
- radare2 packaged/available on Kali — https://www.kali.org/tools/radare2/
- radare2 and Cutter available on REMnux for static code analysis — https://docs.remnux.org/discover-the-tools/statically+analyze+code
- Cutter is a free/open-source reverse-engineering platform with disassembly, function list, and graph views; current Cutter is built on the Rizin engine — https://cutter.re/ and Rizin project: https://rizin.re/
- ELF `file` output fields (class, endianness, machine) — the sample's `ELF 64-bit LSB executable, x86-64` output is standard `file`/ELF behavior described in the radare2/rabin2 docs above for reading binary headers.
- Zeek File Analysis Framework, `files.log`, and file extraction (handoff to static RE) — https://docs.zeek.org/en/master/frameworks/file-analysis.html
- Security Onion (Suricata/Zeek/Elastic pivots; PCAP retrieval and log search) — https://docs.securityonion.net/
- Suricata file extraction / fileinfo events — https://docs.suricata.io/en/latest/file-extraction/file-extraction.html
- UPX packer (section names, `upx -d` decompression) — https://upx.github.io/
- MITRE ATT&CK techniques — T1027 https://attack.mitre.org/techniques/T1027/ ; T1027.002 https://attack.mitre.org/techniques/T1027/002/ ; T1140 https://attack.mitre.org/techniques/T1140/ ; T1620 https://attack.mitre.org/techniques/T1620/ ; T1071 https://attack.mitre.org/techniques/T1071/ ; T1573 https://attack.mitre.org/techniques/T1573/ ; T1497 https://attack.mitre.org/techniques/T1497/
- SANS FOR610 Reverse-Engineering Malware (static-analysis workflow, examination/analysis phase) — https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/

## Related modules
- [Volatility 3 deep-dive (memory plugins & workflow)](../20-volatility-deep/README.md) -- same learning path (Deep-dives); pivot from static RE to in-memory analysis of a running/injected payload.
- [YARA rule authoring & threat hunting](../21-yara-authoring/README.md) -- same learning path (Deep-dives); turn strings/byte patterns found here into detection rules.
- [The Sleuth Kit command mastery](../22-sleuthkit-mastery/README.md) -- same learning path (Deep-dives); recover the suspicious binary from disk before reversing it.
- [Plaso super-timeline deep-dive](../23-plaso-supertimeline/README.md) -- same learning path (Deep-dives); place the binary's creation/execution into a forensic timeline.

<!-- cyberlab-enriched: v1 -->
