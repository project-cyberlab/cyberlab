# 10 * Malicious documents -- LAB-LINUX

## Overview (plain language)
Everyday files like Word documents, Excel spreadsheets, and PDFs can be weaponized to attack a computer. Attackers hide small programs (macros) or scripts inside these otherwise ordinary-looking files, so that simply opening the document can quietly download or run malware. The tools in this module let an analyst crack open these documents *without* opening them normally, so nothing bad actually runs. Instead of double-clicking a suspicious invoice, you use command-line utilities to peek inside its structure, list the hidden pieces, pull out the embedded code, and read what that code was trying to do. This is one of the most common ways attacks start in the real world (phishing with attachments), so learning to safely dissect these files is a core DFIR skill.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| oletools | `pip install oletools` | Suite (olevba, oleid, olemeta, rtfobj) to triage and extract VBA macros/metadata from OLE/Office files |
| oledump | `apt install oledump` | Lists and dumps individual streams inside OLE2 (legacy Office) documents |
| pdfid | `apt install pdfid` | Scans a PDF for risky keywords (JavaScript, OpenAction, launch, embedded files) |
| pdf-parser | `apt install pdf-parser` | Walks PDF objects, follows references, and extracts/decodes embedded streams |
| XLMMacroDeobfuscator | `pip install XLMMacroDeobfuscator` | Emulates and deobfuscates Excel 4.0 (XLM) macros to recover their real logic |

> **Note on packaging:** These tools ship preinstalled on REMnux, the recommended LAB-LINUX platform for this module. On REMnux the Didier Stevens tools are invoked as `oledump.py`, `pdfid.py`, and `pdf-parser.py`, and oletools commands (`oleid`, `olevba`, `olemeta`, `oledump.py`) are on `PATH`. See the REMnux documents-analysis reference for the canonical tool list (https://docs.remnux.org/discover-the-tools/analyze+documents). The `apt install` names above are approximations for non-REMnux Debian/Kali systems; the authoritative distribution channel for the Didier Stevens tools is his own site/GitHub, and for oletools/XLMMacroDeobfuscator it is PyPI/GitHub (see Sources).

## Learning objectives
- Triage an unknown Office document and determine whether it contains VBA or XLM macros.
- Enumerate and dump individual OLE streams to isolate malicious code without executing it.
- Assess a PDF for high-risk keywords and extract suspicious objects/streams.
- Deobfuscate an Excel 4.0 macro to reveal its true command/URL indicators.
- Record IOCs (URLs, decoded strings, sha256) suitable for a SOC ticket.

## Environment check
```bash
# Prove the document-analysis tooling is installed on LAB-LINUX (REMnux)
olevba --version
oledump.py -h | head -n 1
pdfid.py --version
pdf-parser.py --version
xlmdeobfuscator --help | head -n 1
```
Expected output: `olevba` prints its version string (oletools 0.60.x is the current major line per the oletools release history: https://github.com/decalage2/oletools/releases); `oledump.py` prints its usage banner; `pdfid.py`/`pdf-parser.py` print their Didier-Stevens version lines; `xlmdeobfuscator` prints its help header. Any "command not found" means the tool is missing. (Note: `olevba` accepts both `-V`/`--version`; if `--version` is unavailable on an older build, `olevba -h` still prints the banner with the version — see the olevba docs: https://github.com/decalage2/oletools/wiki/olevba.)

## Guided walkthrough
1. `oleid` — quick triage flagging macros, encryption, and other risk indicators. Run this **first** because it is the cheapest signal: it tells you in one pass whether the file is an OLE2/OOXML Office file, whether it has VBA macros, whether it is encrypted, and whether it carries Flash/other embedded objects — before you commit to deeper extraction. `oleid` reads structure only and never executes macro code (https://github.com/decalage2/oletools/wiki/oleid).
```bash
oleid exercise/sample.doc
```
Expected: a table of indicators; the `VBA Macros` row shows `Yes` with a risk flag if macros are present. Nuance: a `Yes` here is not proof of malice — many legitimate documents contain macros — so treat it as a trigger to pull the actual VBA next, not a verdict.

2. `olevba` — extract and display the VBA source and an auto-analysis of suspicious keywords. This is the core step: `olevba` decompresses the VBA from the macro streams and runs a heuristic keyword/IOC scan, so you read the attacker's actual code rather than guessing from metadata (https://github.com/decalage2/oletools/wiki/olevba).
```bash
olevba --decode exercise/sample.doc
```
Expected: prints the VBA modules and an "ANALYSIS" table listing items such as `AutoExec` triggers (e.g. `AutoOpen`), `Suspicious` keywords (e.g. `Shell`), and any `IOC`/decoded strings. Nuance: the `--decode` flag additionally displays the results of olevba's built-in deobfuscation of hex/base64/Dridex-style string encodings, so you see decoded URLs/commands inline; the ANALYSIS table categorizes findings as `AutoExec`, `Suspicious`, `IOC`, `Hex String`, `Base64 String`, etc.

3. `oledump.py` — list OLE streams, then dump the macro-bearing stream by index. Use this when you want to work at the raw OLE2 container level — to confirm exactly which stream holds the macro, to extract streams olevba may not surface, or to carve non-VBA embedded content (https://blog.didierstevens.com/programs/oledump-py/).
```bash
oledump.py exercise/sample.doc
oledump.py -s 3 -v exercise/sample.doc
```
Expected: the first command lists numbered streams; a stream containing VBA macro code is marked with a capital `M` (a lowercase `m` marks a stream with a macro/attribute but no substantial code). `-s 3` selects stream index 3 and `-v` decompresses the VBA and prints the source. Nuance: the exact index (`3` here) is document-specific — always read it off the listing first, since it varies between files.

4. `pdfid.py` then `pdf-parser.py` — score a PDF, then extract the flagged object. `pdfid.py` is a fast keyword counter (it does NOT parse or execute the PDF) that tells you which risky elements are present; `pdf-parser.py` then does the real object-graph walk to pull the flagged content (https://blog.didierstevens.com/programs/pdf-tools/).
```bash
pdfid.py exercise/sample.pdf
pdf-parser.py --search JavaScript exercise/sample.pdf
```
Expected: `pdfid.py` shows nonzero counts for names such as `/JavaScript`, `/JS`, `/OpenAction`, `/AA`, `/Launch`, or `/EmbeddedFile`; `pdf-parser.py --search JavaScript` returns the matching object(s) so you can follow references to the JS stream. Nuance: `/OpenAction` combined with `/JavaScript` means script runs automatically on open — the classic auto-execute pattern. To then decode a specific object's stream, use `pdf-parser.py -o <obj> -f -d out.bin` (`-f` applies stream filters, `-d` dumps).

5. `xlmdeobfuscator` — emulate Excel 4.0 macros to recover final commands. Legacy XLM (Excel 4.0) macros live in macro sheets, not VBA, so olevba's VBA path won't decode them; XLMMacroDeobfuscator interprets/emulates the cell formulas to reveal the real logic (https://github.com/DissectMalware/XLMMacroDeobfuscator).
```bash
xlmdeobfuscator --file exercise/sample.xls
```
Expected: a step-by-step trace of evaluated cells ending in the recovered payload string (e.g. a URL or `EXEC`/`Shell` call). Nuance: because it emulates rather than statically greps, it defeats cell-splitting and formula-based obfuscation that fool simple string searches; supported inputs include `.xls`, `.xlsm`, and `.xlsb` (see the project README).

## Hands-on exercise
Work only against the artifacts in this module's `exercise/` directory.

**Sample declaration**
- `exercise/sample.doc` — a **Microsoft Word 97-2003 (OLE2) document** containing a benign, inert VBA macro that only pops a message box / writes a harmless string. It performs **no network egress and no file execution**.
- Origin: generated locally for training with a hand-written VBA `AutoOpen` sub; **benign/inert, no live malware**.
- sha256: `c8d6b1b7db3374b5e29ff0e9417501b18194b21af9bfe698f4376126899f3c37`

**Tasks**
1. Confirm the document contains a macro and identify the auto-exec trigger.
2. Dump the macro stream by index using `oledump.py`.
3. List every suspicious keyword `olevba` flags and record the decoded string.
4. Compute and record the sha256 of the sample and confirm it matches the declaration.

## SOC analyst perspective
Malicious documents are a leading phishing payload, so defenders must rapidly decide whether an attachment is weaponized. Running `oleid`/`olevba` on a quarantined attachment surfaces auto-exec macros (`AutoOpen`, `Document_Open`, `Workbook_Open`) and decoded URLs/commands that become detection IOCs (olevba's ANALYSIS table explicitly labels `AutoExec`, `Suspicious`, and `IOC` rows — https://github.com/decalage2/oletools/wiki/olevba).

**Concrete detection logic and pivots (Security Onion):**
- **Extract IOCs, then pivot in Zeek.** Take any URL/domain olevba decodes and search Zeek `http.log` (`host`, `uri`) and `dns.log` (`query`) in Kibana to find which internal hosts resolved/fetched the second stage. Zeek `files.log` (with the file-extraction framework enabled) gives you the SHA256/MIME of downloaded objects to correlate against your extracted hash. See Security Onion docs: https://docs.securityonion.net/en/2.4/zeek.html.
- **Suricata alerts.** Correlate the timeframe with Suricata signatures for document-borne downloaders in the Alerts dashboard; Suricata is the IDS/NSM alerting engine in Security Onion (https://docs.securityonion.net/en/2.4/suricata.html).
- **Host telemetry pattern to hunt.** The highest-fidelity behavioral tell is an Office process spawning a scripting host — e.g. `winword.exe`/`excel.exe` → `powershell.exe`/`cmd.exe`/`wscript.exe` (Sysmon Event ID 1, process create — https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon). Turn decoded strings into Sigma/YARA and push into hunt queries.

**MITRE ATT&CK mapping used for scoping:** T1566.001 (Spearphishing Attachment), T1204.002 (User Execution: Malicious File), T1059.001 (PowerShell) / T1059.003 (Windows Command Shell), and T1027 (Obfuscated Files or Information). These let the IR team scope the intrusion and write detection coverage. (Technique pages linked in Sources.)

## Attacker perspective
Attackers embed VBA or Excel 4.0 (XLM) macros that trigger on open (`AutoOpen`, `Document_Open`, `Workbook_Open`) to run a downloader or spawn PowerShell/`cmd` (this user-triggered execution is T1204.002 — https://attack.mitre.org/techniques/T1204/002/, delivered via T1566.001 — https://attack.mitre.org/techniques/T1566/001/). They obfuscate strings (char-code math, base64, string concatenation, XLM cell-splitting) to evade AV signatures, which maps to T1027, Obfuscated Files or Information (https://attack.mitre.org/techniques/T1027/). PDFs are abused with `/OpenAction` + `/JavaScript` or embedded `/Launch` actions so that opening the file auto-executes script.

**Artifacts the technique leaves behind:**
- The OLE2/OOXML document itself carries macro streams and metadata recoverable with `oleid`, `olemeta`, and `oledump.py` (macro streams flagged `M`).
- Behaviorally, Office spawning a scripting interpreter is visible as a parent→child process chain in EDR/Sysmon (Event ID 1 — https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon), mapping to T1059.001/T1059.003 (https://attack.mitre.org/techniques/T1059/001/, https://attack.mitre.org/techniques/T1059/003/).
- Downloaded stagers commonly land in `%TEMP%` / user profile paths, and the fetch is observable in network telemetry (Zeek `http.log`/`dns.log`).

**Evasion:** decoded strings and the file hash are still evidence a defender can pivot on, but attackers reduce that signal by encrypting the document (password-protected OLE, which `oleid` flags as encrypted), by using benign-looking template-injection remote loads, and by heavy formula/string obfuscation that static grep misses — which is exactly why emulation-based tooling (XLMMacroDeobfuscator) and olevba's `--decode` deobfuscation exist.

## Answer key
- Sample sha256: `c8d6b1b7db3374b5e29ff0e9417501b18194b21af9bfe698f4376126899f3c37`
- Verify integrity:
```bash
sha256sum exercise/sample.doc
```
Expected: hash equals the declared value above.
- Confirm macro + auto-exec trigger:
```bash
olevba exercise/sample.doc | grep -E "AutoExec|AutoOpen|Suspicious"
```
Expected: an `AutoExec` row for `AutoOpen` (runs when the document is opened) in the analysis table. (olevba labels auto-execution triggers as `AutoExec` — https://github.com/decalage2/oletools/wiki/olevba.)
- Dump the macro stream:
```bash
oledump.py exercise/sample.doc
oledump.py -s 3 -v exercise/sample.doc
```
Expected: the stream listing marks the macro stream with `M`; `-s 3 -v` prints the decompressed benign VBA (message box / harmless string, no network or execution calls). (Stream markers and `-s`/`-v` behavior per https://blog.didierstevens.com/programs/oledump-py/.)

## MITRE ATT&CK & DFIR phase
- **T1566.001** — Phishing: Spearphishing Attachment (initial access). https://attack.mitre.org/techniques/T1566/001/
- **T1204.002** — User Execution: Malicious File. https://attack.mitre.org/techniques/T1204/002/
- **T1059.001 / T1059.003** — Command and Scripting Interpreter (PowerShell / Windows Command Shell) commonly launched by macros. https://attack.mitre.org/techniques/T1059/001/ , https://attack.mitre.org/techniques/T1059/003/
- **T1027** — Obfuscated Files or Information (macro/XLM obfuscation). https://attack.mitre.org/techniques/T1027/
- **DFIR phase:** Identification and Examination (triage of a suspicious attachment and static extraction of IOCs).

## Sources
Claim → source mapping (all URLs are official tool docs/repos, MITRE ATT&CK, Microsoft Learn, SANS, or recognized project docs):

- REMnux tool availability and invocation (`oledump.py`, `pdfid.py`, `pdf-parser.py`, oletools) — REMnux documents-analysis reference: https://docs.remnux.org/discover-the-tools/analyze+documents
- oletools suite overview and install (PyPI/GitHub) — https://github.com/decalage2/oletools/wiki
- oletools release/version line (0.60.x) — https://github.com/decalage2/oletools/releases
- `oleid` behavior (structure-only triage, VBA/encryption/embedded-object flags) — https://github.com/decalage2/oletools/wiki/oleid
- `olevba` behavior (VBA extraction, `--decode`, ANALYSIS categories `AutoExec`/`Suspicious`/`IOC`) — https://github.com/decalage2/oletools/wiki/olevba
- `oledump.py` behavior (stream listing, `M`/`m` markers, `-s`/`-v` flags) — https://blog.didierstevens.com/programs/oledump-py/
- `pdfid.py` / `pdf-parser.py` behavior (keyword counting vs object walking, `--search`, `-o/-f/-d`) — https://blog.didierstevens.com/programs/pdf-tools/
- XLMMacroDeobfuscator (XLM emulation, supported formats, `--file`) — https://github.com/DissectMalware/XLMMacroDeobfuscator
- Sysmon Event ID 1 (process create) for Office→scripting-host detection — https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- Security Onion — Zeek (`http.log`/`dns.log`/`files.log` pivots) — https://docs.securityonion.net/en/2.4/zeek.html
- Security Onion — Suricata (IDS/NSM alerting) — https://docs.securityonion.net/en/2.4/suricata.html
- SANS FOR610 (Reverse-Engineering Malware) — https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/
- MITRE ATT&CK T1566.001 — https://attack.mitre.org/techniques/T1566/001/
- MITRE ATT&CK T1204.002 — https://attack.mitre.org/techniques/T1204/002/
- MITRE ATT&CK T1059.001 — https://attack.mitre.org/techniques/T1059/001/
- MITRE ATT&CK T1059.003 — https://attack.mitre.org/techniques/T1059/003/
- MITRE ATT&CK T1027 — https://attack.mitre.org/techniques/T1027/

## Related modules
- [oletools macro analysis deep-dive](../36-oletools-deep/README.md) -- shares oledump/olevba for deeper VBA extraction.
- [PDF analysis (pdfid / pdf-parser)](../37-pdf-analysis/README.md) -- shares pdf-parser for full PDF object-graph work.
- [Scenario: phishing document investigation](../48-phishing-doc-case/README.md) -- shares oletools in an end-to-end case.
- [Disk & filesystem forensics](../01-disk-forensics/README.md) -- same learning path (Foundations).

<!-- cyberlab-enriched: v1 -->
