# 48 * Scenario: phishing document investigation -- LAB-LINUX

## Overview (plain language)
Attackers love sending everyday-looking files — a Word invoice, a PDF resume, an Excel spreadsheet — that secretly contain instructions to download and run malware. This module teaches you to safely pull apart those suspicious documents on an offline analysis machine, without ever opening them in the real Office or Adobe apps. You will use **oletools** to peek inside Office documents and read hidden macros, **pdf-parser** to inspect the guts of a PDF and find suspicious actions or embedded JavaScript, and **CyberChef** to decode the scrambled (obfuscated) text those documents use to hide the real web address or command. Think of it as carefully unwrapping a booby-trapped package with tongs behind glass, so you can see how it works and where it phones home — all without letting it hurt anything.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| oletools | apt install oletools | Analyze OLE/Office documents; extract and triage VBA macros (olevba, oleid, oledump) |
| pdf-parser | apt install pdf-parser | Parse PDF objects, streams, and actions; surface JavaScript, OpenAction, and embedded files |
| CyberChef | (bundled on REMnux; run in browser) | Decode/deobfuscate strings (Base64, XOR, URL, gunzip) extracted from documents |

## Learning objectives
- Triage an Office document with `oleid` and `olevba` to identify auto-execution macros and suspicious keywords.
- Enumerate PDF objects with `pdf-parser` to locate `/OpenAction`, `/JavaScript`, and `/URI` entries.
- Extract obfuscated payload strings from a macro/PDF and decode them using a repeatable CyberChef recipe.
- Produce a concise IOC list (URLs, dropped filenames) suitable for a SOC ticket.

## Environment check
```bash
# Prove the Office/PDF static-analysis tools are installed on LAB-LINUX
olevba --version
oleid --version
pdf-parser.py --version
echo "CyberChef is available on REMnux at file:///opt/cyberchef/CyberChef.html"
```
Expected output: `olevba` and `oleid` print their oletools version (e.g. `olevba 0.60.x on Python 3.x`), `pdf-parser.py` prints its version banner (e.g. `pdf-parser.py, version 0.7.x`), and the echo confirms the local CyberChef path.

## Guided walkthrough
1. `oleid` — quick indicator scan that flags VBA macros, Flash, encryption, and other risk indicators.
```bash
oleid exercise/invoice_sample.doc
```
Expected: a table of indicators; the "VBA Macros" row shows `True` / value `Yes` when macros are present.

2. `olevba` — dump and triage VBA macro source, highlighting auto-exec and suspicious calls.
```bash
olevba --decode exercise/invoice_sample.doc
```
Expected: the macro source prints, followed by a summary table listing keywords such as `AutoOpen`, `Shell`, and any `Base64 String` the decoder recovered.

3. `pdf-parser.py` — search the PDF for auto-triggered actions and scripts.
```bash
pdf-parser.py --search OpenAction exercise/resume_sample.pdf
pdf-parser.py --type /JavaScript exercise/resume_sample.pdf
```
Expected: object numbers referencing `/OpenAction` and any `/JavaScript` objects, revealing the code that runs on open.

4. Decode the recovered string with CyberChef using a repeatable recipe (From Base64 → Decode text/URL Decode). To verify from the command line first:
```bash
echo 'aHR0cDovLzIwMy4wLjExMy4xMC9wYXkuZXhl' | base64 -d; echo
```
Expected: `http://203.0.113.10/pay.exe` — the same result you would obtain by pasting the string into CyberChef's "From Base64" operation.

## Hands-on exercise
Analyze the two benign samples in this module's `exercise/` directory and extract the hidden C2 URL.

**Sample declaration**
- `exercise/invoice_sample.doc` — a benign, inert OLE Word document containing a harmless `AutoOpen` VBA macro that only stores (never executes) a Base64 string. No live malware, no network egress.
- `exercise/resume_sample.pdf` — a benign PDF with an `/OpenAction`/`/JavaScript` object that contains only a Base64-encoded URL string (no exploit, no shellcode).

Both samples are **generated locally** by the reproducible commands in the Answer key, so no live malicious binary is ever downloaded. Run analysis in an isolated VM with networking disabled.

**Task:** Identify the auto-exec trigger in the DOC, locate the JavaScript object in the PDF, extract the Base64 blob from each, decode it, and report the resulting URL(s) and dropped filename as IOCs.

## SOC analyst perspective
A defender treats a reported phishing attachment as the "identification" trigger of an incident. Using oletools and pdf-parser on an isolated host lets an analyst confirm whether a macro auto-executes (`AutoOpen`, `Document_Open`) or a PDF fires an `/OpenAction`, then extract the C2 URL and dropped filename as IOCs. Those IOCs feed detection: in Security Onion you pivot on the extracted domain/IP across Zeek `http.log` and `dns.log`, hunt for the dropped filename in Sysmon/EDR process-creation events, and write or tune Suricata/YARA rules. This maps to MITRE ATT&CK T1566.001 (Spearphishing Attachment) and T1204.002 (User Execution: Malicious File), letting the SOC scope who else received or opened the lure and block the infrastructure before the second-stage payload lands.

## Attacker perspective
Adversaries weaponize documents because they arrive through trusted email flows and rely on the victim to click "Enable Content." A macro uses `AutoOpen`/`Document_Open` (T1137/T1204.002) to run on open, often calling `Shell`, `WScript.Shell`, or `powershell -enc`, with the real URL hidden via Base64, XOR, or string concatenation (T1027) to evade static scanners. PDFs abuse `/OpenAction` plus `/JavaScript` to trigger downloads. The tradecraft leaves recoverable artifacts: VBA project streams inside the OLE container, `/OpenAction` and `/JS` keys in the PDF cross-reference, embedded encoded strings, and — once detonated — child-process trees, temp-folder drops, and outbound HTTP to staging infrastructure that defenders can hunt.

## Answer key
**Generate the benign samples (reproducible, no live malware):**
```bash
mkdir -p exercise
# Benign PDF with OpenAction + JavaScript holding a Base64 URL string
cat > exercise/resume_sample.pdf <<'EOF'
%PDF-1.4
1 0 obj<< /Type /Catalog /OpenAction 2 0 R >>endobj
2 0 obj<< /Type /Action /S /JavaScript /JS (var u="aHR0cDovLzIwMy4wLjExMy4xMC9wYXkuZXhl";) >>endobj
trailer<< /Root 1 0 R >>
%%EOF
EOF
# Benign OLE doc stand-in carrying the same encoded URL (inert text)
printf 'Sub AutoOpen()\n b = "aHR0cDovLzIwMy4wLjExMy4xMC9wYXkuZXhl"\nEnd Sub\n' > exercise/invoice_sample.doc
sha256sum exercise/resume_sample.pdf exercise/invoice_sample.doc
```

**Expected findings and the commands that produce them:**
```bash
# 1) Auto-exec macro trigger in the DOC
olevba exercise/invoice_sample.doc | grep -i AutoOpen
# -> shows AutoOpen (auto-executes when document is opened)

# 2) PDF auto-action and JavaScript object
pdf-parser.py --search OpenAction exercise/resume_sample.pdf
pdf-parser.py --type /JavaScript exercise/resume_sample.pdf
# -> object 2 with /S /JavaScript and the encoded string

# 3) Decode the extracted Base64 IOC (equivalent to CyberChef "From Base64")
echo 'aHR0cDovLzIwMy4wLjExMy4xMC9wYXkuZXhl' | base64 -d; echo
# -> http://203.0.113.10/pay.exe
```
**IOCs:** URL `http://203.0.113.10/pay.exe`; dropped filename `pay.exe`; host `203.0.113.10`.

Record the printed `sha256sum` values from the generator above as the authoritative digests for your copies of `resume_sample.pdf` and `invoice_sample.doc` (they are regenerated deterministically by the commands shown).

## MITRE ATT&CK & DFIR phase
- **T1566.001** — Phishing: Spearphishing Attachment (initial access vector).
- **T1204.002** — User Execution: Malicious File (macro/PDF requires victim to open).
- **T1137** — Office Application Startup / macro auto-execution.
- **T1027** — Obfuscated Files or Information (Base64/XOR-encoded URL).
- **T1059.001 / T1059.005** — Command & Scripting Interpreter (PowerShell / VBScript payload staging).
- **DFIR phases:** Identification (triage the reported attachment) and Examination/Analysis (static macro/PDF dissection and IOC extraction).

## Sources
- oletools documentation (olevba/oleid), Decalage: https://github.com/decalage2/oletools/wiki
- Didier Stevens, pdf-parser: https://blog.didierstevens.com/programs/pdf-tools/
- CyberChef (GCHQ): https://gchq.github.io/CyberChef/ and https://github.com/gchq/CyberChef
- REMnux documentation — document analysis tools: https://docs.remnux.org/discover-the-tools/analyze+documents
- SANS FOR610 — Reverse-Engineering Malware / malicious document analysis: https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/
- MITRE ATT&CK T1566.001: https://attack.mitre.org/techniques/T1566/001/
- MITRE ATT&CK T1204.002: https://attack.mitre.org/techniques/T1204/002/
- MITRE ATT&CK T1027: https://attack.mitre.org/techniques/T1027/