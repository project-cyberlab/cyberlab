# 04 * Registry analysis -- LAB-LINUX

## Overview (plain language)
The Windows Registry is a giant built-in database where Windows and its programs store settings — things like which programs run at startup, what USB devices were plugged in, recently opened files, and account details. When investigators grab a Windows disk image, they pull out the raw "registry hive" files (SYSTEM, SOFTWARE, NTUSER.DAT, and others). These files are not plain text, so you need special tools to read them. The tools in this module — RegRipper and libregf-tools — let you open those hive files on a Linux analysis box and turn them into readable reports, without ever booting the suspect Windows machine. RegRipper runs a big library of plugins that automatically extract the forensically interesting settings, while libregf-tools lets you browse and export individual keys and values by hand.

Two things worth knowing up front. First, the on-disk hive files map to logical registry paths at runtime: SYSTEM → `HKLM\SYSTEM`, SOFTWARE → `HKLM\SOFTWARE`, and each user's `NTUSER.DAT` → `HKCU`. Microsoft documents these hive-to-file mappings, including that the default per-user hives live in the user profile directory as `NTUSER.DAT` (see Microsoft Learn, "Registry hives"). Second, every registry key carries a **last-write timestamp** (a Windows FILETIME), which is often the single most valuable forensic field because it tells you *when* a key was last modified — the file format itself is documented by the libregf project ("Windows NT Registry File (REGF) format").

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| RegRipper | apt install regripper | Plugin-driven parser that extracts forensic artifacts from Windows Registry hives into text reports |
| libregf-tools | apt install libregf-utils | Low-level utilities (regfinfo, regfexport, regfmount) to inspect and export raw Windows Registry hive files |

Notes on provenance:
- RegRipper is authored by Harlan Carvey; the current major release is RegRipper 3.0, distributed as `rip.pl` (Perl) with a plugin directory. Packaging as `regripper` and the `rip.pl` entry point is provided by the tool's Debian/Kali packaging (kali.org/tools/regripper). Source of truth: https://github.com/keydet89/RegRipper3.0
- libregf-tools ships the `regfinfo`, `regfexport`, and `regfmount` command-line utilities as part of Joachim Metz's libyal `libregf` project. On Debian/Ubuntu the binaries are packaged in `libregf-utils`. Source of truth: https://github.com/libyal/libregf

## Learning objectives
- Verify RegRipper and libregf-tools are installed and runnable on LAB-LINUX.
- Use `regfinfo` and `regfexport` to inspect the structure and contents of a raw registry hive.
- Run RegRipper against a hive and select relevant plugins to extract persistence and system artifacts.
- Interpret extracted keys (e.g. Run keys, computer name) and map them to MITRE ATT&CK techniques.

## Environment check
```bash
# Prove RegRipper is present (prints usage/version banner)
rip.pl -h

# Prove libregf-tools are present
regfinfo -V
regfexport -V
```
Expected output: `rip.pl -h` prints the RegRipper usage banner listing options such as `-r` (path to the hive to parse), `-f` (run a profile/list of plugins for a hive type), and `-p` (run a single named plugin). These options are documented in the RegRipper 3.0 usage output and README (https://github.com/keydet89/RegRipper3.0). `regfinfo -V` and `regfexport -V` each print a version line — libregf releases are date-stamped, so the version looks like `regfinfo 20240421` (the exact number tracks whatever `libregf-utils` build is installed; the format is documented at https://github.com/libyal/libregf). If `rip.pl` is not on `PATH`, the Kali/Debian package also exposes it as `regripper`; confirm the package with `dpkg -l regripper libregf-utils`.

## Guided walkthrough
1. `regfinfo` — reports hive metadata (file type, format version, and root key) to confirm the file is a valid hive before you trust anything you extract from it. Running this first is a chain-of-custody habit: if the header is corrupt or the file was truncated during acquisition, you want to know *now* rather than after building conclusions on garbage.
```bash
regfinfo exercise/SYSTEM_sample.hive
```
Expected: a summary showing the file signature `regf`, the major/minor format version, and the root key. A valid REGF file begins with the ASCII magic `regf`; `regfinfo` reads and reports this along with version fields exactly as defined in the libregf REGF format documentation (https://github.com/libyal/libregf/blob/main/documentation/Windows%20NT%20Registry%20File%20(REGF)%20format.asciidoc). Nuance: `regfinfo` parses the *header and base block*, so a clean summary tells you the container is well-formed — it does not by itself prove every cell/subkey is intact.

2. `regfexport` — dumps the full key/value tree as text so you can grep for specific keys. This is the "read everything, then filter" approach; it is tool-agnostic (no plugin has to exist) and preserves each key's last-write time in the output, which is the forensic field you usually care about most.
```bash
regfexport exercise/SYSTEM_sample.hive > /tmp/system_dump.txt
grep -i "ComputerName" /tmp/system_dump.txt | head
```
Expected: lines showing the `ControlSet\Control\ComputerName\ComputerName` value with the host name string. Nuance: SYSTEM hives contain multiple control sets (`ControlSet001`, `ControlSet002`, …) plus a volatile `CurrentControlSet` that only exists at runtime; when parsing an offline hive you read the numbered set that `Select\Current` points to (Microsoft Learn, "ControlSet\Select"). That is why you may see more than one `ComputerName` path in the dump.

3. `rip.pl` with a targeted plugin — RegRipper's `compname` plugin pulls the computer name in one step, resolving the correct ControlSet for you. Running a single plugin (`-p`) instead of a full profile (`-f`) keeps output focused and is the fastest way to answer a specific question.
```bash
rip.pl -r exercise/SYSTEM_sample.hive -p compname
```
Expected: RegRipper prints the plugin header (name/version), the source key path it read, and the recovered computer name value. Nuance: RegRipper plugins are hive-type specific — `compname` is a SYSTEM-hive plugin, so pointing it at SOFTWARE or NTUSER.DAT will produce no result. Plugin selection and the `-r`/`-p`/`-f` options are documented in the RegRipper 3.0 README (https://github.com/keydet89/RegRipper3.0).

## Hands-on exercise
Task: Using the benign sample hive in this module's `exercise/` directory, determine (a) the computer name stored in the SYSTEM hive and (b) confirm the hive parses as a valid `regf` file.

Sample declaration:
- Type: Windows Registry SYSTEM hive fragment (raw `regf` file).
- Safe origin: Generated inside a disposable Windows sandbox VM by exporting a stock SYSTEM hive, then trimmed for size. It is benign/inert data only — it contains no executable code, no malware, and no network egress occurs when parsing it.
- Filename: `exercise/SYSTEM_sample.hive`
- sha256: `4bb9288b72efda173d0c86ac07166d80290ebd55197d9ef413a6cf536d14369c`

Steps: run `regfinfo` to confirm the signature, then use either `regfexport | grep ComputerName` or `rip.pl -p compname` to recover the computer name.

## SOC analyst perspective
Registry analysis is a core examination step during Windows incident response (SANS FOR508 covers Windows Registry and persistence analysis in depth — https://www.sans.org/cyber-security-courses/advanced-incident-response-threat-hunting/). Defenders parse SYSTEM/SOFTWARE/NTUSER hives to hunt persistence:

- **Autostart / Run keys — T1547.001.** RegRipper's `run` plugin surfaces `Software\Microsoft\Windows\CurrentVersion\Run` and `RunOnce` (per-user in NTUSER.DAT, per-machine in SOFTWARE). The ATT&CK page for T1547.001 lists these exact key paths (https://attack.mitre.org/techniques/T1547/001/).
- **Services — T1543.003.** The `services` plugin enumerates `ControlSet00x\Services`; look for a service whose `ImagePath` points to a user-writable directory, an unsigned binary, or `cmd.exe`/`powershell.exe`, and a `Start` value of `2` (auto-start). Key path and behavior per ATT&CK T1543.003 (https://attack.mitre.org/techniques/T1543/003/).
- **Winlogon — T1547.004.** The `winlogon` plugin reads `Software\Microsoft\Windows NT\CurrentVersion\Winlogon`; abnormal `Shell` or `Userinit` values indicate persistence (ATT&CK T1547.004, https://attack.mitre.org/techniques/T1547/004/).

Detection logic and Security Onion pivots:
- **Sysmon Event ID 13** (RegistryEvent — value set) and **Event ID 12** (key create/delete) are the live-telemetry counterparts to what you confirm offline; Microsoft documents these IDs at https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon. In Security Onion these events land in Elastic and are searchable in Kibana/Hunt — pivot with `event.module:sysmon and winlog.event_id:13` and filter on `registry.path` containing `\CurrentVersion\Run` or `\Services\`.
- **Zeek/Suricata** won't see registry writes directly, but the *payload retrieval or C2* that a Run-key implant triggers is visible: pivot from the host to its `conn.log`/`http.log`/`dns.log` in Security Onion (https://docs.securityonion.net/) around the key's last-write time.
- Correlate the extracted key path, value data, and hive/key last-write time against Security Onion timeline data to scope the intrusion and build a detection for the observed persistence key across the estate.

## Attacker perspective
Attackers routinely abuse the Registry for persistence and defense evasion. Concrete TTPs and the artifacts they leave:

- **Run/RunOnce keys (T1547.001).** Write a payload path into `HKCU\...\CurrentVersion\Run` (no admin needed) or `HKLM\...\Run` (admin). Artifact: a new value under the Run key whose data is a binary path or a `powershell -enc` command line; the key's last-write timestamp brackets the compromise. ATT&CK T1547.001 (https://attack.mitre.org/techniques/T1547/001/).
- **Malicious service (T1543.003).** Create a key under `ControlSet00x\Services\<name>` with an `ImagePath` and `Start=2`. Artifact: new service subkey with recent last-write time; frequently paired with a masquerading service name. ATT&CK T1543.003 (https://attack.mitre.org/techniques/T1543/003/).
- **Fileless / encoded storage (T1112 Modify Registry, T1027 Obfuscated Files or Information).** Stash a base64 or gzip blob in an obscure value and load it at runtime, avoiding a payload on disk. Artifact: an oversized/binary value in an unusual location. ATT&CK T1112 (https://attack.mitre.org/techniques/T1112/) and T1027 (https://attack.mitre.org/techniques/T1027/).

Evasion and its limits: attackers may hide values by using long/whitespace-padded names, place data in non-standard subkeys, or delete the on-disk payload afterward. However, because these writes persist inside the hive files, an analyst using RegRipper or `regfexport` can recover the exact malicious value **and** its key last-write time even after the attacker deletes the on-disk payload — the REGF format stores per-key FILETIME timestamps (https://github.com/libyal/libregf). Timestamp anti-forensics is possible but leaves the hive internally inconsistent, which is itself a lead.

## Answer key
Expected findings:
- The hive is a valid `regf` file (regfinfo prints the `regf` signature and version), confirming (b).
- The computer name value is recoverable via the SYSTEM hive.

Exact commands:
```bash
regfinfo exercise/SYSTEM_sample.hive
rip.pl -r exercise/SYSTEM_sample.hive -p compname
regfexport exercise/SYSTEM_sample.hive | grep -i "ComputerName"
sha256sum exercise/SYSTEM_sample.hive
```
`regfinfo` confirms the `regf` signature; `rip.pl -p compname` and the `regfexport | grep` both return the ComputerName value from `ControlSet001\Control\ComputerName\ComputerName`. The `sha256sum` output must equal `4bb9288b72efda173d0c86ac07166d80290ebd55197d9ef413a6cf536d14369c`.

## MITRE ATT&CK & DFIR phase
- T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder — https://attack.mitre.org/techniques/T1547/001/
- T1547.004 — Boot or Logon Autostart Execution: Winlogon Helper DLL — https://attack.mitre.org/techniques/T1547/004/
- T1543.003 — Create or Modify System Process: Windows Service — https://attack.mitre.org/techniques/T1543/003/
- T1112 — Modify Registry — https://attack.mitre.org/techniques/T1112/
- T1027 — Obfuscated Files or Information (encoded data stored in registry values) — https://attack.mitre.org/techniques/T1027/
- DFIR phase: Examination / Analysis (offline parsing of acquired hives), feeding Identification and Scoping.

## Sources
Claim → source mapping (all URLs are real, authoritative pages):

- RegRipper `rip.pl`, options `-r`/`-p`/`-f`, plugin model, `compname`/`run`/`services`/`winlogon` plugins — https://github.com/keydet89/RegRipper3.0
- RegRipper Debian/Kali packaging (`regripper`, `rip.pl` entry point) — https://www.kali.org/tools/regripper/
- libregf-tools (`regfinfo`, `regfexport`, `regfmount`), version string format, per-key FILETIME timestamps — https://github.com/libyal/libregf
- REGF file format, `regf` magic/signature and header/version fields — https://github.com/libyal/libregf/blob/main/documentation/Windows%20NT%20Registry%20File%20(REGF)%20format.asciidoc
- Windows Registry hives and hive-to-file mapping (SYSTEM/SOFTWARE/NTUSER.DAT → HKLM/HKCU) — https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives
- ControlSet / `Select\Current` and CurrentControlSet behavior — https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/control-sets-registry
- Sysmon Event ID 12 (registry key create/delete) and Event ID 13 (registry value set) — https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- Security Onion (Elastic/Kibana Hunt, Zeek, Suricata) analyst workflow and logs — https://docs.securityonion.net/
- SANS FOR508 — Windows Registry and persistence analysis coverage — https://www.sans.org/cyber-security-courses/advanced-incident-response-threat-hunting/
- SANS DFIR, Windows Registry forensics resources — https://www.sans.org/blog/digital-forensics-registry/
- MITRE ATT&CK T1547.001 — https://attack.mitre.org/techniques/T1547/001/
- MITRE ATT&CK T1547.004 — https://attack.mitre.org/techniques/T1547/004/
- MITRE ATT&CK T1543.003 — https://attack.mitre.org/techniques/T1543/003/
- MITRE ATT&CK T1112 — https://attack.mitre.org/techniques/T1112/
- MITRE ATT&CK T1027 — https://attack.mitre.org/techniques/T1027/

## Related modules
- [Scenario: intrusion timeline reconstruction](../49-intrusion-timeline-case/README.md) -- shares regripper for registry-based persistence and timeline pivots.
- [Disk & filesystem forensics](../01-disk-forensics/README.md) -- same learning path (Foundations); where you acquire the image the hives come from.
- [Memory forensics](../02-memory-forensics/README.md) -- same learning path (Foundations); recovers registry data resident in RAM.
- [Timeline / super-timelining](../03-timeline-analysis/README.md) -- same learning path (Foundations); fold registry key last-write times into a super-timeline.

<!-- cyberlab-enriched: v1 -->
