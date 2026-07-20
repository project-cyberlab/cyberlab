# 49 * Scenario: intrusion timeline reconstruction -- LAB-LINUX

## Overview (plain language)
When an attacker breaks into a computer, they leave behind a trail: files get created, programs run, registry keys change, and logins happen. Timeline reconstruction is the detective work of putting all those events in the correct order so you can tell the story of what happened, when, and how. This module uses three tools to build that story from a disk image. Plaso (log2timeline) automatically gathers timestamps from hundreds of sources into one big timeline. The Sleuth Kit reads the raw filesystem so you can see files and their creation/modification/access times directly. RegRipper pulls meaningful facts out of Windows registry hives, like which programs auto-start or which USB devices were plugged in. Together they turn a confusing pile of data into a readable, minute-by-minute account of an intrusion.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| Plaso | apt install plaso | Automated super-timeline creation (log2timeline/psort) across many artifact types |
| RegRipper | apt install regripper | Parse Windows registry hives into human-readable forensic findings |
| Sleuth Kit | apt install sleuthkit | Command-line filesystem forensics: list files, recover deleted data, produce timelines |

> Note on install: Plaso's own maintainers recommend the [GIFT PPA / official install methods](https://plaso.readthedocs.io/en/latest/sources/user/Installation-instructions.html) or Docker over distro `apt` packages, which can lag behind releases. On the SANS SIFT Workstation and REMnux, Plaso, The Sleuth Kit, and RegRipper are pre-installed (see [SIFT](https://www.sans.org/tools/sift-workstation/) and [remnux.org tools](https://docs.remnux.org/discover-the-tools)).

## Learning objectives
- Generate a Plaso storage file from a disk image and export a filtered CSV super-timeline.
- Use Sleuth Kit (`fls`/`mactime`) to produce a filesystem MAC-time bodyfile and timeline.
- Extract autostart and USB artifacts from a registry hive with RegRipper and place them on the timeline.
- Correlate events from all three tools to reconstruct the sequence of an intrusion.
- Identify the DFIR examination phase and map findings to MITRE ATT&CK techniques.

## Environment check
```bash
# Prove the three tools are installed on LAB-LINUX (SIFT)
log2timeline.py --version
psort.py --version
fls -V
mactime -V
rip.pl -h | head -n 3
```
Expected output: Plaso prints its version (e.g. `plaso - log2timeline version 20230717`), `fls`/`mactime` print The Sleuth Kit version banner, and `rip.pl -h` prints RegRipper usage text.

Notes on the commands above (each flag verified against tool docs):
- `log2timeline.py --version` and `psort.py --version` — the `--version` argument is documented for the Plaso frontends ([Plaso log2timeline.py docs](https://plaso.readthedocs.io/en/latest/sources/user/Using-log2timeline.html), [psort.py docs](https://plaso.readthedocs.io/en/latest/sources/user/Using-psort.html)).
- `fls -V` and `mactime -V` — `-V` prints The Sleuth Kit version for both tools ([TSK fls man page](https://www.sleuthkit.org/sleuthkit/man/fls.html), [TSK mactime man page](https://www.sleuthkit.org/sleuthkit/man/mactime.html)).
- `rip.pl -h` — RegRipper's CLI (`rip.pl`) prints usage/help; see the [RegRipper repo](https://github.com/keydet89/RegRipper3.0). On some packagings the executable is `rip.pl`/`rip`; confirm with the packaged docs.

## Guided walkthrough
1. `fls` walks the filename layer of a filesystem and prints file/directory entries with their inode and MAC times; the `-m` option emits output in the **bodyfile** (TSK 3.x `mactime`) format, which `mactime` then sorts into a chronological timeline. We run this first because filesystem metadata is the most direct, least-abstracted timeline source and is available even when higher-level logs are missing.
```bash
# Build a Sleuth Kit bodyfile from a raw image, then a mactime timeline
IMAGE=disk.raw
fls -r -m C: -o 2048 "$IMAGE" > bodyfile.txt
mactime -b bodyfile.txt -d 2024-01-01 > sk_timeline.csv
head -n 5 sk_timeline.csv
```
Why each flag matters (per the [fls man page](https://www.sleuthkit.org/sleuthkit/man/fls.html)):
- `-r` recurses into subdirectories so you capture the whole tree, not just the root.
- `-m C:` prepends the mount point string (here `C:`) to each path in the bodyfile so the resulting timeline paths read like Windows paths.
- `-o 2048` is the **sector offset** to the start of the partition within the image. `2048` is a common first-partition offset but is image-specific — confirm it with `mmls "$IMAGE"` before trusting it, or `fls` will read the wrong volume.

For `mactime` (per the [mactime man page](https://www.sleuthkit.org/sleuthkit/man/mactime.html)):
- `-b bodyfile.txt` supplies the bodyfile to sort.
- `-d` produces comma-delimited (CSV) output; the trailing `2024-01-01` restricts the timeline to on/after that date. Output is in the host/`TZ` timezone unless you pass `-z`.

Expected output: `bodyfile.txt` contains pipe-delimited lines in TSK bodyfile format — `MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime` (the MD5 field is `0` when hashing is not requested). `sk_timeline.csv` shows date-sorted rows with a MACB column indicating which of the four timestamps fired for each entry.

2. `log2timeline.py` runs Plaso's parsers/plugins across the image and writes events into a `.plaso` storage file (an SQLite database); `psort.py` then post-processes, sorts, de-duplicates, filters, and exports that storage file. We separate collection (`log2timeline.py`) from output (`psort.py`) so you can extract once and re-query many time windows/output formats without re-parsing the image.
```bash
# Create the Plaso super-timeline, then export a date-scoped CSV
IMAGE=disk.raw
log2timeline.py --storage-file timeline.plaso "$IMAGE"
psort.py -o l2tcsv -w super_timeline.csv timeline.plaso \
  "date > '2024-01-10 00:00:00' AND date < '2024-01-12 00:00:00'"
wc -l super_timeline.csv
```
Why each flag matters (per [Using log2timeline.py](https://plaso.readthedocs.io/en/latest/sources/user/Using-log2timeline.html) and [Using psort.py](https://plaso.readthedocs.io/en/latest/sources/user/Using-psort.html)):
- `--storage-file timeline.plaso` names the output storage file; the positional argument is the source (image, device, or directory). Plaso auto-detects storage-media images and iterates volumes/partitions.
- `psort.py -o l2tcsv` selects the classic l2t CSV output module; `-w super_timeline.csv` writes to that file.
- The trailing quoted string is a Plaso **event filter** expression restricting the export to a time window (see [Plaso filters / event-filters docs](https://plaso.readthedocs.io/en/latest/sources/user/Event-filters.html)). Scoping keeps a super-timeline (often millions of rows) manageable.

Expected output: `log2timeline.py` prints a processing summary (sources parsed, events extracted, warnings). `super_timeline.csv` holds l2tcsv rows for the scoped window; the l2tcsv header is `date,time,timezone,MACB,source,sourcetype,type,user,host,short,desc,version,filename,inode,notes,format,extra`.

3. `rip.pl` runs RegRipper plugins against a single registry hive to surface autostart and device artifacts. The registry is a rich, timestamped artifact store (key LastWrite times) that survives log clearing, so we mine it independently and merge findings onto the timeline.
```bash
# Extract autostart programs and USB device history from a registry hive
rip.pl -r NTUSER.DAT -p run
rip.pl -r SYSTEM -p usbstor
```
Why each flag matters (per the [RegRipper repo](https://github.com/keydet89/RegRipper3.0)):
- `-r NTUSER.DAT` / `-r SYSTEM` names the hive file to parse. Autostart Run/RunOnce keys live under both `NTUSER.DAT` (per-user `HKCU`) and `SOFTWARE` (`HKLM`); the `usbstor` data lives in `SYSTEM` (`ControlSet00x\Enum\USBSTOR`).
- `-p run` / `-p usbstor` selects a specific plugin. `run` reports the RuneKey persistence values; `usbstor` enumerates USB mass-storage device history with the subkey LastWrite times.

Expected output: RegRipper prints the plugin's findings — for `run`, the Run/RunOnce values (auto-start program paths) with the key LastWrite time; for `usbstor`, device class/serial entries with their LastWrite timestamps. Note that a Run key's LastWrite reflects the *last* modification to the key, not necessarily the moment a specific value was added.

## Hands-on exercise
Sample artifact: `exercise/intrusion_bodyfile.txt` — a **benign, inert Sleuth Kit bodyfile** (plain text, no executable content, no live malware). It is safely generated offline (no network egress) by the reproducible generator below, which fabricates a small MAC-time record simulating an attacker dropping `evil.exe` and modifying `hosts`.

Generator (run inside the module's `exercise/` dir):
```bash
cat > intrusion_bodyfile.txt <<'EOF'
0|C:/Windows/Temp/evil.exe|4128|r/rrwxrwxrwx|0|0|73216|1705032000|1705032000|1705032000|1705032000
0|C:/Windows/System32/drivers/etc/hosts|4130|r/rrwxrwxrwx|0|0|824|1705032600|1705032600|1704000000|1704000000
0|C:/Users/analyst/NTUSER.DAT|4200|r/rrwxrwxrwx|0|0|262144|1705033200|1705033200|1705033200|1704000000
EOF
sha256sum intrusion_bodyfile.txt
```
Tasks:
1. Convert the bodyfile into a human-readable timeline with `mactime`.
2. Identify the first-created suspicious file and its epoch/date.
3. Determine which file was modified but has an older creation time (indicating tampering).

## SOC analyst perspective
A defender uses timeline reconstruction during incident response to answer "patient zero and dwell time" questions. In Security Onion you typically start from an alert and pivot to the host disk image, then use Plaso/Sleuth Kit to stitch endpoint events into an order that matches network telemetry ([Security Onion docs](https://docs.securityonion.net/)).

Concrete detection logic and pivots:
- **Suricata alerts → host pivot.** A Suricata signature firing (e.g. malware C2 or exploit) gives you a timestamp and a host IP. In Security Onion, Suricata alerts and Zeek metadata are indexed in Elasticsearch and browsable via the Alerts/Dashboards interfaces ([Suricata in Security Onion](https://docs.securityonion.net/en/2.4/suricata.html)).
- **Zeek connection correlation.** Pivot on the host IP in `conn.log` (Zeek) around the payload's creation time to find the outbound connection that followed execution — this ties the filesystem crtime of `evil.exe` to a network event ([Zeek in Security Onion](https://docs.securityonion.net/en/2.4/zeek.html); [Zeek conn.log reference](https://docs.zeek.org/en/master/logs/conn.html)).
- **Registry persistence (T1547.001).** A Run-key value from RegRipper's `run` plugin, correlated with the `.exe` crtime and a subsequent outbound connection, confirms Registry Run Key/Startup Folder persistence ([ATT&CK T1547.001](https://attack.mitre.org/techniques/T1547/001/)). Microsoft's autoruns/registry references confirm the Run/RunOnce key locations ([Microsoft Learn: Run and RunOnce registry keys](https://learn.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys)).
- **Timestomp signal (T1070.006).** Watch for files where crtime is *later* than mtime, or where `$STANDARD_INFORMATION` and `$FILE_NAME` timestamps disagree — Plaso surfaces both via the NTFS `$MFT` parser, letting you flag manipulation ([ATT&CK T1070.006](https://attack.mitre.org/techniques/T1070/006/)).
- **USB introduction (T1091).** RegRipper `usbstor` LastWrite times placed on the timeline show when a device was first connected, relevant to removable-media replication ([ATT&CK T1091](https://attack.mitre.org/techniques/T1091/)).

Timelines also feed Security Onion case notes, help scope which hosts and time windows need containment, and provide a defensible chronology for reporting.

## Attacker perspective
An attacker leaves timestamps everywhere: dropping a payload updates a file's creation/modification MAC times, writing a Run key changes a hive's LastWrite time, and plugging a USB device registers a USBSTOR entry.

Concrete TTPs, artifacts, and evasion:
- **Timestomping (T1070.006).** Adversaries modify file timestamps to blend malware in with existing files, often overwriting `$STANDARD_INFORMATION` (`$SI`) times to look old ([ATT&CK T1070.006](https://attack.mitre.org/techniques/T1070/006/)). The catch: on NTFS the `$FILE_NAME` (`$FN`) attribute and the `$UsnJrnl`/`$LogFile` often retain the true times, and `$SI` timestamps rewritten by user-mode tools frequently lose sub-second precision — both signals Sleuth Kit's `$MFT` handling and Plaso's NTFS parser can surface (see [SANS DFIR Windows Forensic Analysis poster](https://www.sans.org/posters/windows-forensic-analysis/) and [The Sleuth Kit docs](https://www.sleuthkit.org/sleuthkit/docs.php)).
- **Registry Run-key persistence (T1547.001).** Writing to `HKCU\...\Run` or `HKLM\...\Run` leaves the payload path *and* updates the containing key's LastWrite time, an artifact RegRipper `run` reads directly ([ATT&CK T1547.001](https://attack.mitre.org/techniques/T1547/001/)).
- **Clearing event logs (T1070.001).** Adversaries run `wevtutil cl` or use APIs to wipe `.evtx` logs to destroy the login/process trail ([ATT&CK T1070.001](https://attack.mitre.org/techniques/T1070/001/)). But this leaves its own tells (a `1102` "log cleared" record before the gap), and registry LastWrite times and filesystem `$MFT` metadata survive, giving investigators independent artifacts to rebuild the true sequence of events.

## Answer key
Expected findings from the sample (`exercise/intrusion_bodyfile.txt`):
```bash
mactime -b exercise/intrusion_bodyfile.txt -d 2024-01-01 | head
```
- First suspicious file created: `C:/Windows/Temp/evil.exe` at epoch `1705032000` = **2024-01-12 04:00:00 UTC** (all four MAC times equal → freshly dropped).
- Tampered file: `C:/Windows/System32/drivers/etc/hosts` — modified at `1705032600` but with an older creation time `1704000000`, indicating the attacker altered an existing system file.
- The `NTUSER.DAT` entry shows a modification (`1705033200`) newer than its birth time (`1704000000`), consistent with a Run-key persistence write that RegRipper's `run` plugin would reveal.

Note: the bodyfile column order is `MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime` ([TSK mactime man page](https://www.sleuthkit.org/sleuthkit/man/mactime.html)), so the last field is the creation (crtime) time and the second-to-last is ctime; the epoch-to-UTC conversions above assume UTC (`mactime -z UTC`).

Sample sha256: reproduce with the generator's `sha256sum intrusion_bodyfile.txt`; the digest is held by the validator (regenerate deterministically from the provided heredoc, which produces identical bytes).

## MITRE ATT&CK & DFIR phase
- **T1547.001** — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder (RegRipper `run`) — https://attack.mitre.org/techniques/T1547/001/
- **T1070.006** — Indicator Removal: Timestomp (detected via MAC-time / `$SI` vs `$FN` inconsistencies) — https://attack.mitre.org/techniques/T1070/006/
- **T1070.001** — Indicator Removal: Clear Windows Event Logs — https://attack.mitre.org/techniques/T1070/001/
- **T1091** — Replication Through Removable Media / device history (RegRipper `usbstor`) — https://attack.mitre.org/techniques/T1091/
- **DFIR phase:** Examination and Analysis (timeline reconstruction / correlation) following Identification.

## Sources
Claim → source mapping (all URLs are real, authoritative pages):

- Plaso `log2timeline.py`/`psort.py` usage, `--version`, `--storage-file`, `-o l2tcsv`, `-w`, event filters:
  - https://plaso.readthedocs.io/
  - https://plaso.readthedocs.io/en/latest/sources/user/Using-log2timeline.html
  - https://plaso.readthedocs.io/en/latest/sources/user/Using-psort.html
  - https://plaso.readthedocs.io/en/latest/sources/user/Event-filters.html
  - Recommended install methods: https://plaso.readthedocs.io/en/latest/sources/user/Installation-instructions.html
- The Sleuth Kit `fls` (`-r`, `-m`, `-o`, `-V`), `mactime` (`-b`, `-d`, `-z`, `-V`) and bodyfile format:
  - https://www.sleuthkit.org/sleuthkit/man/fls.html
  - https://www.sleuthkit.org/sleuthkit/man/mactime.html
  - https://www.sleuthkit.org/sleuthkit/docs.php
- RegRipper (`rip.pl`, `-r`, `-p`, `run`/`usbstor` plugins):
  - https://github.com/keydet89/RegRipper3.0
- Windows Run / RunOnce registry key behavior (autostart persistence):
  - https://learn.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys
- SANS DFIR — log2timeline / super-timelining and Windows forensic timestamps:
  - https://www.sans.org/blog/digital-forensics-sifting-cheating-timelines-with-log2timeline/
  - https://www.sans.org/posters/windows-forensic-analysis/
- SANS SIFT Workstation (pre-installed tooling):
  - https://www.sans.org/tools/sift-workstation/
- REMnux tools listing:
  - https://docs.remnux.org/discover-the-tools
- Security Onion (Suricata/Zeek/Elastic pivots):
  - https://docs.securityonion.net/
  - https://docs.securityonion.net/en/2.4/suricata.html
  - https://docs.securityonion.net/en/2.4/zeek.html
- Zeek `conn.log` fields (network correlation):
  - https://docs.zeek.org/en/master/logs/conn.html
- MITRE ATT&CK techniques:
  - T1547.001 — https://attack.mitre.org/techniques/T1547/001/
  - T1070.006 — https://attack.mitre.org/techniques/T1070/006/
  - T1070.001 — https://attack.mitre.org/techniques/T1070/001/
  - T1091 — https://attack.mitre.org/techniques/T1091/

## Related modules
- [Scenario: end-to-end host triage](../51-linux-triage-workflow/README.md) -- shares Sleuth Kit for host-level filesystem triage.
- [Disk & filesystem forensics](../01-disk-forensics/README.md) -- shares Sleuth Kit for volume/partition and file recovery work.
- [Timeline / super-timelining](../03-timeline-analysis/README.md) -- shares Plaso for building and filtering super-timelines.
- [Registry analysis](../04-registry-analysis/README.md) -- shares RegRipper for deeper hive parsing.

<!-- cyberlab-enriched: v1 -->
