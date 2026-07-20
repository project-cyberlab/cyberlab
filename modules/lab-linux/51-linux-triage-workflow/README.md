# 51 * Scenario: end-to-end host triage -- LAB-LINUX

## Overview (plain language)
Imagine you get handed a copy of a suspicious computer's hard drive and you need to quickly figure out what happened without changing anything. This module walks through that "first look" — called triage — using three free tools. The Sleuth Kit lets you browse the files inside a disk image the way you'd look through drawers, including files that were deleted. bulk_extractor scans the whole image and pulls out interesting text like email addresses, URLs, and credit-card-shaped numbers, even from unallocated space. ClamAV is an antivirus scanner that flags known-bad files. Together they give you a fast, repeatable way to answer "is this host compromised, and what did the attacker touch?" before you commit to a deep investigation.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| Sleuth Kit | apt install sleuthkit | Command-line disk/filesystem forensics: list files, recover deleted entries, build timelines from an image |
| bulk_extractor | apt install bulk-extractor | Bulk feature carving (emails, URLs, IPs, PII) from raw images including slack/unallocated space |
| ClamAV | apt install clamav clamav-daemon | Open-source antivirus signature scanning of mounted/extracted files |

## Learning objectives
- Enumerate partitions and filesystem metadata from a raw disk image with `mmls` and `fsstat`.
- Recover file listings (including deleted inodes) using `fls` and extract file content with `icat`.
- Carve investigative features (emails, URLs, IPs) from an image with `bulk_extractor`.
- Signature-scan extracted content with `clamscan` and interpret hit/clean results.
- Produce a documented, reproducible triage sequence suitable for a SOC handoff ticket.

## Environment check
```bash
# Prove the three tools are installed on LAB-LINUX
fls -V
bulk_extractor -V
clamscan --version
```
Expected output: The Sleuth Kit prints a version banner (e.g. `The Sleuth Kit ver 4.12.1`), bulk_extractor prints `bulk_extractor 2.x.x`, and clamscan prints `ClamAV 1.x.x/...` including its virus database version.

## Guided walkthrough
1. `mmls` — display the partition table so you know where filesystems start.
```bash
mmls disk.raw
```
Expected observable: a table of slots with `Start` offsets and descriptions (e.g. an NTFS/FAT partition starting at sector 2048).

2. `fsstat` — read filesystem-level metadata for the partition at a chosen offset.
```bash
fsstat -o 2048 disk.raw
```
Expected observable: filesystem type, volume label, block/cluster size, and inode/root directory details.

3. `fls` — list files and directories, including deleted (`*`-marked) entries.
```bash
fls -o 2048 -r -p disk.raw
```
Expected observable: a recursive path listing; deleted entries appear with a leading `*` and their inode numbers.

4. `icat` — extract the content of a specific inode to disk.
```bash
icat -o 2048 disk.raw 5 > recovered_file.bin
```
Expected observable: the file's raw bytes are written to `recovered_file.bin`.

5. `bulk_extractor` — carve features from the whole image into an output directory.
```bash
bulk_extractor -o be_out disk.raw
```
Expected observable: a `be_out/` directory containing `email.txt`, `url.txt`, `ip.txt`, and a `report.xml` summary.

6. `clamscan` — scan recovered/extracted files for known malware.
```bash
clamscan -r --infected --stdout be_out recovered_file.bin
```
Expected observable: per-file `OK`/`FOUND` lines and a summary with `Infected files: N`.

## Hands-on exercise
The sample lives in this module's `exercise/` directory as `triage_sample.raw`.

- **Type:** a small raw FAT filesystem image (benign, inert — contains only harmless text files plus one file carrying the EICAR antivirus test string, which is NOT malware).
- **Safe origin / no-egress:** generated locally with the generator command below; no network access, no live malware. The EICAR string is the industry-standard, harmless AV test signature.
- **Reproducible generator** (run once inside `exercise/` to build the sample):
```bash
mkdir -p exercise && cd exercise
dd if=/dev/zero of=triage_sample.raw bs=1M count=8
mkfs.vfat triage_sample.raw
mmd -i triage_sample.raw ::/loot 2>/dev/null || true
printf 'contact admin at analyst@example.com visit http://203.0.113.10/payload\n' > note.txt
mcopy -i triage_sample.raw note.txt ::/note.txt
printf 'X5O!P%%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > eicar.com
mcopy -i triage_sample.raw eicar.com ::/eicar.com
sha256sum triage_sample.raw
```

**Tasks:**
1. List all files in the image with `fls`.
2. Carve the embedded email address and URL with `bulk_extractor`.
3. Extract `eicar.com` and confirm ClamAV flags it.

## SOC analyst perspective
During an incident, the SOC receives a disk image and must triage fast before escalating. The Sleuth Kit gives an auditable, mount-free file listing and timeline that answers "what files exist, when were they touched, what was deleted." bulk_extractor surfaces attacker infrastructure — carved URLs and IPs feed directly into Security Onion pivots (search Zeek `conn.log`/`http.log` and Suricata alerts for the same indicators to correlate host and network evidence). A ClamAV hit maps to MITRE ATT&CK T1204 (User Execution) or dropped-tool detection, and the whole sequence produces reproducible hashes and outputs that hold up in a handoff ticket or chain-of-custody record, aligning with the identification and examination DFIR phases.

## Attacker perspective
An attacker who compromises a host drops tooling (T1105 Ingress Tool Transfer), then tries to hide by deleting files and clearing artifacts (T1070 Indicator Removal). Deleting a file only unlinks its directory entry — the inode and data often survive, so `fls -r` reveals the `*`-marked deleted entries and `icat` recovers the content. Attackers frequently leave C2 URLs, hard-coded IPs, and staging paths inside binaries and configs; bulk_extractor pulls those from unallocated space and file slack that the attacker assumed were gone. Even packed or renamed payloads betray themselves when scanned, and ClamAV or the recovered indicators expose the intrusion the attacker tried to erase.

## Answer key
Sample sha256: run `sha256sum exercise/triage_sample.raw` after generating; the digest is fixed by the deterministic generator above and is held by the validator for the check.

Expected findings and the exact commands that produce them:
```bash
# 1. Files present in the image (note.txt, eicar.com; FAT image usually at offset 0)
fls -r -p exercise/triage_sample.raw
# -> lists r/r entries for note.txt and eicar.com

# 2. Carved email + URL indicators
bulk_extractor -o exercise/be_out exercise/triage_sample.raw
grep -i example.com exercise/be_out/email.txt   # -> analyst@example.com
cat exercise/be_out/url.txt                       # -> http://203.0.113.10/payload

# 3. Extract eicar.com and scan
mkdir -p exercise/extract
icat exercise/triage_sample.raw $(fls -p exercise/triage_sample.raw | awk '/eicar.com/{gsub(/:/,"",$2);print $2}') > exercise/extract/eicar.com
clamscan --infected --stdout exercise/extract/eicar.com
# -> exercise/extract/eicar.com: Eicar-Test-Signature FOUND ; Infected files: 1
```
Expected result summary: two indicators carved (`analyst@example.com`, `http://203.0.113.10/payload`) and exactly one ClamAV detection (`Eicar-Test-Signature`).

## MITRE ATT&CK & DFIR phase
- **T1105** Ingress Tool Transfer — dropped/staged files recovered via Sleuth Kit.
- **T1070.004** Indicator Removal: File Deletion — deleted inodes recovered with `fls`/`icat`.
- **T1027** Obfuscated/embedded indicators surfaced by bulk_extractor.
- **T1204** User Execution — malicious file identified by ClamAV signature.
- **DFIR phases:** Identification (mmls/fsstat), Examination (fls/icat/bulk_extractor), Analysis (clamscan + indicator correlation).

## Sources
- The Sleuth Kit documentation — https://www.sleuthkit.org/sleuthkit/docs.php
- bulk_extractor (Kali Tools) — https://www.kali.org/tools/bulk-extractor/
- ClamAV documentation — https://docs.clamav.net/
- SANS SIFT Workstation — https://www.sans.org/tools/sift-workstation/
- REMnux docs — https://docs.remnux.org/
- EICAR standard anti-malware test file — https://www.eicar.org/download-anti-malware-testfile/
- MITRE ATT&CK — https://attack.mitre.org/ (T1105, T1070/004, T1027, T1204)