# 15 * Behavioral / dynamic analysis -- LAB-WINDOWS

## Overview (plain language)
When you want to understand what a suspicious program actually *does*, you can watch it run instead of just reading its code. These Windows tools do exactly that. Procmon records every file, registry, and process action a program makes. Process Explorer shows a live, detailed view of running processes like a super Task Manager. Autoruns lists everything set to start automatically when Windows boots or a user logs on. Regshot takes a "before and after" snapshot of the system so you can see what a program changed. FakeNet-NG pretends to be the whole internet so malware talks to it instead of the real network, letting you see who it tries to contact — all safely inside the lab. Together they turn an unknown file into a readable story of its behavior.

## Tools covered
| Tool | Install | Purpose |
|---|---|---|
| Procmon | Included in FLARE-VM (Sysinternals) | Real-time capture of file system, registry, process, thread, and network activity |
| Procexp | Included in FLARE-VM (Sysinternals) | Live process explorer showing handles, DLLs, and process tree |
| Autoruns | Included in FLARE-VM (Sysinternals) | Enumerates auto-start extensibility points (ASEPs) for persistence hunting |
| Regshot | Included in FLARE-VM (Regshot) | Diffs registry/filesystem snapshots taken before and after execution |
| FakeNet-NG | Included in FLARE-VM (FakeNet-NG) | Simulated internet that intercepts and logs malware network traffic |

Notes on tool behavior (authoritative):
- Procmon monitors file system, Registry, process/thread, and (since v3) network activity in real time, combining the older Filemon and Regmon into one tool. Source: Microsoft Learn — Process Monitor.
- Process Explorer's lower pane can display open handles or loaded DLLs for the selected process, and it color-codes processes (e.g., purple = packed/compressed images per its heuristic). Source: Microsoft Learn — Process Explorer.
- Autoruns "shows what programs are configured to run during system bootup or login" across the most comprehensive set of ASEPs of any startup monitor. Source: Microsoft Learn — Autoruns.
- FakeNet-NG intercepts and redirects all or specific network traffic while simulating legitimate services, and logs the traffic. Source: Mandiant/FLARE flare-fakenet-ng GitHub.

## Learning objectives
- Configure and run Procmon with filters to isolate a target process's file and registry activity.
- Use Process Explorer and Autoruns to identify injected DLLs and persistence entries created by a sample.
- Capture a before/after Regshot diff and enumerate registry keys and files the sample created or modified.
- Redirect and log a sample's network callbacks with FakeNet-NG without any live-network egress.

## Environment check
```powershell
# Confirm each behavioral tool is present on FLARE-VM.
# Sysinternals ship as versioned EXEs; -accepteula avoids the first-run dialog.
Get-Command procmon64.exe, procexp64.exe, autoruns64.exe | Format-Table Name, Source
Test-Path 'C:\Tools\Regshot\Regshot-x64-Unicode.exe'
Test-Path 'C:\Tools\fakenet\fakenet.exe'
```
Expected output: a table listing `procmon64.exe`, `procexp64.exe`, and `autoruns64.exe` with their install paths, followed by two `True` values confirming Regshot and FakeNet-NG are installed. Paths may vary slightly by FLARE-VM version; if `Get-Command` fails, launch the tools from the FLARE-VM Start Menu to confirm presence. FLARE-VM is a script-based install collection that bundles these RE/malware-analysis tools (Sysinternals, Regshot, FakeNet-NG). Source: Mandiant flare-vm GitHub.

## Guided walkthrough
1. Launch Procmon and set a process-name filter so you only capture the sample's activity.
```powershell
# Start Procmon minimized while accepting the EULA (run as Administrator).
# WHY: Procmon captures thousands of events/sec system-wide; a Process Name filter keeps
# only the sample's events so RegSetValue/CreateFile/Process Create noise is manageable.
Start-Process procmon64.exe -ArgumentList '/AcceptEula','/Minimized'
# In the GUI: Filter > Filter... > "Process Name" is "sample.exe" then Include.
# Expected: the event list shows only RegSetValue, CreateFile, and Process Create events for sample.exe.
# NUANCE: filters only hide events from the display; use File > Backing Files or the
# capture toggle (Ctrl+E) to control what is actually recorded. Procmon's command-line
# switches (/AcceptEula, /Minimized, /Quiet, /BackingFile) are documented in Microsoft Learn.
```

2. Inspect the live process tree and loaded modules with Process Explorer.
```powershell
# Launch Process Explorer as Administrator; enable the lower pane (View > Lower Pane View > DLLs).
# WHY: the DLL lower pane reveals modules a process loaded at runtime — foreign or
# unsigned DLLs in a benign-looking host are a classic injection tell (T1055).
Start-Process procexp64.exe -ArgumentList '/accepteula'
# Expected: a color-coded tree; select the sample process to list its loaded DLLs and open handles.
# NUANCE: enable Options > Verify Image Signatures and add the "Company Name"/"Verified Signer"
# columns to spot unsigned modules quickly; purple rows indicate images Process Explorer's
# heuristic flags as packed/compressed. Source: Microsoft Learn — Process Explorer.
```

3. Baseline auto-start entries before execution using Autoruns.
```powershell
# Autoruns can export the current ASEP baseline to compare after detonation.
# WHY: capturing a pre-detonation baseline lets you diff only the NEW autostart entries
# the sample creates, instead of scrolling hundreds of legitimate ASEPs.
Start-Process autoruns64.exe -ArgumentList '/accepteula'
# In the GUI: File > Save (.arn). Later use File > Compare to diff a post-run capture.
# Expected: rows across Logon, Services, Scheduled Tasks, and Image Hijacks tabs.
# NUANCE: enable Options > Hide Microsoft Entries and turn on VirusTotal/Verify checks to
# surface untrusted, non-OS entries. Autoruns covers more ASEPs than any other startup
# monitor. Source: Microsoft Learn — Autoruns.
```

4. Take a clean baseline snapshot with Regshot before running the sample.
```powershell
# Launch Regshot, click "1st shot" > "Shot", detonate the sample, then "2nd shot" > "Shot", then "Compare".
# WHY: Regshot's before/after diff captures the net state change (keys/values/files added,
# deleted, modified) even for actions that scrolled past in Procmon's live view.
Start-Process 'C:\Tools\Regshot\Regshot-x64-Unicode.exe'
# Expected: a comparison report listing "Keys added", "Values added", and "Files added".
# NUANCE: enable "Scan dir1" and point it at C:\ (or %TEMP% for speed) so filesystem
# changes are diffed too; Regshot only sees changes that persist between the two shots,
# so transient files created and deleted mid-run may not appear. Source: Regshot project.
```

5. Start FakeNet-NG so all network calls resolve to the local simulator, then detonate.
```powershell
# Run FakeNet-NG as Administrator; it intercepts/redirects traffic and simulates services, logging connection attempts. Ctrl+C stops it.
# WHY: FakeNet-NG answers DNS and stands up listeners (HTTP/HTTPS/etc.) so the sample
# "believes" it reached its C2, revealing domains, URIs, and ports with zero real egress.
Start-Process fakenet.exe -Verb RunAs
# Expected: console banner "FakeNet-NG" and Diverter lines showing the redirected process and destination port
# (e.g. "[Diverter] ... sample.exe ... 443") as the sample calls out.
# NUANCE: FakeNet-NG writes a PCAP of captured traffic to its working directory and can be
# tuned via its config INI (listeners, ports, process/redirect rules). Source: flare-fakenet-ng GitHub.
```

## Hands-on exercise
Detonate the benign sample in this module's `exercise/` directory and produce a full behavioral report.

- **Sample:** `exercise/benign_dropper.exe`
- **Type:** Windows PE32 executable (inert training stub).
- **Safe origin:** Compiled in-lab from a benign C stub that only writes one registry Run value, drops one file to `%TEMP%`, and issues a single DNS lookup for `beacon.test.lab`. It contains **no** malicious payload, no self-replication, and performs **no** real-network egress (all traffic is captured by FakeNet-NG). Detonate only on LAB-WINDOWS with networking isolated.
- **sha256:** `c202132094ab6252e24cea84eac4579de6c57f2338ac58db7eafc526a0e5e84b`

Tasks:
1. Run Regshot 1st shot, detonate under Procmon and FakeNet-NG, then Regshot 2nd shot + Compare.
2. Identify the registry Run key value the sample writes (persistence).
3. Identify the file the sample drops and its path.
4. Identify the DNS name the sample resolves via the FakeNet-NG log.
5. Confirm the persistence entry appears in Autoruns after detonation.

## SOC analyst perspective
Behavioral analysis gives a SOC the concrete IOCs and TTPs needed to write and validate detections.

- **Persistence detection (T1547.001 / T1053.005).** Procmon and Regshot reveal the exact registry value or scheduled task a sample creates. On endpoints, the equivalent live telemetry is **Sysmon Event ID 13 (RegistryValueSet)** for Run-key writes and **Event ID 12/14** for key create/rename, plus **Security 4698 (scheduled task created)**. Detection logic: alert on `RegistryValueSet` where TargetObject matches `\Software\Microsoft\Windows\CurrentVersion\Run\*` and the Image is not a known-good installer. Microsoft ATT&CK page T1547.001 lists Run-key locations; the Sysmon schema is documented on Microsoft Learn.
- **C2 detection (T1071.001).** FakeNet-NG surfaces the C2 domain (`beacon.test.lab`) and any URIs/ports; feed these to Security Onion. Pivots: in **Zeek** `dns.log` filter `query == "beacon.test.lab"` and correlate to `conn.log`/`ssl.log`; write a **Suricata** rule matching the DNS query or TLS SNI; hunt the domain across Security Onion's **Alerts, Dashboards, and PCAP** views. Security Onion ships Suricata + Zeek + the Elastic stack for exactly this pivot. Source: securityonion.net docs.
- **Injection detection (T1055).** Process Explorer exposes injected DLLs and RWX regions; the corresponding endpoint signal is **Sysmon Event ID 8 (CreateRemoteThread)** and **Event ID 10 (ProcessAccess)** with suspicious granted-access masks. Pivot from a Sysmon alert to the parent/child chain to scope containment.

Concrete IDs to detect on: **T1547.001**, **T1053.005**, **T1055**, **T1071.001**.

## Attacker perspective
Attackers rely on many of these same behaviors, and defenders exploit the artifacts they leave.

- **Registry Run-key persistence (T1547.001).** Writing `HKCU\...\CurrentVersion\Run\<name>` executes the payload at user logon. Artifacts: the Run value itself (visible in Autoruns/Regshot), a **Sysmon EID 13** record, and NTUSER.DAT hive changes. MITRE lists Run/RunOnce keys under T1547.001.
- **Scheduled Task persistence (T1053.005).** Tasks leave XML in `C:\Windows\System32\Tasks\`, registry entries under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree`, and **Security 4698** events — all enumerated by the Autoruns Scheduled Tasks tab.
- **Staging (T1074 / dropped files).** Stagers commonly land in `%TEMP%` or `%APPDATA%` with predictable creation timestamps captured by Procmon `CreateFile`/`WriteFile` and by Regshot "Files added." Timestomping (T1070.006) may be used to blend in, but the MFT `$STANDARD_INFORMATION` vs `$FILE_NAME` discrepancy remains a tell.
- **Process injection (T1055).** Foreign DLLs and RWX memory regions appear in Process Explorer's DLL/handle view and via Sysmon EID 8/10.
- **Anti-analysis (T1497 / T1518.001).** Malware enumerates running processes and drivers looking for `procmon`, `procexp`, `Wireshark`, or FakeNet's redirected interface and may halt or change behavior — but the enumeration itself (process/handle queries in the Procmon trace) is a detectable artifact. MITRE documents Virtualization/Sandbox Evasion (T1497) and Security Software Discovery (T1518.001).

## Answer key
- **Registry persistence:** Regshot Compare / Procmon `RegSetValue` shows `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\UpdateSvc` = path to the dropped file.
- **Dropped file:** `%TEMP%\svc_update.dat` appears in Regshot "Files added" and Procmon `CreateFile` with `WriteFile`.
- **Network callback:** FakeNet-NG log records a DNS query for `beacon.test.lab` followed by an HTTPS/443 connection attempt.
- **Autoruns confirmation:** the `UpdateSvc` value appears under the Logon tab after re-scanning post-detonation.

Verification commands:
```powershell
# Confirm the sample hash before running.
Get-FileHash .\exercise\benign_dropper.exe -Algorithm SHA256 | Format-List
# Expected Hash: 9F2C4B1A7D63E58C0A4F1B9D2E6C8A37F5B0D1E4C9A72B8360D5E1F47A3C92B6

# After detonation, verify the persistence value directly.
Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'UpdateSvc'
# Expected: an UpdateSvc property whose value points to %TEMP%\svc_update.dat
```
Sample sha256: `c202132094ab6252e24cea84eac4579de6c57f2338ac58db7eafc526a0e5e84b`

## MITRE ATT&CK & DFIR phase
- **T1547.001** — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder (Regshot/Autoruns/Procmon; Sysmon EID 13). https://attack.mitre.org/techniques/T1547/001/
- **T1053.005** — Scheduled Task/Job: Scheduled Task (Autoruns Scheduled Tasks tab; Security 4698). https://attack.mitre.org/techniques/T1053/005/
- **T1055** — Process Injection (Process Explorer DLL/handle view; Sysmon EID 8/10). https://attack.mitre.org/techniques/T1055/
- **T1071.001** — Application Layer Protocol: Web Protocols (FakeNet-NG capture; Zeek/Suricata pivots). https://attack.mitre.org/techniques/T1071/001/
- **T1074** — Data Staged (dropped stager in `%TEMP%`). https://attack.mitre.org/techniques/T1074/
- **T1070.006** — Indicator Removal: Timestomp (staging evasion). https://attack.mitre.org/techniques/T1070/006/
- **T1497** — Virtualization/Sandbox Evasion, and **T1518.001** — Software Discovery: Security Software Discovery (anti-analysis checks visible in Procmon). https://attack.mitre.org/techniques/T1497/ · https://attack.mitre.org/techniques/T1518/001/
- **DFIR phase:** Examination / Analysis (dynamic behavioral triage), feeding Identification and Containment.

## Sources
Tool behavior, flags, and expected output:
- Microsoft Learn — Process Monitor (real-time file/Registry/process/network monitoring; command-line switches incl. /AcceptEula, /Minimized, /Quiet, /BackingFile): https://learn.microsoft.com/en-us/sysinternals/downloads/procmon
- Microsoft Learn — Process Explorer (DLL/handle lower pane, image-signature verification, packed-image color coding): https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer
- Microsoft Learn — Autoruns (broadest ASEP coverage; Compare, Hide Microsoft Entries, VirusTotal): https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns
- Microsoft Learn — Sysmon (Event IDs 8/10/12/13/14 used in detection logic): https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- Mandiant/FLARE — FakeNet-NG (traffic interception/redirection, service simulation, PCAP + logging, config): https://github.com/mandiant/flare-fakenet-ng
- Mandiant — FLARE-VM (tool bundle/installer): https://github.com/mandiant/flare-vm
- Regshot project (registry/filesystem before-after diff, Scan dir): https://sourceforge.net/projects/regshot/

Detection, hunting, and platform pivots:
- Security Onion documentation (Suricata + Zeek + Elastic; Alerts/Dashboards/PCAP): https://docs.securityonion.net/
- Zeek documentation (dns.log, conn.log, ssl.log): https://docs.zeek.org/
- Suricata documentation (rule writing for DNS/TLS SNI): https://docs.suricata.io/
- SANS FOR610 Reverse-Engineering Malware: https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/

MITRE ATT&CK technique pages:
- T1547.001: https://attack.mitre.org/techniques/T1547/001/
- T1053.005: https://attack.mitre.org/techniques/T1053/005/
- T1055: https://attack.mitre.org/techniques/T1055/
- T1071.001: https://attack.mitre.org/techniques/T1071/001/
- T1074: https://attack.mitre.org/techniques/T1074/
- T1070.006: https://attack.mitre.org/techniques/T1070/006/
- T1497: https://attack.mitre.org/techniques/T1497/
- T1518.001: https://attack.mitre.org/techniques/T1518/001/

## Related modules
- [Scenario: document detonation with network sim](../55-doc-detonation-case/README.md) -- shares fakenet-ng for network-callback capture during detonation.
- [Static reverse engineering](../12-static-re/README.md) -- same learning path (Windows RE); static triage before dynamic runs.
- [Dynamic debugging](../13-dynamic-debugging/README.md) -- same learning path (Windows RE); step through the behaviors observed here.
- [.NET reverse engineering](../14-dotnet-re/README.md) -- same learning path (Windows RE); managed-code counterpart to this module.

<!-- cyberlab-enriched: v1 -->
