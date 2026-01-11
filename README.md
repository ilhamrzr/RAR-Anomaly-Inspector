# RAR Anomaly Inspector

<p align="center">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License MIT">
  <img src="https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg" alt="PowerShell 5.1+">
  <img src="https://img.shields.io/badge/CVE-2025--8088-red.svg" alt="CVE-2025-8088">
</p>

RAR Anomaly Inspector is a **read-only PowerShell tool** for **static inspection of RAR archives**, designed to detect **path traversal anomalies** related to **CVE-2025-8088 (WinRAR RAR5 Path Traversal)**.

The tool does **not extract or execute** archive contents.

---

## Features

- Static, read-only analysis (no extraction, no execution)
- Detection of raw path traversal patterns (`..\`)
- Identification of writes outside extraction directory
- Detection of NTFS Alternate Data Stream (ADS) indicators
- Clean, directory-only output (safe for copy-paste)
- Heuristic-based risk classification

---

## Requirements

- Windows
- PowerShell 5.1+
- Optional: `7z.exe` (for listing user-visible files)

---

## Usage

```powershell
.\anom-rar.ps1 .\suspicious.rar
```

### Example Output

```textile
RAR Anomaly Inspector
CVE      : CVE-2025-8088 (WinRAR Path Traversal)
Author   : Ilham
Source   : https://github.com/ilhamrzr/RAR-Anomaly-Inspector

Mode     : Static / Read-Only Inspection
Warning  : Indicators only - NOT proof of exploitation
ScanTime : 2026-01-11 13:33:05
-------------------------------------------------------

=== Archive File Inventory (7-Zip read-only) ===
Files visible to the user:
  - CVE-2025-8088.pdf

=== Suspicious Path Indicators Extraction ===
RAW suspicious path indicators (UNFILTERED):
  - ..\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\CVE-2025-8088.vbs
  - ..\..\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\CVE-2025-8088.vbs
  - ..\..\..\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\CVE-2025-8088.vbs
  - ..\..\..\..\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\CVE-2025-8088.vbs
  - ..\..\..\..\..\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\CVE-2025-8088.vbs
  - ..\..\..\..\..\..\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\CVE-2025-8088.vbs
  - ..\..\..\..\..\..\..\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\CVE-2025-8088.vbs
  - ..\..\..\..\..\..\..\..\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\CVE-2025-8088.vbs
  - ..\..\..\..\..\..\..\..\..\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\CVE-2025-8088.vbs
  - ..\..\..\..\..\..\..\..\..\..\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\CVE-2025-8088.vbs
Total RAW indicators: 10

Sanitized logical paths (SAFE for copy-paste):
  -> AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup

=== Summary ===
Result: [!] ARCHIVE REQUIRES FURTHER INVESTIGATION
[!] High-risk archive structure detected (repeated deep traversal / ADS-style metadata)

Manual investigation hint:
- Review archive construction and intent.
- Do NOT execute extracted files directly.
- Treat repeated traversal as HIGH RISK.

Inspection completete.


```

---

## Risk Levels

- **LOW**  
  Minor anomalies without sensitive targets

- **MEDIUM**  
  Traversal detected without clear persistence paths

- **HIGH**  
  Explicit traversal targeting sensitive directories

> Risk levels are heuristic and do not indicate exploit success.

---

## What This Tool Does Not Do

- Does not extract archives

- Does not execute files

- Does not validate payloads

- Does not guarantee exploitation

---

## Scope

- Intended for defensive analysis and triage

- Suitable for blue teams, responders, and researchers

- Not an exploitation framework

---

## CVE Reference

- **CVE-2025-8088**

- Affected: WinRAR for Windows ≤ 7.12

- Fixed in: WinRAR 7.13+

---

## Disclaimer

This tool is provided for **defensive and educational purposes only**.
