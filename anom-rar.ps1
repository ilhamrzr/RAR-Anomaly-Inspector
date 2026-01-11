<#
  RAR Anomaly Inspector (Final Stable)
  Author  : Ilham
  Source  : https://github.com/ilhamrzr/RAR-Anomaly-Inspector

  Purpose :
  Static inspection for RAR archives on Windows.
  - Show user-visible decoy files
  - Highlight suspicious extensions
  - FULL RAW dump of suspicious execution/persistence paths
  - SAFE directory-only paths for investigation

  This tool is READ-ONLY and does NOT extract or execute files.
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$Archive
)

# --------------------------------------------------
# Metadata
# --------------------------------------------------
$ScanTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$SevenZip = "C:\Program Files\7-Zip\7z.exe"

# --------------------------------------------------
# Resolve archive path (CWD → script dir fallback)
# --------------------------------------------------
$Archive = $Archive.Trim()

$Resolved = $null
try { $Resolved = [System.IO.Path]::GetFullPath($Archive) } catch {}

if (-not $Resolved -or -not (Test-Path -LiteralPath $Resolved)) {
    $ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    $AltPath   = Join-Path $ScriptDir $Archive
    if (Test-Path -LiteralPath $AltPath) {
        $Resolved = [System.IO.Path]::GetFullPath($AltPath)
    }
}

if (-not $Resolved -or -not (Test-Path -LiteralPath $Resolved)) {
    Write-Error "Archive not found: '$Archive'"
    exit 1
}
$Archive = $Resolved

# --------------------------------------------------
# Banner
# --------------------------------------------------
Write-Host @"

RAR Anomaly Inspector
CVE      : CVE-2025-8088 (WinRAR Path Traversal)
Author   : Ilham
Source   : https://github.com/ilhamrzr/RAR-Anomaly-Inspector

Mode     : Static / Read-Only Inspection
Warning  : Indicators only - NOT proof of exploitation
ScanTime : $ScanTime
-------------------------------------------------------
"@ -ForegroundColor Green

function Header($text) {
    Write-Host "`n=== $text ===" -ForegroundColor Cyan
}

# --------------------------------------------------
# Pre-flight
# --------------------------------------------------
if (-not (Test-Path -LiteralPath $SevenZip)) {
    Write-Error "7-Zip not found at: $SevenZip"
    exit 1
}

# --------------------------------------------------
# 1. Archive inventory (decoy awareness)
# --------------------------------------------------
Header "Archive File Inventory (7-Zip read-only)"

$list = & "$SevenZip" l "$Archive" 2>$null

$FileList = $list |
    Where-Object { $_ -match '^\d{4}-\d{2}-\d{2}' } |
    ForEach-Object { ($_ -split '\s{2,}')[-1] } |
    Where-Object { $_ -match '\.[A-Za-z0-9]{1,8}$' }

if ($FileList.Count -gt 0) {
    Write-Host "Files visible to the user:" -ForegroundColor Green
    $FileList | Sort-Object | ForEach-Object { Write-Host "  - $_" }
} else {
    Write-Host "No visible files detected in archive." -ForegroundColor Yellow
}

# --------------------------------------------------
# 2. Suspicious extension highlight
# --------------------------------------------------
$SuspiciousExtensions = @(
    ".exe",".dll",".scr",".com",".cpl",".msi",
    ".bat",".cmd",".ps1",
    ".vbs",".js",".jse",".wsf",".hta",
    ".lnk",".url",
    ".dat",".bin",".tmp",
    ".lock",".crypt",".encrypted",".enc"
)

$SuspiciousFiles = $FileList | Where-Object {
    $SuspiciousExtensions -contains ([System.IO.Path]::GetExtension($_).ToLower())
}

if ($SuspiciousFiles.Count -gt 0) {
    Write-Host "`nSuspicious file extensions detected:" -ForegroundColor Yellow
    $SuspiciousFiles | ForEach-Object { Write-Host "  - $_" }
}

# --------------------------------------------------
# 3. RAW binary path inspection (NO Select-String)
# --------------------------------------------------
Header "Suspicious Path Indicators Extraction"

# --- Read archive bytes (hard fail) ---
try {
    $BinaryBytes = [System.IO.File]::ReadAllBytes($Archive)
} catch {
    Write-Error "Failed to read archive bytes."
    exit 1
}

if (-not $BinaryBytes -or $BinaryBytes.Length -eq 0) {
    Write-Error "Archive is empty or unreadable."
    exit 1
}

# --- Binary-safe conversion (PS 5.1 compatible) ---
$Latin1 = [System.Text.Encoding]::GetEncoding(28591)
$BinaryText = $Latin1.GetString($BinaryBytes)

# --- RAW detection patterns ---
$RawPatterns = @(
    '(?:\.\.\\){1,40}.*?(Startup|AppData|ProgramData|System32|Windows\\Tasks|Windows\\Fonts|Users\\Public|Temp)[^\x00]{0,300}',
    'Users\\[^\\]+\\AppData\\Roaming\\[^\x00]{1,300}',
    'Users\\[^\\]+\\AppData\\Local\\[^\x00]{1,300}',
    'ProgramData\\[^\x00]{1,300}',
    'Windows\\System32\\[^\x00]{1,300}',
    'Windows\\Tasks\\[^\x00]{1,300}',
    'Windows\\Fonts\\[^\x00]{1,300}',
    'Windows\\Temp\\[^\x00]{1,300}',
    'Users\\Public\\[^\x00]{1,300}'
)

$RawRegex = [string]::Join('|', $RawPatterns)

$Matches = [System.Text.RegularExpressions.Regex]::Matches(
    $BinaryText,
    $RawRegex,
    [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
)

$RawPaths = foreach ($m in $Matches) { $m.Value }

if ($RawPaths.Count -gt 0) {
    Write-Host "RAW suspicious path indicators (UNFILTERED):" -ForegroundColor Red
    $RawPaths | ForEach-Object { Write-Host "  - $_" -ForegroundColor DarkRed }
    Write-Host "Total RAW indicators: $($RawPaths.Count)" -ForegroundColor DarkGray
} else {
    Write-Host "No raw traversal indicators found in archive metadata." -ForegroundColor Green
}

# --------------------------------------------------
# 4. CLEAN / SAFE directory paths
# --------------------------------------------------
$CleanPaths = $RawPaths |
    ForEach-Object { $_ -replace '^[^A-Za-z0-9]*','' } |
    ForEach-Object { $_ -replace '\\[^\\]+$','' } |
    Where-Object { $_ -match '\\' } |
    Sort-Object -Unique

if ($CleanPaths.Count -gt 0) {
    Write-Host "`nSanitized logical paths (SAFE for copy-paste):" -ForegroundColor Yellow
    $CleanPaths | ForEach-Object { Write-Host "  -> $_" }
}

# --------------------------------------------------
# 5. Summary
# --------------------------------------------------
Header "Summary"

$TraversalHeavy = $RawPaths | Where-Object { $_ -match '(?:\.\.\\){3,}' }

if ($SuspiciousFiles.Count -gt 0 -or $RawPaths.Count -gt 0) {
    Write-Host "Result: [!] ARCHIVE REQUIRES FURTHER INVESTIGATION" -ForegroundColor Yellow

    if ($TraversalHeavy.Count -gt 1) {
        Write-Host "[!] High-risk archive structure detected (repeated deep traversal / ADS-style metadata)" -ForegroundColor Yellow
    }

    Write-Host "`nManual investigation hint:" -ForegroundColor Gray
    Write-Host "- Review archive construction and intent." -ForegroundColor Gray
    Write-Host "- Do NOT execute extracted files directly." -ForegroundColor Gray
    Write-Host "- Treat repeated traversal as HIGH RISK." -ForegroundColor Gray
} else {
    Write-Host "Result: No obvious indicators found via static inspection." -ForegroundColor Green
}

Write-Host "`nInspection complete."
