param(
    [string]$ProcessName = "",
    [string]$OutputDir = "",
    [int]$Hours = 24,
    [switch]$Redact,
    [switch]$Zip,
    [switch]$Version
)

$ScriptVersion = "1.1.0"

if ($Version) {
    Write-Host $ScriptVersion
    exit 0
}

$ErrorActionPreference = "Continue"
$Warnings = New-Object System.Collections.Generic.List[string]

function Add-Warning {
    param([string]$Message)
    $Warnings.Add($Message) | Out-Null
    Write-Warning $Message
}

function Test-Tool {
    param([string]$Name)
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        Add-Warning "Missing command: $Name"
        return $false
    }
    return $true
}

function Redact-TextFile {
    param([string]$Path)
    try {
        $text = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
        if ($env:USERNAME) {
            $text = $text -replace [regex]::Escape($env:USERNAME), "USER_REDACTED"
        }
        if ($env:USERPROFILE) {
            $text = $text -replace [regex]::Escape($env:USERPROFILE), "USERPROFILE_REDACTED"
        }
        if ($env:COMPUTERNAME) {
            $text = $text -replace [regex]::Escape($env:COMPUTERNAME), "HOST_REDACTED"
        }
        $text = $text -replace "\b(?:\d{1,3}\.){3}\d{1,3}\b", "IP_REDACTED"
        $text = $text -replace "(?i)\b([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b", "EMAIL_REDACTED"
        $text = $text -replace "(?i)\b(password|passwd|token|secret|api[_-]?key|authorization)\s*[:=]\s*(?:(?:bearer|basic)\s+)?[^\r\n,;]+", '$1=REDACTED'
        Set-Content -LiteralPath $Path -Value $text -Encoding UTF8
    } catch {
        Add-Warning "Could not redact ${Path}: $($_.Exception.Message)"
    }
}

function Write-Manifest {
    param([string]$Dir)
    $files = @()
    Get-ChildItem -LiteralPath $Dir -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -ne "manifest.json" -and $_.Extension -ne ".zip" } |
        Sort-Object FullName |
        ForEach-Object {
            $hash = $null
            try {
                $hash = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
            } catch {
                Add-Warning "Could not hash $($_.FullName): $($_.Exception.Message)"
            }
            $relative = $_.FullName.Substring($Dir.Length).TrimStart("\", "/")
            $files += [ordered]@{
                path = $relative
                bytes = $_.Length
                sha256 = $hash
            }
        }

    $manifest = [ordered]@{
        schema_version = 1
        script = "collect_windows_crash_info.ps1"
        script_version = $ScriptVersion
        platform = "windows"
        collected_at = (Get-Date).ToString("o")
        process_name = $ProcessName
        hours = $Hours
        redacted = [bool]$Redact
        zip_requested = [bool]$Zip
        warnings = $Warnings.ToArray()
        warnings_file = "collection-warnings.txt"
        warnings_count = $Warnings.Count
        files = $files
    }
    $manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $Dir "manifest.json") -Encoding UTF8
}

if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $OutputDir = Join-Path -Path (Get-Location) -ChildPath "crash-info-windows-$stamp"
}

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

Test-Tool "Get-WinEvent" | Out-Null
Test-Tool "Get-CimInstance" | Out-Null
Test-Tool "Get-FileHash" | Out-Null

$startTime = (Get-Date).AddHours(-1 * $Hours)
$summary = [ordered]@{
    collected_at = (Get-Date).ToString("o")
    script_version = $ScriptVersion
    host = $env:COMPUTERNAME
    user = $env:USERNAME
    process_name = $ProcessName
    hours = $Hours
    redacted = [bool]$Redact
}

$summary | ConvertTo-Json | Set-Content -Path (Join-Path $OutputDir "summary.json") -Encoding UTF8

try {
    $events = Get-WinEvent -FilterHashtable @{LogName = "Application"; StartTime = $startTime} -ErrorAction Stop |
        Where-Object {
            $_.Id -in 1000, 1001 -or
            $_.ProviderName -match "Application Error|Windows Error Reporting" -or
            (-not [string]::IsNullOrWhiteSpace($ProcessName) -and $_.Message -match [regex]::Escape($ProcessName))
        } |
        Select-Object TimeCreated, Id, ProviderName, LevelDisplayName, Message
    $events | ConvertTo-Json -Depth 4 | Set-Content -Path (Join-Path $OutputDir "application-events.json") -Encoding UTF8
    $events | Format-List * | Out-File -FilePath (Join-Path $OutputDir "application-events.txt") -Encoding UTF8
} catch {
    Add-Warning "Could not read Application event log: $($_.Exception.Message)"
}

try {
    Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps" -ErrorAction Stop |
        Select-Object PSChildName, Name |
        ConvertTo-Json -Depth 3 |
        Set-Content -Path (Join-Path $OutputDir "wer-localdumps.json") -Encoding UTF8
} catch {
    Add-Warning "Could not read WER LocalDumps registry key: $($_.Exception.Message)"
}

try {
    Get-CimInstance Win32_OperatingSystem -ErrorAction Stop |
        Select-Object Caption, Version, BuildNumber, OSArchitecture, LastBootUpTime |
        ConvertTo-Json |
        Set-Content -Path (Join-Path $OutputDir "os.json") -Encoding UTF8
} catch {
    Add-Warning "Could not collect OS information: $($_.Exception.Message)"
}

if (-not [string]::IsNullOrWhiteSpace($ProcessName)) {
    try {
        $safeProcessName = $ProcessName.Replace("'", "''")
        Get-CimInstance Win32_Process -Filter "name = '$safeProcessName'" -ErrorAction Stop |
            Select-Object ProcessId, Name, ExecutablePath, CommandLine, CreationDate |
            ConvertTo-Json -Depth 3 |
            Set-Content -Path (Join-Path $OutputDir "matching-processes.json") -Encoding UTF8
    } catch {
        Add-Warning "Could not collect matching process information: $($_.Exception.Message)"
    }
}

$warningsPath = Join-Path $OutputDir "collection-warnings.txt"
if ($Warnings.Count -gt 0) {
    $Warnings | Set-Content -LiteralPath $warningsPath -Encoding UTF8
} else {
    Set-Content -LiteralPath $warningsPath -Value "" -Encoding UTF8
}

if ($Redact) {
    Get-ChildItem -LiteralPath $OutputDir -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -ne "manifest.json" -and @(".zip", ".dmp", ".mdmp", ".dump") -notcontains $_.Extension } |
        ForEach-Object { Redact-TextFile $_.FullName }
}

Write-Manifest $OutputDir

if ($Zip) {
    $zipPath = "$OutputDir.zip"
    try {
        if (Test-Path -LiteralPath $zipPath) {
            Remove-Item -LiteralPath $zipPath -Force
        }
        Compress-Archive -LiteralPath $OutputDir -DestinationPath $zipPath -Force
        Write-Host "Zip written to $zipPath"
    } catch {
        Add-Warning "Could not create zip archive: $($_.Exception.Message)"
        Write-Manifest $OutputDir
    }
}

Write-Host "Crash collection written to $OutputDir"
