<#
.SYNOPSIS
    Disables LLMNR (Link-Local Multicast Name Resolution) on Windows, creates
    a Tools folder on the C: drive, and installs/updates a standard set of
    tools via winget (plus RSAT via Windows Capabilities).

.DESCRIPTION
    Sets the "Turn off multicast name resolution" group policy setting by
    writing EnableMulticast = 0 under the DNS Client policy key, and creates
    C:\Tools if it does not already exist. Requires an elevated
    (Administrator) PowerShell session. A detailed timestamped log of every
    step is written to the directory the script was run from.

    Software is installed/updated with `winget`. Before installing the apps
    below, `winget upgrade --all` is run to update anything already present
    on the system. If a package ID below has changed upstream, run
    `winget search "<app name>"` to find the current ID and update the
    $Apps table. RSAT is installed separately via Add-WindowsCapability,
    since it is not distributed through winget.

    Installed/updated apps:
        - 7-Zip
        - Burp Suite Professional
        - Cloudflare WARP
        - Firefox
        - Notepad++
        - OpenVPN Connect
        - Proxifier
        - PuTTY
        - Sysinternals Suite
        - Tailscale
        - WireGuard
        - Wireshark
        - Git
        - Azure CLI
        - Python
        - DBeaver CE
        - VS Code
        - RSAT (Remote Server Administration Tools)

    Also unpins the following apps from the taskbar, if pinned:
        - Microsoft Edge
        - Outlook

    Unpins ALL apps currently pinned to the Start menu, then pins only:
        - Settings
        - Microsoft Store
        - Windows PowerShell
        - Windows PowerShell ISE
        - Command Prompt
        - Notepad++
        - Proxifier
        - DBeaver CE
        - VS Code

    NOTE: Microsoft has progressively restricted scripted taskbar/Start
    menu pin/unpin automation on newer Windows 10/11 builds. The
    pin/unpin steps below use the classic Shell.Application "Pin to
    Start" / "Unpin from Start" / "Unpin from taskbar" verbs, which are
    best-effort - if a verb is unavailable on this build, the log will
    note it and that app must be pinned/unpinned manually.
#>

#Requires -RunAsAdministrator

$ErrorActionPreference = 'Stop'

$logDir  = Get-Location
$logFile = Join-Path $logDir "win_install_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR')]
        [string]$Level = 'INFO'
    )
    $line = "[{0}] [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Add-Content -Path $logFile -Value $line
    switch ($Level) {
        'ERROR' { Write-Host $line -ForegroundColor Red }
        'WARN'  { Write-Host $line -ForegroundColor Yellow }
        default { Write-Host $line -ForegroundColor Green }
    }
}

function Get-LLMNRStatus {
    param([string]$Path)
    if (-not (Test-Path $Path)) {
        return "Not configured (registry path absent) - LLMNR is ENABLED (default)"
    }
    $value = Get-ItemProperty -Path $Path -Name 'EnableMulticast' -ErrorAction SilentlyContinue
    if ($null -eq $value) {
        return "Not configured (EnableMulticast value absent) - LLMNR is ENABLED (default)"
    }
    elseif ($value.EnableMulticast -eq 0) {
        return "EnableMulticast = 0 - LLMNR is DISABLED"
    }
    else {
        return "EnableMulticast = $($value.EnableMulticast) - LLMNR is ENABLED"
    }
}

function Install-OrUpdateWingetApp {
    param(
        [string]$Id,
        [string]$Name
    )

    Write-Log "---- $Name (winget id: $Id) ----"
    try {
        $listOutput = winget list --id $Id -e --accept-source-agreements 2>&1 | Out-String
        Write-Log "winget list output for $Name : $($listOutput.Trim())"

        if ($listOutput -match [regex]::Escape($Id)) {
            Write-Log "$Name is already installed. Attempting upgrade..."
            $result = winget upgrade --id $Id -e --accept-package-agreements --accept-source-agreements --silent 2>&1 | Out-String
            Write-Log "$Name upgrade output: $($result.Trim())"
        }
        else {
            Write-Log "$Name not found on system. Installing..."
            $result = winget install --id $Id -e --accept-package-agreements --accept-source-agreements --silent 2>&1 | Out-String
            Write-Log "$Name install output: $($result.Trim())"
        }

        if ($LASTEXITCODE -eq 0) {
            Write-Log "$Name completed successfully (exit code 0)."
        }
        else {
            Write-Log "$Name finished with exit code $LASTEXITCODE. Review output above." -Level 'WARN'
        }
    }
    catch {
        Write-Log "Failed to install/update $Name : $($_.Exception.Message)" -Level 'ERROR'
    }
}

function Install-RSAT {
    Write-Log "---- RSAT (Remote Server Administration Tools) ----"
    try {
        $caps = Get-WindowsCapability -Online | Where-Object { $_.Name -like 'Rsat*' }
        if (-not $caps) {
            Write-Log "No RSAT capabilities found on this SKU." -Level 'WARN'
            return
        }

        $notInstalled = $caps | Where-Object { $_.State -ne 'Installed' }
        Write-Log "RSAT capabilities found: $($caps.Count) total, $($notInstalled.Count) not yet installed."

        foreach ($cap in $notInstalled) {
            Write-Log "Installing RSAT capability: $($cap.Name)"
            try {
                Add-WindowsCapability -Online -Name $cap.Name | Out-Null
                Write-Log "Installed RSAT capability: $($cap.Name)"
            }
            catch {
                Write-Log "Failed to install RSAT capability $($cap.Name): $($_.Exception.Message)" -Level 'ERROR'
            }
        }

        if ($notInstalled.Count -eq 0) {
            Write-Log "All RSAT capabilities already installed."
        }
    }
    catch {
        Write-Log "Failed to enumerate/install RSAT: $($_.Exception.Message)" -Level 'ERROR'
    }
}

function Remove-TaskbarPin {
    param([string[]]$AppNames)

    Write-Log "---- Unpinning apps from taskbar ----"
    try {
        $taskbarPath = "shell:::{4234d49b-0245-4df3-b780-3893943456e1}"
        $shell = New-Object -ComObject Shell.Application
        $folder = $shell.Namespace($taskbarPath)
        if (-not $folder) {
            Write-Log "Could not access the taskbar-pinned items shell folder." -Level 'WARN'
            return
        }

        $items = $folder.Items()

        foreach ($appName in $AppNames) {
            $matches = $items | Where-Object { $_.Name -like "*$appName*" }
            if (-not $matches) {
                Write-Log "$appName is not pinned to the taskbar. Skipping."
                continue
            }

            foreach ($item in $matches) {
                $verb = $item.Verbs() | Where-Object { ($_.Name -replace '&', '') -match 'Unpin from taskbar' }
                if ($verb) {
                    Write-Log "Unpinning '$($item.Name)' from the taskbar."
                    $verb.DoIt()
                    Write-Log "'$($item.Name)' unpinned from taskbar."
                }
                else {
                    Write-Log "No 'Unpin from taskbar' verb found for '$($item.Name)'. This Windows build may not support scripted unpinning - unpin manually if needed." -Level 'WARN'
                }
            }
        }
    }
    catch {
        Write-Log "Failed to unpin taskbar apps: $($_.Exception.Message)" -Level 'ERROR'
    }
}

function Get-StartAppsFolder {
    return (New-Object -ComObject Shell.Application).Namespace('shell:AppsFolder')
}

function Remove-AllStartPins {
    Write-Log "---- Unpinning all apps from Start menu ----"
    try {
        $folder = Get-StartAppsFolder
        if (-not $folder) {
            Write-Log "Could not access the shell:AppsFolder namespace." -Level 'WARN'
            return
        }

        $items = $folder.Items()
        Write-Log "Scanning $($items.Count) installed apps for Start menu pins..."

        $unpinnedCount = 0
        foreach ($item in $items) {
            $verb = $item.Verbs() | Where-Object { ($_.Name -replace '&', '') -match 'Unpin from Start' }
            if ($verb) {
                Write-Log "Unpinning '$($item.Name)' from Start menu."
                $verb.DoIt()
                $unpinnedCount++
            }
        }

        if ($unpinnedCount -eq 0) {
            Write-Log "No pinned Start menu items were unpinned (either none were pinned, or the 'Unpin from Start' verb is unavailable on this Windows build)." -Level 'WARN'
        }
        else {
            Write-Log "Unpinned $unpinnedCount app(s) from the Start menu."
        }
    }
    catch {
        Write-Log "Failed to unpin Start menu apps: $($_.Exception.Message)" -Level 'ERROR'
    }
}

function Add-StartPins {
    param([hashtable[]]$Targets)

    Write-Log "---- Pinning selected apps to Start menu ----"
    try {
        $folder = Get-StartAppsFolder
        if (-not $folder) {
            Write-Log "Could not access the shell:AppsFolder namespace." -Level 'WARN'
            return
        }

        $items = $folder.Items()

        foreach ($target in $Targets) {
            $display = $target.Display
            $search  = $target.Search

            $match = $items | Where-Object { $_.Name -eq $search }
            if (-not $match) {
                $match = $items | Where-Object { $_.Name -like "*$search*" }
                if ($match) {
                    Write-Log "No exact name match for '$display'. Using fuzzy match: '$($match[0].Name)'." -Level 'WARN'
                }
            }

            if (-not $match) {
                Write-Log "Could not find '$display' in the installed apps list. It may not be installed, or its Start menu name differs. Skipping." -Level 'WARN'
                continue
            }

            $match = $match | Select-Object -First 1
            $verb = $match.Verbs() | Where-Object { ($_.Name -replace '&', '') -match 'Pin to Start' }
            if ($verb) {
                Write-Log "Pinning '$($match.Name)' to Start menu."
                $verb.DoIt()
                Write-Log "'$($match.Name)' pinned to Start menu."
            }
            else {
                Write-Log "No 'Pin to Start' verb found for '$($match.Name)' (it may already be pinned, or this Windows build blocks scripted pinning). Pin manually if needed." -Level 'WARN'
            }
        }
    }
    catch {
        Write-Log "Failed to pin Start menu apps: $($_.Exception.Message)" -Level 'ERROR'
    }
}

Write-Log "Script started. Log file: $logFile"

try {
    # Create C:\Tools
    $toolsPath = 'C:\Tools'
    if (-not (Test-Path $toolsPath)) {
        Write-Log "Creating directory $toolsPath"
        New-Item -Path $toolsPath -ItemType Directory -Force | Out-Null
        Write-Log "Directory $toolsPath created."
    }
    else {
        Write-Log "Directory $toolsPath already exists. Skipping creation."
    }

    # Disable LLMNR
    $regPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'

    $beforeStatus = Get-LLMNRStatus -Path $regPath
    Write-Log "LLMNR status before change: $beforeStatus"

    Write-Log "Checking registry path $regPath"
    if (-not (Test-Path $regPath)) {
        Write-Log "Registry path not found. Creating $regPath"
        New-Item -Path $regPath -Force | Out-Null
    }

    Write-Log "Setting EnableMulticast = 0 under $regPath"
    New-ItemProperty -Path $regPath -Name 'EnableMulticast' -PropertyType DWord -Value 0 -Force | Out-Null
    Write-Log "LLMNR disabled successfully."

    $afterStatus = Get-LLMNRStatus -Path $regPath
    Write-Log "LLMNR status after change: $afterStatus"

    # Install / update software via winget
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Write-Log "winget was not found on this system. Skipping software installation. Install 'App Installer' from the Microsoft Store and re-run." -Level 'ERROR'
    }
    else {
        Write-Log "Running winget upgrade --all to update all currently installed packages..."
        try {
            $upgradeAllOutput = winget upgrade --all --accept-package-agreements --accept-source-agreements --silent 2>&1 | Out-String
            Write-Log "winget upgrade --all output: $($upgradeAllOutput.Trim())"
            if ($LASTEXITCODE -eq 0) {
                Write-Log "winget upgrade --all completed successfully (exit code 0)."
            }
            else {
                Write-Log "winget upgrade --all finished with exit code $LASTEXITCODE. Review output above." -Level 'WARN'
            }
        }
        catch {
            Write-Log "winget upgrade --all failed: $($_.Exception.Message)" -Level 'ERROR'
        }

        $Apps = [ordered]@{
            '7-Zip'               = '7zip.7zip'
            'Burp Suite Professional' = 'PortSwigger.BurpSuite.Professional'
            'Cloudflare WARP'     = 'Cloudflare.Warp'
            'Firefox'             = 'Mozilla.Firefox'
            'Notepad++'           = 'Notepad++.Notepad++'
            'OpenVPN Connect'     = 'OpenVPNTechnologies.OpenVPNConnect'
            'Proxifier'           = 'Proxifier.Proxifier'
            'PuTTY'               = 'PuTTY.PuTTY'
            'Sysinternals Suite'  = 'Microsoft.Sysinternals'
            'Tailscale'           = 'Tailscale.Tailscale'
            'WireGuard'           = 'WireGuard.WireGuard'
            'Wireshark'           = 'WiresharkFoundation.Wireshark'
            'Git'                 = 'Git.Git'
            'Azure CLI'           = 'Microsoft.AzureCLI'
            'Python'              = 'Python.Python.3.12'
            'DBeaver CE'          = 'dbeaver.dbeaver'
            'VS Code'             = 'Microsoft.VisualStudioCode'
        }

        Write-Log "Beginning software install/update pass for $($Apps.Count) applications."
        foreach ($appName in $Apps.Keys) {
            Install-OrUpdateWingetApp -Id $Apps[$appName] -Name $appName
        }
        Write-Log "Software install/update pass complete."
    }

    # RSAT (not available via winget - installed as a Windows Capability)
    Install-RSAT

    # Unpin apps from the taskbar
    Remove-TaskbarPin -AppNames @('Microsoft Edge', 'Outlook')

    # Unpin everything from the Start menu, then pin only the desired tools
    Remove-AllStartPins

    $StartPinTargets = @(
        @{ Display = 'Settings';              Search = 'Settings' }
        @{ Display = 'Microsoft Store';       Search = 'Microsoft Store' }
        @{ Display = 'Windows PowerShell';    Search = 'Windows PowerShell' }
        @{ Display = 'Windows PowerShell ISE'; Search = 'Windows PowerShell ISE' }
        @{ Display = 'Command Prompt';        Search = 'Command Prompt' }
        @{ Display = 'Notepad++';             Search = 'Notepad++' }
        @{ Display = 'Proxifier';             Search = 'Proxifier' }
        @{ Display = 'DBeaver CE';            Search = 'DBeaver' }
        @{ Display = 'VS Code';               Search = 'Visual Studio Code' }
    )
    Add-StartPins -Targets $StartPinTargets

    Write-Log "Script completed successfully."
}
catch {
    Write-Log "Script failed: $($_.Exception.Message)" -Level 'ERROR'
    throw
}
