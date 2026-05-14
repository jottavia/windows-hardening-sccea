<#
.SYNOPSIS
    Reverses every change made by Post-Hardening-Console.ps1.
.DESCRIPTION
    Reads the PostHardening section of a hardening-state.json file and:
      - Uninstalls Tailscale (logout, msiexec or registered uninstaller)
      - Uninstalls RustDesk (msiexec or registered uninstaller)
      - Re-disables RDP if it was re-enabled
      - Removes all custom firewall rules added via the console
      - Removes all Defender exclusions added via the console
      - Clears the PostHardening section so the state matches a fresh
        hardening run.

    Run this BEFORE undo-hardening.ps1 if a full rollback is desired.
.NOTES
    Version: 1.0.0
    Pairs with: Post-Hardening-Console.ps1
                undo-hardening.ps1
#>
[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$true)][string]$LogFolderPath,
    [switch]$All
)

if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script requires administrative privileges."
    exit 1
}

$stateFile = Join-Path $LogFolderPath "hardening-state.json"
if (-not (Test-Path $stateFile)) {
    Write-Error "State file not found at '$stateFile'."
    exit 1
}

$state = Get-Content -Path $stateFile -Raw -Encoding UTF8 | ConvertFrom-Json
if (-not ($state.PSObject.Properties.Name -contains 'PostHardening') -or -not $state.PostHardening) {
    Write-Host "No PostHardening section in state. Nothing to undo."
    exit 0
}

$ph = $state.PostHardening

#---------------------------------------------------------------------------
# Helpers
#---------------------------------------------------------------------------
$script:MsiPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"

function Invoke-WithMsiAllowed {
    param([Parameter(Mandatory=$true)][scriptblock]$ScriptBlock)
    $had = $false; $prev = $null
    try {
        if (Test-Path $script:MsiPolicyPath) {
            $had = $true
            $prev = (Get-ItemProperty -Path $script:MsiPolicyPath -Name "DisableMSI" -ErrorAction SilentlyContinue).DisableMSI
            Set-ItemProperty -Path $script:MsiPolicyPath -Name "DisableMSI" -Value 0 -Type DWord -Force
        }
        & $ScriptBlock
    } finally {
        if ($had -and $null -ne $prev) {
            Set-ItemProperty -Path $script:MsiPolicyPath -Name "DisableMSI" -Value $prev -Type DWord -Force
        }
    }
}

function Get-UninstallEntry {
    param([Parameter(Mandatory=$true)][string]$DisplayNamePattern)
    $hives = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    foreach ($hive in $hives) {
        $hit = Get-ItemProperty -Path $hive -ErrorAction SilentlyContinue |
               Where-Object { $_.DisplayName -like $DisplayNamePattern } |
               Select-Object -First 1
        if ($hit) { return $hit }
    }
    return $null
}

function Save-State {
    $state | ConvertTo-Json -Depth 10 | Out-File -FilePath $stateFile -Encoding UTF8 -Force
}

#---------------------------------------------------------------------------
# Undo functions
#---------------------------------------------------------------------------
function Undo-Tailscale {
    if (-not $ph.Tailscale -or -not $ph.Tailscale.Installed) {
        Write-Host "  Tailscale not flagged as installed by the console. Skipping."
        return
    }
    Write-Host "  - Uninstalling Tailscale..." -ForegroundColor Yellow
    $exe = 'C:\Program Files\Tailscale\tailscale.exe'
    if (Test-Path $exe) {
        if ($PSCmdlet.ShouldProcess("tailscale", "logout")) {
            Start-Process -FilePath $exe -ArgumentList 'logout' -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue
        }
    }

    if ($ph.Tailscale.InstallerPath -and (Test-Path $ph.Tailscale.InstallerPath) -and ($ph.Tailscale.InstallerPath -like '*.msi')) {
        if ($PSCmdlet.ShouldProcess($ph.Tailscale.InstallerPath, "msiexec /x")) {
            Invoke-WithMsiAllowed { Start-Process msiexec -ArgumentList @('/x', "`"$($ph.Tailscale.InstallerPath)`"", '/qn', '/norestart') -Wait }
        }
    } else {
        $u = Get-UninstallEntry -DisplayNamePattern 'Tailscale*'
        if ($u) {
            if ($u.QuietUninstallString) {
                if ($PSCmdlet.ShouldProcess("Tailscale", $u.QuietUninstallString)) {
                    Start-Process cmd -ArgumentList @('/c', $u.QuietUninstallString) -Wait
                }
            } elseif ($u.UninstallString) {
                if ($u.UninstallString -match 'msiexec' -and $u.UninstallString -match '({[A-F0-9-]+})') {
                    $guid = $Matches[1]
                    Invoke-WithMsiAllowed { Start-Process msiexec -ArgumentList @('/x',$guid,'/qn','/norestart') -Wait }
                } else {
                    Start-Process cmd -ArgumentList @('/c', "$($u.UninstallString) /S") -Wait
                }
            }
        } else {
            Write-Warning "    Could not find Tailscale uninstaller."
        }
    }

    foreach ($n in @($ph.Tailscale.FirewallRules)) {
        if ($n -and (Get-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue)) {
            Remove-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue
            Write-Host "    Firewall rule removed: $n"
        }
    }
    foreach ($p in @($ph.Tailscale.DefenderExclusions)) {
        if ($p) {
            Remove-MpPreference -AttackSurfaceReductionOnlyExclusions $p -ErrorAction SilentlyContinue
            Write-Host "    Defender exclusion removed: $p"
        }
    }
    $ph.Tailscale = $null
}

function Undo-RustDesk {
    if (-not $ph.RustDesk -or -not $ph.RustDesk.Installed) {
        Write-Host "  RustDesk not flagged as installed by the console. Skipping."
        return
    }
    Write-Host "  - Uninstalling RustDesk..." -ForegroundColor Yellow
    $done = $false
    # 1. MSI path if state has one
    if ($ph.RustDesk.InstallerPath -and (Test-Path $ph.RustDesk.InstallerPath) -and ($ph.RustDesk.InstallerPath -like '*.msi')) {
        if ($PSCmdlet.ShouldProcess($ph.RustDesk.InstallerPath, "msiexec /x")) {
            Invoke-WithMsiAllowed { Start-Process msiexec -ArgumentList @('/x', "`"$($ph.RustDesk.InstallerPath)`"", '/qn', '/norestart') -Wait }
            $done = $true
        }
    }
    # 2. Official RustDesk uninstall: 'rustdesk.exe --uninstall' (silent, no /S).
    #    Use the ExePath we recorded if available; otherwise check the default path.
    if (-not $done) {
        $exe = $null
        if ($ph.RustDesk.ExePath -and (Test-Path $ph.RustDesk.ExePath)) {
            $exe = $ph.RustDesk.ExePath
        } elseif (Test-Path 'C:\Program Files\RustDesk\rustdesk.exe') {
            $exe = 'C:\Program Files\RustDesk\rustdesk.exe'
        }
        if ($exe -and $PSCmdlet.ShouldProcess("RustDesk", "$exe --uninstall")) {
            Start-Process -FilePath $exe -ArgumentList '--uninstall' -Wait -WindowStyle Hidden
            $done = $true
        }
    }
    # 3. Fallback: registry UninstallString (which is normally "...rustdesk.exe" --uninstall)
    if (-not $done) {
        $u = Get-UninstallEntry -DisplayNamePattern 'RustDesk*'
        if ($u -and ($u.QuietUninstallString -or $u.UninstallString)) {
            $cmdStr = if ($u.QuietUninstallString) { $u.QuietUninstallString } else { $u.UninstallString }
            if ($PSCmdlet.ShouldProcess("RustDesk", $cmdStr)) {
                if ($cmdStr -match 'msiexec' -and $cmdStr -match '({[A-F0-9-]+})') {
                    $guid = $Matches[1]
                    Invoke-WithMsiAllowed { Start-Process msiexec -ArgumentList @('/x',$guid,'/qn','/norestart') -Wait }
                } else {
                    Start-Process cmd -ArgumentList @('/c', $cmdStr) -Wait -WindowStyle Hidden
                }
            }
        } else {
            Write-Warning "    Could not find RustDesk uninstaller."
        }
    }

    foreach ($n in @($ph.RustDesk.FirewallRules)) {
        if ($n -and (Get-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue)) {
            Remove-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue
            Write-Host "    Firewall rule removed: $n"
        }
    }
    foreach ($p in @($ph.RustDesk.DefenderExclusions)) {
        if ($p) {
            Remove-MpPreference -AttackSurfaceReductionOnlyExclusions $p -ErrorAction SilentlyContinue
            Write-Host "    Defender exclusion removed: $p"
        }
    }
    $ph.RustDesk = $null
}

function Undo-Rdp {
    if (-not $ph.RdpReenabled) {
        Write-Host "  RDP not re-enabled by the console. Skipping."
        return
    }
    Write-Host "  - Re-disabling RDP..." -ForegroundColor Yellow
    if ($PSCmdlet.ShouldProcess("RDP", "disable")) {
        Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1 -Type DWord -Force
        Stop-Service -Name 'TermService' -Force -ErrorAction SilentlyContinue
        Get-NetFirewallRule -DisplayName "*Remote Desktop*" -ErrorAction SilentlyContinue | Disable-NetFirewallRule -ErrorAction SilentlyContinue
        $ph.RdpReenabled = $false
    }
}

function Undo-CustomFirewall {
    if (-not $ph.CustomFirewallRules -or @($ph.CustomFirewallRules).Count -eq 0) {
        Write-Host "  No custom firewall rules to remove."
        return
    }
    Write-Host "  - Removing custom firewall rules..." -ForegroundColor Yellow
    foreach ($r in @($ph.CustomFirewallRules)) {
        if ($r -and $r.Name -and (Get-NetFirewallRule -DisplayName $r.Name -ErrorAction SilentlyContinue)) {
            Remove-NetFirewallRule -DisplayName $r.Name -ErrorAction SilentlyContinue
            Write-Host "    Rule removed: $($r.Name)"
        }
    }
    $ph.CustomFirewallRules = @()
}

function Undo-DefenderExclusions {
    if (-not $ph.DefenderExclusionsAdded -or @($ph.DefenderExclusionsAdded).Count -eq 0) {
        Write-Host "  No Defender exclusions to remove."
        return
    }
    Write-Host "  - Removing Defender exclusions..." -ForegroundColor Yellow
    foreach ($e in @($ph.DefenderExclusionsAdded)) {
        if ($e -and $e.Path) {
            Remove-MpPreference -AttackSurfaceReductionOnlyExclusions $e.Path -ErrorAction SilentlyContinue
            if ($e.CFA) {
                Remove-MpPreference -ControlledFolderAccessAllowedApplications $e.Path -ErrorAction SilentlyContinue
            }
            Write-Host "    Exclusion removed: $($e.Path)"
        }
    }
    $ph.DefenderExclusionsAdded = @()
}

#---------------------------------------------------------------------------
# Driver
#---------------------------------------------------------------------------
function Invoke-Full {
    Undo-Tailscale
    Undo-RustDesk
    Undo-Rdp
    Undo-CustomFirewall
    Undo-DefenderExclusions
    Save-State
    Write-Host "`nFull post-hardening rollback complete. Run undo-hardening.ps1 to reverse the base hardening." -ForegroundColor Green
}

if ($All) {
    Invoke-Full
    exit 0
}

do {
    Clear-Host
    Write-Host "--- Undo Post-Hardening Console Changes ---" -ForegroundColor Cyan
    Write-Host "State: $stateFile`n"
    Write-Host " 1) Undo Tailscale install"
    Write-Host " 2) Undo RustDesk install"
    Write-Host " 3) Re-disable RDP (only if console enabled it)"
    Write-Host " 4) Remove custom firewall rules"
    Write-Host " 5) Remove Defender exclusions added via console"
    Write-Host " 9) === UNDO ALL ===" -ForegroundColor Yellow
    Write-Host " Q) Quit"

    $choice = Read-Host "`nEnter your choice"
    switch ($choice) {
        '1' { Undo-Tailscale;          Save-State }
        '2' { Undo-RustDesk;           Save-State }
        '3' { Undo-Rdp;                Save-State }
        '4' { Undo-CustomFirewall;     Save-State }
        '5' { Undo-DefenderExclusions; Save-State }
        '9' { Invoke-Full }
    }
    if ($choice -ne 'q' -and $choice -ne 'Q' -and $choice -ne '9') {
        Read-Host "Press Enter to return to the menu..."
    }
} while ($choice -ne 'q' -and $choice -ne 'Q' -and $choice -ne '9')
