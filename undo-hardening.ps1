<#
.SYNOPSIS
    Reverts changes made by the Unified-Hardening.ps1 script (v9+).
.DESCRIPTION
    This script reads a 'hardening-state.json' file from a specified log folder
    and provides a menu to undo the non-account security changes.

    Account-related operations performed during hardening (creation of SecOpsAdm,
    demotion of named users, and enable/disable of the built-in Administrator)
    are intentionally NOT reversed by this script. Once a machine has been
    hardened, those account changes form the new security baseline; reversing
    them would destroy the operator's current access and re-grant privileges
    that were intentionally removed.

    *** WARNING ***
    This script will reduce the security posture of the system. Operations like
    decrypting BitLocker or deleting WDAC policies are high-risk and may require a reboot.
#>
[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$true)]
    [string]$LogFolderPath
)

# --- Check for Administrative Privileges ---
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script requires administrative privileges. Please re-run from an elevated PowerShell prompt."
    exit 1
}

# --- Load State File ---
$stateFile = Join-Path $LogFolderPath "hardening-state.json"
if (-not (Test-Path $stateFile)) {
    Write-Error "State file not found at '$stateFile'. Cannot proceed with undo operation."
    exit 1
}
$state = Get-Content -Path $stateFile | ConvertFrom-Json

# --- UNDO FUNCTIONS ---
#
# NOTE: account-related changes (SecOpsAdm creation, demotion of named users,
# built-in Administrator enable/disable) are deliberately NOT reversed here.
# Once the hardened baseline is in place those accounts form the live security
# posture; reverting them would lock out the operator and re-grant privileges
# that were intentionally removed.

function Undo-Laps {
    Write-Host "  - Reverting LAPS policy (account state untouched)..." -ForegroundColor Yellow
    switch ($state.LapsConfigured) {
        "Modern" {
            if ($PSCmdlet.ShouldProcess("Modern LAPS Policy", "Disabling")) {
                if (Get-Command -Name Set-LapsPolicy -ErrorAction SilentlyContinue) {
                    Set-LapsPolicy -Enable 0
                    Write-Host "    - Modern LAPS policy disabled."
                } else { Write-Warning "Modern LAPS module not found." }
            }
        }
        "Legacy" {
            if ($PSCmdlet.ShouldProcess("Legacy LAPS Policy", "Removing registry keys")) {
                 Remove-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft Services\LAPS" -Recurse -Force -ErrorAction SilentlyContinue
                 Write-Host "    - Legacy LAPS registry policy removed."
                 Write-Warning "    - Note: The legacy LAPS application itself is NOT uninstalled automatically."
            }
        }
        "None" {
             Write-Host "  - No LAPS was configured by the hardening run. Nothing to revert."
        }
    }
}

function Undo-Defender {
    Write-Host "  - Reverting Defender hardening..." -ForegroundColor Yellow
    Write-Host "    (Note: Disabling Tamper Protection may require a reboot)" -ForegroundColor Gray
    if ($PSCmdlet.ShouldProcess("Microsoft Defender", "Disabling advanced protections")) {
        if ((Get-Command Set-MpPreference).Parameters.Keys -contains 'EnableTamperProtection') {
             Set-MpPreference -EnableTamperProtection 0
        }
        Set-MpPreference -EnableControlledFolderAccess Disabled
        Set-MpPreference -AttackSurfaceReductionRules_Ids $null -AttackSurfaceReductionRules_Actions Disabled
        Write-Host "    - Disabled CFA and cleared ASR rules."
    }
}

function Undo-BitLocker {
    Write-Host "  - Reverting BitLocker..." -ForegroundColor Yellow
    Write-Warning "DECRYPTING THE DRIVE CAN TAKE A VERY LONG TIME AND IS RISKY."
    $confirmation = Read-Host "Are you absolutely sure you want to turn off BitLocker for C:? (Type 'yes' to confirm)"
    if ($confirmation -eq 'yes') {
        if ($PSCmdlet.ShouldProcess("drive C:", "Disabling BitLocker Encryption")) {
            manage-bde -off C:
            Write-Host "    - BitLocker decryption process has been started for C:."
            Write-Host "    - You can monitor the progress with 'manage-bde -status'."
        }
    } else { Write-Host "    - BitLocker decryption cancelled." }
}

function Undo-Agents {
    Write-Host "  - Uninstalling agents..." -ForegroundColor Yellow
    if ($state.WazuhInstalled) {
        if ($PSCmdlet.ShouldProcess("Wazuh Agent", "Uninstalling")) {
            Write-Host "    - Attempting to uninstall Wazuh Agent..."
            Start-Process msiexec -ArgumentList "/x `"$($state.WazuhInstalled)`" /qn" -Wait
        }
    }
    if ($state.SysmonInstalled) {
        if ($PSCmdlet.ShouldProcess("Sysmon", "Uninstalling")) {
            Write-Host "    - Attempting to uninstall Sysmon..."
            $sysmonExe = Join-Path $PSScriptRoot 'Sysmon64.exe'
            if (Test-Path $sysmonExe) { & $sysmonExe -u force } else { Write-Warning "Sysmon64.exe not found to run uninstaller." }
        }
    }
}

function Undo-WDAC {
    Write-Host "  - Reverting WDAC Policy..." -ForegroundColor Yellow
    Write-Warning "This will delete the Code Integrity policy file and requires a REBOOT to take effect."
    if ($PSCmdlet.ShouldProcess("C:\Windows\System32\CodeIntegrity\SIPolicy.p7b", "Deleting file")) {
        Remove-Item -Path "C:\Windows\System32\CodeIntegrity\SIPolicy.p7b" -Force
        Write-Host "    - WDAC policy file deleted. Please reboot the computer."
    }
}

function Undo-Firewall {
    Write-Host "  - Resetting Windows Firewall to default..." -ForegroundColor Yellow
    if ($PSCmdlet.ShouldProcess("Windows Firewall", "Resetting all policies")) {
        netsh advfirewall reset
    }
}

function Undo-RemoteAccess {
    Write-Host "  - Re-enabling remote access services..." -ForegroundColor Yellow
    if ($PSCmdlet.ShouldProcess("Remote Access Services", "Enabling WinRM and RDP")) {
        Set-Service -Name 'WinRM' -StartupType Automatic
        Start-Service -Name 'WinRM' -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0
        Get-NetFirewallRule -DisplayName "*Remote Desktop*" | Enable-NetFirewallRule
        Write-Host "    - WinRM and RDP services and firewall rules have been re-enabled."
    }
}

# --- Main Menu Logic ---
do {
    Clear-Host
    Write-Host "--- Hardening Rollback Script ---" -ForegroundColor Cyan
    Write-Host "Reading state from: $stateFile`n"
    Write-Host "NOTE: Account changes (SecOpsAdm, demotions, built-in Administrator) are NOT reversed by this script." -ForegroundColor DarkGray
    Write-Host "      Manage those manually if needed.`n" -ForegroundColor DarkGray
    Write-Host "Select the action to perform:"
    Write-Host " 1) Undo LAPS Policy"
    Write-Host " 2) Undo Defender Hardening"
    Write-Host " 3) Undo BitLocker Encryption (HIGH RISK)"
    Write-Host " 4) Undo Agent Installations (Wazuh/Sysmon)"
    Write-Host " 5) Undo WDAC Policy (Reboot Required)"
    Write-Host " 6) Undo Firewall Hardening"
    Write-Host " 7) Undo Remote Access Disabling"
    Write-Host " 9) === UNDO ALL APPLIED CHANGES (non-account) ===" -ForegroundColor Yellow
    Write-Host " Q) Quit"

    $choice = Read-Host "`nEnter your choice"

    switch ($choice) {
        '1' { Undo-Laps }
        '2' { Undo-Defender }
        '3' { Undo-BitLocker }
        '4' { Undo-Agents }
        '5' { Undo-WDAC }
        '6' { Undo-Firewall }
        '7' { Undo-RemoteAccess }
        '9' {
            Write-Host "`n--- PERFORMING FULL ROLLBACK (non-account) ---`n" -ForegroundColor Yellow
            Undo-Laps
            Undo-Defender
            Undo-BitLocker
            Undo-Agents
            Undo-WDAC
            Undo-Firewall
            Undo-RemoteAccess
            Write-Host "`nFull rollback sequence complete. Account changes were NOT reversed." -ForegroundColor Green
        }
    }
    if ($choice -ne 'q' -and $choice -ne '9') { Read-Host "Press Enter to return to the menu..." }
} while ($choice -ne 'q' -and $choice -ne '9')
