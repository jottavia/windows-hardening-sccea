<#
.SYNOPSIS
    Reverts changes made by the Unified-Hardening.ps1 script.
.DESCRIPTION
    This script reads a 'hardening-state.json' file from a specified log folder
    and provides a menu to undo the security changes. It must be run with
    administrative privileges from the same removable drive as the original script.

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

function Undo-AdminChanges {
    Write-Host "  - Reverting Admin changes..." -ForegroundColor Yellow
    if ($state.DemotedAdmins.Count -gt 0) {
        foreach ($user in $state.DemotedAdmins) {
            if ($PSCmdlet.ShouldProcess("user '$user'", "Adding back to Administrators group")) {
                Write-Host "    - Re-promoting user '$user' to Administrators."
                net localgroup Administrators $user /add
            }
        }
    }
    if ($PSCmdlet.ShouldProcess("user '$($state.NewAdminName)'", "Deleting account")) {
        Write-Host "    - Deleting user '$($state.NewAdminName)'."
        net user $state.NewAdminName /delete
    }
}

function Undo-Defender {
    Write-Host "  - Reverting Defender hardening..." -ForegroundColor Yellow
    Write-Host "    (Note: Disabling Tamper Protection may require a reboot)" -ForegroundColor Gray
    if ($PSCmdlet.ShouldProcess("Microsoft Defender", "Disabling advanced protections")) {
        Set-MpPreference -EnableTamperProtection 0
        Set-MpPreference -EnableControlledFolderAccess Disabled
        Set-MpPreference -AttackSurfaceReductionRules_Ids $null -AttackSurfaceReductionRules_Actions Disabled
        Write-Host "    - Disabled Tamper Protection, CFA, and cleared ASR rules."
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

function Undo-Laps {
    Write-Host "  - Disabling LAPS policy..." -ForegroundColor Yellow
    if ($PSCmdlet.ShouldProcess("LAPS Policy", "Disabling")) {
        Set-LapsPolicy -Enable 0
    }
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
        Start-Service -Name 'WinRM'
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
    Write-Host "Select the action to perform:"
    Write-Host " 1) Undo Admin Account Changes" -ForegroundColor ($state.DemotedAdmins.Count -gt 0 ? "White" : "DarkGray")
    Write-Host " 2) Undo Defender Hardening" -ForegroundColor ($state.DefenderHardened ? "White" : "DarkGray")
    Write-Host " 3) Undo BitLocker Encryption (HIGH RISK)" -ForegroundColor ($state.BitLockerEnabled ? "White" : "DarkGray")
    Write-Host " 4) Undo LAPS Configuration" -ForegroundColor ($state.LapsConfigured ? "White" : "DarkGray")
    Write-Host " 5) Undo Agent Installations (Wazuh/Sysmon)" -ForegroundColor (($state.WazuhInstalled -or $state.SysmonInstalled) ? "White" : "DarkGray")
    Write-Host " 6) Undo WDAC Policy (Reboot Required)" -ForegroundColor ($state.WDACApplied ? "White" : "DarkGray")
    Write-Host " 7) Undo Firewall Hardening" -ForegroundColor ($state.FirewallHardened ? "White" : "DarkGray")
    Write-Host " 8) Undo Remote Access Disabling" -ForegroundColor ($state.RemoteAccessDisabled ? "White" : "DarkGray")
    Write-Host " 9) === UNDO ALL APPLIED CHANGES ===" -ForegroundColor Yellow
    Write-Host " Q) Quit"

    $choice = Read-Host "`nEnter your choice"

    switch ($choice) {
        '1' { if ($state.DemotedAdmins.Count -gt 0) { Undo-AdminChanges } }
        '2' { if ($state.DefenderHardened) { Undo-Defender } }
        '3' { if ($state.BitLockerEnabled) { Undo-BitLocker } }
        '4' { if ($state.LapsConfigured) { Undo-Laps } }
        '5' { if ($state.WazuhInstalled -or $state.SysmonInstalled) { Undo-Agents } }
        '6' { if ($state.WDACApplied) { Undo-WDAC } }
        '7' { if ($state.FirewallHardened) { Undo-Firewall } }
        '8' { if ($state.RemoteAccessDisabled) { Undo-RemoteAccess } }
        '9' {
            Write-Host "`n--- PERFORMING FULL ROLLBACK ---`n" -ForegroundColor Yellow
            if ($state.DemotedAdmins.Count -gt 0) { Undo-AdminChanges }
            if ($state.DefenderHardened) { Undo-Defender }
            if ($state.BitLockerEnabled) { Undo-BitLocker }
            if ($state.LapsConfigured) { Undo-Laps }
            if ($state.WazuhInstalled -or $state.SysmonInstalled) { Undo-Agents }
            if ($state.WDACApplied) { Undo-WDAC }
            if ($state.FirewallHardened) { Undo-Firewall }
            if ($state.RemoteAccessDisabled) { Undo-RemoteAccess }
            Write-Host "`nFull rollback sequence complete." -ForegroundColor Green
        }
    }
    if ($choice -ne 'q' -and $choice -ne '9') { Read-Host "Press Enter to return to the menu..." }
} while ($choice -ne 'q' -and $choice -ne '9')
