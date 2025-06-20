<#
.SYNOPSIS
    Reverts changes made by the Unified-Hardening.ps1 script (v9+).
.DESCRIPTION
    This script reads a 'hardening-state.json' file from a specified log folder
    and provides a menu to undo the security changes, including the new LAPS logic. 
    It must be run with administrative privileges from the same removable drive as the original script.

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

function Undo-LapsAndBuiltinAdmin {
    Write-Host "  - Reverting LAPS configuration and built-in Admin state..." -ForegroundColor Yellow
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
             Write-Host "  - No LAPS was configured. Reverting built-in Admin to its original state only."
        }
    }
    # Always revert the built-in admin to its original recorded state
    $originalState = if ($state.BuiltinAdminState) { "yes" } else { "no" }
    if ($PSCmdlet.ShouldProcess("Administrator Account", "Setting active state to '$($originalState)'")) {
        net user Administrator /active:$originalState
        Write-Host "    - Built-in Administrator account active state reverted to '$originalState'."
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
    Write-Host "Select the action to perform:"
    Write-Host " 1) Undo Admin Account Changes"
    Write-Host " 2) Undo LAPS & Built-in Admin State"
    Write-Host " 3) Undo Defender Hardening"
    Write-Host " 4) Undo BitLocker Encryption (HIGH RISK)"
    Write-Host " 5) Undo Agent Installations (Wazuh/Sysmon)"
    Write-Host " 6) Undo WDAC Policy (Reboot Required)"
    Write-Host " 7) Undo Firewall Hardening"
    Write-Host " 8) Undo Remote Access Disabling"
    Write-Host " 9) === UNDO ALL APPLIED CHANGES ===" -ForegroundColor Yellow
    Write-Host " Q) Quit"

    $choice = Read-Host "`nEnter your choice"

    switch ($choice) {
        '1' { Undo-AdminChanges }
        '2' { Undo-LapsAndBuiltinAdmin }
        '3' { Undo-Defender }
        '4' { Undo-BitLocker }
        '5' { Undo-Agents }
        '6' { Undo-WDAC }
        '7' { Undo-Firewall }
        '8' { Undo-RemoteAccess }
        '9' {
            Write-Host "`n--- PERFORMING FULL ROLLBACK ---`n" -ForegroundColor Yellow
            Undo-AdminChanges
            Undo-LapsAndBuiltinAdmin
            Undo-Defender
            Undo-BitLocker
            Undo-Agents
            Undo-WDAC
            Undo-Firewall
            Undo-RemoteAccess
            Write-Host "`nFull rollback sequence complete." -ForegroundColor Green
        }
    }
    if ($choice -ne 'q' -and $choice -ne '9') { Read-Host "Press Enter to return to the menu..." }
} while ($choice -ne 'q' -and $choice -ne '9')
