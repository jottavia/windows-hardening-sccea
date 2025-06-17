<#
.SYNOPSIS
    Automates the security hardening of a Windows machine, verifies each step, and saves a state file for rollback.
.DESCRIPTION
    Performs a security lockdown, confirms each change was applied successfully, and creates a
    'hardening-state.json' file required by the Undo-Hardening.ps1 script to reverse the changes.

    *** CRITICAL SECURITY WARNING ***
    This script writes secrets (passwords, keys) and state data to the execution drive.
    This drive MUST be removed and stored securely immediately after use.
#>
[CmdletBinding()]
param(
    [string[]]$UsersToDemote = @(),
    [string]$WazuhManagerIP = '192.168.1.100'
)

#===========================================================================
# SCRIPT CONFIGURATION
#===========================================================================
$config = @{
    NewAdminName      = "SecOpsAdm"
    PasswordLength    = 24
    LogFolderName     = "PC-$env:COMPUTERNAME-LOGS"
    LogFileName       = "hardening-log.txt"
    StateFileName     = "hardening-state.json"
    LapsAdminAccount  = "Administrator"
    FirewallAllowRules = @(
        @{Name='HTTPS-Out';      Protocol='TCP'; Port=443},
        @{Name='DNS-Out';        Protocol='UDP'; Port=53},
        @{Name='HTTP-WinUpdate'; Protocol='TCP'; Port=80},
        @{Name='NTP-Time';       Protocol='UDP'; Port=123},
        @{Name='URBackup-Out';   Protocol='TCP'; Port=55415}
    )
}

#===========================================================================
# HELPER FUNCTIONS
#===========================================================================
function New-StrongPassword { param([int]$Length = 20); $charSets=@{Lower=[char[]]('a'..'z');Upper=[char[]]('A'..'Z');Digit=[char[]]('0'..'9');Symbol='!@#$%^&*()_+-=[]{}|';};$p=@();$p+=$charSets.Lower|Get-Random;$p+=$charSets.Upper|Get-Random;$p+=$charSets.Digit|Get-Random;$p+=$charSets.Symbol|Get-Random;$allChars=$charSets.Values-join''|%{$_};$rem=$Length-$p.Count;if($rem-gt 0){$p+=Get-Random -InputObject $allChars -Count $rem};return -join($p|Get-Random -Count $p.Count)}
function Get-ScriptDriveRoot { return (Split-Path -Qualifier $PSScriptRoot) }
function Get-LogFolder { $d=Get-ScriptDriveRoot; $f=Join-Path $d $config.LogFolderName; if(-not(Test-Path $f)){New-Item -ItemType Directory -Path $f|Out-Null}; return $f }
function Write-SecLog { param([string]$Text); $logFile=Join-Path (Get-LogFolder) $config.LogFileName; "$(Get-Date -f 'yyyy-MM-dd HH:mm:ss') :: $Text"|Add-Content -Path $logFile }

#===========================================================================
# SCRIPT EXECUTION
#===========================================================================

# --- INITIALIZATION ---
Clear-Host
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "==  MASTER WINDOWS HARDENING SCRIPT (v3)   ==" -ForegroundColor Cyan
Write-Host "==         (with Task Verification)        ==" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host
$logFolder = Get-LogFolder
Write-Host "[[ Activity and SECRETS will be logged to '$logFolder' ]]" -ForegroundColor Yellow
Write-Host "********************** SECURITY WARNING **********************" -ForegroundColor Red
Write-Host "THIS DRIVE MUST BE REMOVED AND SECURED AFTER SCRIPT COMPLETION." -ForegroundColor Red
Write-Host "**************************************************************`n" -ForegroundColor Red

# Initialize the state object for the undo file
$undoState = [PSCustomObject]@{
    HardeningDate       = (Get-Date -Format 'o')
    NewAdminName        = $config.NewAdminName
    DemotedAdmins       = @()
    DefenderHardened    = $false
    BitLockerEnabled    = $false
    LapsConfigured      = $false
    WazuhInstalled      = $false
    SysmonInstalled     = $false
    WDACApplied         = $false
    FirewallHardened    = $false
}

Write-SecLog "Master harden script started. Preparing undo state file."

# --- 1. CREATE SECOPS ADMIN & DEMOTE OTHERS ---
Write-Host "[1] Managing Administrator Accounts..." -ForegroundColor Green
try {
    # Record users to be demoted for undo purposes first
    $undoState.DemotedAdmins = $UsersToDemote

    if (-not (Get-LocalUser -Name $config.NewAdminName -ErrorAction SilentlyContinue)) {
        $password = New-StrongPassword -Length $config.PasswordLength
        net user $config.NewAdminName $password /add /expires:never /passwordchg:no
        net localgroup Administrators $config.NewAdminName /add
        # VERIFICATION
        if ((Get-LocalGroupMember -Group 'Administrators').Name -contains $config.NewAdminName) {
            Write-Host "  [VERIFIED] Created and promoted local admin '$($config.NewAdminName)'." -ForegroundColor Green
            Write-SecLog "Created '$($config.NewAdminName)'. ==> PASSWORD: $password"
        } else {
            Write-Warning "  [FAILED] Could not verify '$($config.NewAdminName)' was added to Administrators."
            Write-SecLog "[ERROR] Failed to verify promotion of '$($config.NewAdminName)'."
        }
    } else { Write-Host "  [INFO] User '$($config.NewAdminName)' already exists. Skipping creation." -ForegroundColor Yellow }

    foreach ($user in $UsersToDemote) {
        $user = $user.Trim()
        if ($user -and ($user -ne $config.NewAdminName) -and ($user -ne "Administrator")) {
            net localgroup Administrators $user /delete
            # VERIFICATION
            if (-not ((Get-LocalGroupMember -Group 'Administrators').Name -contains $user)) {
                Write-Host "  [VERIFIED] Demoted user '$user'." -ForegroundColor Green
                Write-SecLog "Demoted user: $user"
            } else { Write-Warning "  [FAILED] Could not verify demotion of user '$user'." }
        }
    }
} catch { Write-Warning "  - Admin account management error: $_"; Write-SecLog "[ERROR] Admin management failed: $_" }

# --- 2. DEFENDER HARDENING: CFA, TAMPER, ASR ---
Write-Host "[2] Hardening Microsoft Defender..." -ForegroundColor Green
try {
    Set-MpPreference -EnableTamperProtection 1 -EnableControlledFolderAccess Enabled
    $asrRuleIds = @("56a863a9-875e-4185-98a7-b882c64b5ce5", "3b576869-a4ec-4529-8536-b80a7769e899", "d4f940ab-401b-4efc-aadc-ad5f3c50688a", "9e6c285a-c97e-4ad4-a890-1ce04d5e0674", "c1db55ab-c21a-4637-bb3f-a12568109d35", "92e97fa1-2edf-4476-bdd6-9dd38f7c9c35")
    Set-MpPreference -AttackSurfaceReductionRules_Ids $asrRuleIds -AttackSurfaceReductionRules_Actions Enabled
    # VERIFICATION
    $prefs = Get-MpPreference
    if ($prefs.EnableTamperProtection -and $prefs.EnableControlledFolderAccess -eq 1) {
        Write-Host "  [VERIFIED] Tamper Protection and Controlled Folder Access are enabled." -ForegroundColor Green
        $undoState.DefenderHardened = $true; Write-SecLog "Defender hardened successfully."
    } else { Write-Warning "  [FAILED] Could not verify Defender preferences were set." }
} catch { Write-Warning "  - Defender hardening error: $_"; Write-SecLog "[ERROR] Defender hardening failed: $_" }

# --- 3. BITLOCKER ENCRYPTION (TPM-ONLY) ---
Write-Host "[3] Managing BitLocker Encryption..." -ForegroundColor Green
try {
    $vol = Get-BitLockerVolume -MountPoint "C:"
    if ($vol.VolumeStatus -eq 'FullyDecrypted') {
        Write-Host "  - Enabling BitLocker on C:."
        manage-bde -on C: -skiphardwaretest
        Start-Sleep -Seconds 10 # Give service time to start encrypting
        # VERIFICATION
        $volAfter = Get-BitLockerVolume -MountPoint "C:"
        if ($volAfter.ProtectionStatus -eq 'On' -or $volAfter.VolumeStatus -eq 'Encrypting') {
            $recKey = (manage-bde -protectors -get C: | Select-String 'Numerical Password' -Context 0,1).Context.PostContext[0].Trim()
            Write-Host "  [VERIFIED] BitLocker encryption is active on C:. Recovery key saved." -ForegroundColor Green
            Write-SecLog "BitLocker enabled. ==> RECOVERY KEY: $recKey"; $undoState.BitLockerEnabled = $true
        } else { Write-Warning "  [FAILED] BitLocker failed to start encryption process." }
    } else { Write-Host "  [INFO] BitLocker is already active on C: ($($vol.VolumeStatus))." -ForegroundColor Yellow }
} catch { Write-Warning "  - BitLocker error: $_"; Write-SecLog "[ERROR] BitLocker failed: $_" }

# --- 4. LAPS CONFIGURATION ---
Write-Host "[4] Configuring LAPS..." -ForegroundColor Green
try {
    Set-LapsPolicy -Enable 1 -AdminAccountName $config.LapsAdminAccount -PasswordComplexity 4 -PasswordLength 15 -PasswordAgeDays 30
    # VERIFICATION
    if ((Get-LapsPolicy).Enable -eq 1) {
        $exp = (Get-LapsDiagnostics).ExpirationTimestamp
        Write-Host "  [VERIFIED] LAPS policy is enabled. Next rotation: $exp" -ForegroundColor Green
        Write-SecLog "LAPS enabled for '$($config.LapsAdminAccount)'."; $undoState.LapsConfigured = $true
    } else { Write-Warning "  [FAILED] Could not verify LAPS policy was enabled." }
} catch { Write-Warning "  - LAPS configuration error: $_"; Write-SecLog "[ERROR] LAPS configuration failed: $_" }

# --- 5. INSTALL WAZUH & SYSMON ---
Write-Host "[5] Checking for optional agents..." -ForegroundColor Green
# Wazuh
$wazuhMsi = Get-ChildItem (Join-Path $PSScriptRoot 'wazuh-agent*.msi') -ErrorAction SilentlyContinue | Select-Object -First 1
if ($wazuhMsi) {
    Write-Host "  - Found Wazuh installer. Installing..."
    try {
        Start-Process msiexec -ArgumentList "/i `"$($wazuhMsi.FullName)`" /qn WAZUH_MANAGER='$WazuhManagerIP'" -Wait
        # VERIFICATION
        if (Get-Service -Name 'WazuhSvc' -ErrorAction SilentlyContinue) {
            Write-Host "  [VERIFIED] Wazuh service is present." -ForegroundColor Green
            Write-SecLog "Wazuh agent installed."; $undoState.WazuhInstalled = $wazuhMsi.FullName
        } else { Write-Warning "  [FAILED] Wazuh service not found after installation." }
    } catch { Write-Warning "  - Wazuh install failed: $_"; Write-SecLog "[ERROR] Wazuh install failed: $_" }
}
# Sysmon
$sysmonExe=Join-Path $PSScriptRoot 'Sysmon64.exe'; $sysmonXml=Join-Path $PSScriptRoot 'sysmon.xml'
if ((Test-Path $sysmonExe) -and (Test-Path $sysmonXml)) {
    Write-Host "  - Found Sysmon. Installing..."
    try { 
        & $sysmonExe -accepteula -i $sysmonXml
        # VERIFICATION
        if (Get-Service -Name 'Sysmon64' -ErrorAction SilentlyContinue) {
            Write-Host "  [VERIFIED] Sysmon service is present." -ForegroundColor Green
            Write-SecLog "Sysmon installed."; $undoState.SysmonInstalled = $true
        } else { Write-Warning "  [FAILED] Sysmon service not found after installation." }
    } catch { Write-Warning "  - Sysmon install failed: $_"; Write-SecLog "[ERROR] Sysmon install failed: $_" }
}

# --- 6. OPTIONAL WDAC POLICY ---
Write-Host "[6] Checking for optional WDAC policy..." -ForegroundColor Green
$wdacPolicyBinary = "$env:SystemRoot\System32\CodeIntegrity\SIPolicy.p7b"
if (-not(Test-Path $wdacPolicyBinary)) {
    $wdacPolicyXml = Join-Path $PSScriptRoot 'WDAC_Policy.xml'
    if (Test-Path $wdacPolicyXml) {
        Write-Host "  - Found WDAC policy. Applying..."
        try {
            ConvertFrom-CIPolicy -XmlFilePath $wdacPolicyXml -BinaryFilePath $wdacPolicyBinary
            # VERIFICATION
            if (Test-Path $wdacPolicyBinary) {
                Write-Host "  [VERIFIED] WDAC policy binary created successfully." -ForegroundColor Green
                Write-SecLog "WDAC policy applied."; $undoState.WDACApplied = $true
            } else { Write-Warning "  [FAILED] Could not find WDAC policy binary after conversion." }
        } catch { Write-Warning "  - WDAC policy application failed: $_"; Write-SecLog "[ERROR] WDAC failed: $_" }
    }
} else { Write-Host "  [INFO] WDAC policy already exists. Skipping." -ForegroundColor Yellow }


# --- 7. OUTBOUND FIREWALL BLOCK ---
Write-Host "[7] Hardening Windows Firewall..." -ForegroundColor Green
try {
    netsh advfirewall set allprofiles firewallpolicy blockoutbound,allowinbound
    foreach ($rule in $config.FirewallAllowRules) {
        netsh advfirewall firewall add rule name="$($rule.Name)" dir=out action=allow protocol="$($rule.Protocol)" remoteport="$($rule.Port)" | Out-Null
    }
    # VERIFICATION
    $profiles = Get-NetFirewallProfile
    if (($profiles | Where-Object {$_.DefaultOutboundAction -eq 'Block'}).Count -eq $profiles.Count) {
        Write-Host "  [VERIFIED] All firewall profiles are set to Block Outbound by default." -ForegroundColor Green
        Write-SecLog "Firewall hardened."; $undoState.FirewallHardened = $true
    } else { Write-Warning "  [FAILED] Not all firewall profiles are set to Block Outbound." }
} catch { Write-Warning "  - Firewall hardening error: $_"; Write-SecLog "[ERROR] Firewall hardening failed: $_" }

# --- FINALIZATION: SAVE STATE FILE ---
Write-Host "`n[8] Finalizing and saving undo state..." -ForegroundColor Green
try {
    $stateFilePath = Join-Path $logFolder $config.StateFileName
    $undoState | ConvertTo-Json -Depth 5 | Out-File -FilePath $stateFilePath -Encoding UTF8
    Write-Host "  - Successfully saved undo data to '$stateFilePath'"
    Write-SecLog "Undo state file created successfully."
} catch { Write-Warning "  - CRITICAL: Could not save the undo state file: $_"; Write-SecLog "[FATAL] Failed to save undo state file: $_" }

Write-Host "`n=============================================" -ForegroundColor Green
Write-SecLog "Master harden script finished."
Write-Host "==      HARDENING SCRIPT COMPLETE     ==" -ForegroundColor Green
Write-Host "=============================================" -ForegroundColor Green
Write-Host "REMINDER: Eject this drive and store it securely NOW." -ForegroundColor Yellow
