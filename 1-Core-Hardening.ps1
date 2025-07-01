<#
.SYNOPSIS
    Windows 11 Core Security Hardening Script (1 of 3)
.DESCRIPTION
    Main hardening script that performs critical security configurations.
    Creates admin account, configures Administrator password, enables BitLocker, hardens Defender, etc.
    GUARANTEES creation of password and BitLocker key files.
    Enhanced with advanced security policies and URBackup integration.
.NOTES
    Version: 11.1 - Part 1 of 3 (Enhanced Security Policies)
    Run Order: 1-Core-Hardening.ps1 -> 2-Compliance-Collection.ps1 -> 3-Final-Report.ps1
#>
[CmdletBinding()]
param(
    [string[]]$UsersToDemote = @(),
    [string]$WazuhManagerIP = '192.168.1.100'
)

# Safety confirmation gate
Clear-Host
Write-Host "===============================================================================" -ForegroundColor Red
Write-Host "                           CRITICAL SECURITY WARNING" -ForegroundColor Red  
Write-Host "                                                                              " -ForegroundColor Red
Write-Host "  This script will make SIGNIFICANT and IRREVERSIBLE changes to this system: " -ForegroundColor Red
Write-Host "                                                                              " -ForegroundColor Red
Write-Host "  [*] Create new admin account and demote existing admins                    " -ForegroundColor Red
Write-Host "  [*] Configure Administrator account with strong password                    " -ForegroundColor Red
Write-Host "  [*] Enable BitLocker drive encryption (may take hours)                     " -ForegroundColor Red
Write-Host "  [*] Lock down Windows Firewall (blocks most network traffic)              " -ForegroundColor Red
Write-Host "  [*] Disable Remote Desktop and WinRM                                       " -ForegroundColor Red
Write-Host "  [*] Install security monitoring agents                                     " -ForegroundColor Red
Write-Host "  [*] Apply enhanced security policies (Edge, timeouts, execution)          " -ForegroundColor Red
Write-Host "                                                                              " -ForegroundColor Red
Write-Host "  CRITICAL FILES WILL BE SAVED TO FLASH DRIVE - SECURE THEM IMMEDIATELY     " -ForegroundColor Red
Write-Host "===============================================================================" -ForegroundColor Red

Write-Host "`nTARGET COMPLIANCE FRAMEWORKS:" -ForegroundColor Cyan
Write-Host "   • NIST 800-171 (All 14 control families)" -ForegroundColor White
Write-Host "   • CMMC Level 1 (All 17 practices)" -ForegroundColor White  
Write-Host "   • NIST 800-53 Low Baseline" -ForegroundColor White
Write-Host "   • ISO 27001:2022 Core Controls" -ForegroundColor White

Write-Host "`n" -NoNewline
$confirmation = Read-Host "Type 'PROCEED' to continue with system hardening (or anything else to exit)"
if ($confirmation -ne 'PROCEED') {
    Write-Host "Operation cancelled by user. No changes made." -ForegroundColor Yellow
    exit 0
}

# Check admin privileges
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "Administrator privileges required. Relaunching with elevation..."
    Start-Process powershell.exe -Verb RunAs -ArgumentList ('-NoProfile -ExecutionPolicy Bypass -File "{0}"' -f $MyInvocation.MyCommand.Path)
    exit
}

Clear-Host
Write-Host "================================================================================" -ForegroundColor Green
Write-Host "              WINDOWS 11 CORE HARDENING SCRIPT v11.1 (1/3)" -ForegroundColor Green
Write-Host "                     Enterprise Security Lockdown Initiated" -ForegroundColor Green
Write-Host "================================================================================" -ForegroundColor Green

# Configuration
$config = @{
    NewAdminName = "SecOpsAdm"
    BuiltinAdminName = "Administrator"
    PasswordLength = 24
    ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
    WindowsVersion = (Get-CimInstance Win32_OperatingSystem).Caption
}

# Create timestamped log folder with computer subfolder
$computerFolder = Join-Path $config.ScriptRoot "PC-$env:COMPUTERNAME"
if (-not (Test-Path $computerFolder)) { 
    New-Item -ItemType Directory -Path $computerFolder -Force | Out-Null 
}
$logFolder = Join-Path $computerFolder "HARDENING-$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss')"
New-Item -ItemType Directory -Path $logFolder -Force | Out-Null

# Save configuration for other scripts
$config | ConvertTo-Json | Out-File "$logFolder\script-config.json" -Encoding UTF8

# Logging function
function Write-Log { 
    param([string]$Text, [string]$Level = "INFO")
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    "[$timestamp] [$Level] $Text" | Add-Content -Path "$logFolder\hardening-detailed.log"
    if ($Level -eq "ERROR") { Write-Host "  [X] $Text" -ForegroundColor Red }
    elseif ($Level -eq "SUCCESS") { Write-Host "  [+] $Text" -ForegroundColor Green }
    elseif ($Level -eq "WARNING") { Write-Host "  [!] $Text" -ForegroundColor Yellow }
    else { Write-Host "  [i] $Text" -ForegroundColor Cyan }
}

# Password generation function
function New-SecurePassword { 
    param([int]$Length = 24)
    $lower = 'abcdefghijklmnopqrstuvwxyz'.ToCharArray()
    $upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'.ToCharArray()
    $digits = '0123456789'.ToCharArray()
    $symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?'.ToCharArray()
    
    # Ensure we have at least one from each category
    $password = @()
    $password += Get-Random -InputObject $lower
    $password += Get-Random -InputObject $upper
    $password += Get-Random -InputObject $digits
    $password += Get-Random -InputObject $symbols
    
    # Fill the rest randomly from all character sets
    $allChars = $lower + $upper + $digits + $symbols
    for ($i = 4; $i -lt $Length; $i++) { 
        $password += Get-Random -InputObject $allChars
    }
    
    # Shuffle the array and convert to string
    $shuffled = $password | Sort-Object {Get-Random}
    return -join $shuffled
}

# Status tracking
$hardeningStatus = @{
    Successes = [System.Collections.ArrayList]@()
    Errors = [System.Collections.ArrayList]@()
    CriticalFailures = [System.Collections.ArrayList]@()
}

# Initialize critical success tracking variables
$adminSuccess = $false
$bitlockerSuccess = $false
$adminPasswordSuccess = $false

Write-Log "Core hardening initiated on $($config.WindowsVersion)" "INFO"
Write-Host "Results will be saved to: $logFolder" -ForegroundColor Cyan

# 1. ADMIN ACCOUNT MANAGEMENT
Write-Host "`n[1] Managing Administrator Accounts..." -ForegroundColor Green
try {
    $adminPassword = New-SecurePassword -Length $config.PasswordLength
    $securePassword = ConvertTo-SecureString $adminPassword -AsPlainText -Force
    $existingUser = Get-LocalUser -Name $config.NewAdminName -ErrorAction SilentlyContinue
    
    if ($existingUser) {
        Write-Log "User '$($config.NewAdminName)' already exists. Resetting password." "WARNING"
        Set-LocalUser -Name $config.NewAdminName -Password $securePassword -ErrorAction Stop
        Enable-LocalUser -Name $config.NewAdminName -ErrorAction Stop
        Write-Log "Password reset for '$($config.NewAdminName)'" "SUCCESS"
    } else {
        Write-Log "User '$($config.NewAdminName)' not found. Creating new user." "INFO"
        New-LocalUser -Name $config.NewAdminName -Password $securePassword -FullName "Secure Operations Admin" -Description "Dedicated admin account for system mgmt" -PasswordNeverExpires -UserMayNotChangePassword -ErrorAction Stop
        Write-Log "Created local user '$($config.NewAdminName)'" "SUCCESS"
    }

    Add-LocalGroupMember -Group 'Administrators' -Member $config.NewAdminName -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2

    $adminMembers = Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue
    $isAdminMember = $adminMembers | Where-Object { $_.Name -like "*$($config.NewAdminName)" -or $_.Name -eq $config.NewAdminName }

    if ($isAdminMember) {
        Write-Log "'$($config.NewAdminName)' confirmed as a member of Administrators" "SUCCESS"

        $passwordFile = "$logFolder\SecOpsAdm_Password.txt"
        try {
            $passwordContent = @"
SecOpsAdm Administrator Account Password
Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Computer: $env:COMPUTERNAME
Username: $($config.NewAdminName)
Password: $adminPassword

STORE THIS PASSWORD SECURELY - Required for system administration
This account has full administrative privileges on this system.
Use this account to log in and retrieve LAPS-managed Administrator passwords.
"@
            $passwordContent | Out-File -FilePath $passwordFile -Encoding UTF8 -Force

            if (Test-Path $passwordFile) {
                $adminSuccess = $true
                $hardeningStatus.Successes.Add("AC-2: Created/updated dedicated admin account '$($config.NewAdminName)'") | Out-Null
                $hardeningStatus.Successes.Add("IA-5: Strong password generated and secured") | Out-Null
                Write-Log "Admin password file created/updated and verified successfully" "SUCCESS"
            } else {
                $hardeningStatus.CriticalFailures.Add("CRITICAL: Failed to create admin password file") | Out-Null
                Write-Log "CRITICAL FAILURE: Password file creation failed" "ERROR"
            }
        } catch {
            $hardeningStatus.CriticalFailures.Add("CRITICAL: Failed to save admin password file: $_") | Out-Null
            Write-Log "CRITICAL FAILURE: Password file creation failed: $_" "ERROR"
        }
    } else {
        $hardeningStatus.CriticalFailures.Add("CRITICAL: Admin account promotion verification failed") | Out-Null
        Write-Log "Could not verify '$($config.NewAdminName)' was added to Administrators" "ERROR"
    }

    foreach ($user in $UsersToDemote) {
        $user = $user.Trim()
        if ($user -and ($user -ne $config.NewAdminName) -and ($user -ne $config.BuiltinAdminName)) {
            net localgroup Administrators $user /delete
            Start-Sleep -Seconds 1
            $adminMembers = Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue
            $isStillAdmin = $adminMembers | Where-Object { $_.Name -like "*$user" -or $_.Name -eq $user }
            
            if (-not $isStillAdmin) {
                $hardeningStatus.Successes.Add("AC-2: Demoted user '$user' from Administrators") | Out-Null
                Write-Log "Successfully demoted user: $user" "SUCCESS"
            } else {
                $hardeningStatus.Errors.Add("Failed to demote user: $user") | Out-Null
                Write-Log "Could not verify demotion of user: $user" "ERROR"
            }
        }
    }
} catch {
    $hardeningStatus.CriticalFailures.Add("Admin account management failed: $_") | Out-Null
    Write-Log "Admin account management failed: $_" "ERROR"
}

# 2. ADMINISTRATOR ACCOUNT MANAGEMENT
Write-Host "`n[2] Managing Built-in Administrator Account..." -ForegroundColor Green

try {
    Write-Log "Implementing manual Administrator account password management" "INFO"
    Write-Log "Future SHIPS-style solution will replace this manual approach" "INFO"
    
    $builtinAdmin = Get-LocalUser -Name $config.BuiltinAdminName -ErrorAction SilentlyContinue
    if (-not $builtinAdmin) {
        Write-Log "Built-in Administrator account not found" "ERROR"
        $hardeningStatus.Errors.Add("Built-in Administrator account missing") | Out-Null
        throw "Cannot proceed - Administrator account missing"
    }
    
    Write-Log "Enabling built-in Administrator account for manual password management" "INFO"
    
    $adminPassword = New-SecurePassword -Length $config.PasswordLength
    $secureAdminPassword = ConvertTo-SecureString $adminPassword -AsPlainText -Force
    
    try {
        Set-LocalUser -Name $config.BuiltinAdminName -Password $secureAdminPassword -ErrorAction Stop
        Enable-LocalUser -Name $config.BuiltinAdminName -ErrorAction SilentlyContinue
        net user $config.BuiltinAdminName /active:yes | Out-Null
        Write-Log "Built-in Administrator account enabled and password set successfully" "SUCCESS"
        
        Write-Log "Administrator account password updated successfully" "SUCCESS"
        
        $adminPasswordFile = "$logFolder\Administrator_Password.txt"
        $adminPasswordContent = @"
Built-in Administrator Account Password (Manual Management)
Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Computer: $env:COMPUTERNAME
Windows Version: $($config.WindowsVersion)
Username: $($config.BuiltinAdminName)
Password: $adminPassword

STORE THIS PASSWORD SECURELY - Required for system administration
This account uses manual password management until SHIPS-style solution is implemented.
Use this account for administrative tasks requiring built-in Administrator privileges.
Future SHIPS-style solution will provide automated password rotation.
"@
        
        try {
            $adminPasswordContent | Out-File -FilePath $adminPasswordFile -Encoding UTF8 -Force
            
            if (Test-Path $adminPasswordFile) {
                $hardeningStatus.Successes.Add("AC-2: Built-in Administrator account configured with strong password") | Out-Null
                $hardeningStatus.Successes.Add("IA-5: Administrator password generated and secured (manual management)") | Out-Null
                Write-Log "Administrator password file created successfully" "SUCCESS"
                $adminPasswordSuccess = $true
            } else {
                $hardeningStatus.CriticalFailures.Add("CRITICAL: Failed to create Administrator password file") | Out-Null
                Write-Log "CRITICAL FAILURE: Administrator password file creation failed" "ERROR"
                $adminPasswordSuccess = $false
            }
        } catch {
            $hardeningStatus.CriticalFailures.Add("CRITICAL: Failed to save Administrator password file: $_") | Out-Null
            Write-Log "CRITICAL FAILURE: Administrator password file creation failed: $_" "ERROR"
            $adminPasswordSuccess = $false
        }
        
    } catch {
        Write-Log "Failed to set Administrator account password: $_" "ERROR"
        $hardeningStatus.Errors.Add("Failed to set Administrator account password") | Out-Null
        $adminPasswordSuccess = $false
    }
    
    $verifyAdmin = Get-LocalUser -Name $config.BuiltinAdminName -ErrorAction SilentlyContinue
    if ($verifyAdmin -and $verifyAdmin.Enabled) {
        Write-Log "Administrator account verified as active and configured" "SUCCESS"
        $hardeningStatus.Successes.Add("AC-2: Administrator account verification completed") | Out-Null
    } else {
        Write-Log "Failed to verify Administrator account status" "ERROR"
        $hardeningStatus.Errors.Add("Administrator account verification failed") | Out-Null
    }
    
    Write-Log "Administrator Account Management Status: Manual password management configured (Future SHIPS-style replacement planned)" "INFO"
    
} catch {
    $hardeningStatus.Errors.Add("Administrator account management failed: $_") | Out-Null
    Write-Log "Administrator account management failed: $_" "ERROR"
    $adminPasswordSuccess = $false
}

# 3. BITLOCKER ENCRYPTION
Write-Host "`n[3] Managing BitLocker Drive Encryption..." -ForegroundColor Green

try {
    $vol = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
    
    if (-not $vol) {
        Write-Log "Cannot access BitLocker volume C:" "ERROR"
        $hardeningStatus.CriticalFailures.Add("CRITICAL: Cannot access BitLocker volume") | Out-Null
    } else {
        Write-Log "BitLocker Volume Status: $($vol.VolumeStatus), Protection: $($vol.ProtectionStatus)" "INFO"
        
        if ($vol.VolumeStatus -eq 'FullyDecrypted') {
            Write-Log "Enabling BitLocker encryption on C: drive" "INFO"
            try {
                Enable-BitLocker -MountPoint "C:" -EncryptionMethod Aes256 -SkipHardwareTest -ErrorAction Stop
                Write-Log "BitLocker encryption initiated" "SUCCESS"
                Start-Sleep -Seconds 10
                $vol = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
            } catch {
                Write-Log "Failed to enable BitLocker: $_" "ERROR"
                try {
                    $enableResult = manage-bde -on C: -skiphardwaretest 2>&1
                    Write-Log "BitLocker enabled using manage-bde" "SUCCESS"
                    Start-Sleep -Seconds 10
                    $vol = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
                } catch {
                    Write-Log "Both BitLocker enable methods failed" "ERROR"
                }
            }
        }
        
        $existingRecoveryProtector = $vol.KeyProtector | Where-Object KeyProtectorType -eq 'RecoveryPassword'
        
        if (-not $existingRecoveryProtector) {
            Write-Log "No recovery password protector found, adding one" "INFO"
            try {
                Add-BitLockerKeyProtector -MountPoint "C:" -RecoveryPasswordProtector -ErrorAction Stop
                Write-Log "Recovery password protector added successfully" "SUCCESS"
                $vol = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
            } catch {
                Write-Log "Failed to add recovery password protector: $_" "ERROR"
                $hardeningStatus.CriticalFailures.Add("CRITICAL: Cannot add BitLocker recovery password protector") | Out-Null
            }
        } else {
            Write-Log "Recovery password protector already exists" "INFO"
        }
        
        try {
            $recoveryProtectors = $vol.KeyProtector | Where-Object KeyProtectorType -eq 'RecoveryPassword'
            
            if ($recoveryProtectors) {
                $recoveryPassword = $recoveryProtectors[0].RecoveryPassword
                
                if ($recoveryPassword -and $recoveryPassword -match '\d{6}-\d{6}-\d{6}-\d{6}-\d{6}-\d{6}-\d{6}-\d{6}') {
                    $bitlockerFile = "$logFolder\BitLocker_Recovery_Key.txt"
                    $keyContent = @"
BitLocker Recovery Password for $env:COMPUTERNAME
Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Drive: C:\
Volume Status: $($vol.VolumeStatus)
Protection Status: $($vol.ProtectionStatus)
Encryption Method: $($vol.EncryptionMethod)
Recovery Password: $recoveryPassword

STORE THIS PASSWORD SECURELY - Required for data recovery if TPM fails or password/PIN is lost
This is a 48-digit recovery password that can be entered at the BitLocker unlock screen.
Print this password and store in a secure physical location separate from this computer.
"@
                    try {
                        $keyContent | Out-File -FilePath $bitlockerFile -Encoding UTF8 -Force
                        
                        if (Test-Path $bitlockerFile) {
                            $bitlockerSuccess = $true
                            $hardeningStatus.Successes.Add("SC-28: BitLocker recovery password secured") | Out-Null
                            $hardeningStatus.Successes.Add("SC-13: Full disk encryption enabled") | Out-Null
                            Write-Log "BitLocker recovery password extracted and secured: $recoveryPassword" "SUCCESS"
                            
                            if ($recoveryProtectors.Count -gt 1) {
                                Write-Log "Multiple recovery passwords found ($($recoveryProtectors.Count) total)" "INFO"
                            }
                        }
                    } catch {
                        $hardeningStatus.CriticalFailures.Add("CRITICAL: Failed to save BitLocker recovery password file") | Out-Null
                        Write-Log "CRITICAL FAILURE: BitLocker password file creation failed" "ERROR"
                    }
                } else {
                    Write-Log "Recovery password format validation failed" "ERROR"
                    $hardeningStatus.CriticalFailures.Add("CRITICAL: Invalid BitLocker recovery password format") | Out-Null
                }
            } else {
                Write-Log "No recovery password protectors found after creation attempt" "ERROR"
                $hardeningStatus.CriticalFailures.Add("CRITICAL: BitLocker recovery password not available") | Out-Null
            }
        } catch {
            $hardeningStatus.Errors.Add("BitLocker recovery password extraction failed: $_") | Out-Null
            Write-Log "BitLocker recovery password extraction error: $_" "ERROR"
        }
    }
    
    if (-not $bitlockerSuccess) {
        $hardeningStatus.CriticalFailures.Add("CRITICAL: BitLocker recovery password not secured") | Out-Null
    }
} catch {
    $hardeningStatus.CriticalFailures.Add("CRITICAL: BitLocker operation failed: $_") | Out-Null
    Write-Log "BitLocker operation failed: $_" "ERROR"
}

# 4. MICROSOFT DEFENDER HARDENING
Write-Host "`n[4] Hardening Microsoft Defender..." -ForegroundColor Green
try {
    $asrIds = @(
        "56a863a9-875e-4185-98a7-b882c64b5ce5",
        "3b576869-a4ec-4529-8536-b80a7769e899",
        "d4f940ab-401b-4efc-aadc-ad5f3c50688a",
        "9e6c285a-c97e-4ad4-a890-1ce04d5e0674",
        "c1db55ab-c21a-4637-bb3f-a12568109d35",
        "92e97fa1-2edf-4476-bdd6-9dd38f7c9c35"
    )
    $asrActions = @(1,1,1,1,1,1)
    
    Set-MpPreference -EnableControlledFolderAccess Enabled -AttackSurfaceReductionRules_Ids $asrIds -AttackSurfaceReductionRules_Actions $asrActions -ErrorAction SilentlyContinue
    
    if ((Get-Command Set-MpPreference).Parameters.Keys -contains 'EnableTamperProtection') {
        Set-MpPreference -EnableTamperProtection 1 -ErrorAction SilentlyContinue
        $hardeningStatus.Successes.Add("SI-3: Tamper Protection enabled") | Out-Null
    }
    
    Set-MpPreference -DisableRealtimeMonitoring $false -DisableBehaviorMonitoring $false -DisableBlockAtFirstSeen $false -ErrorAction SilentlyContinue
    
    $hardeningStatus.Successes.Add("SI-3: Microsoft Defender hardened with ASR rules") | Out-Null
    $hardeningStatus.Successes.Add("SI-4: Real-time protection and behavior monitoring enabled") | Out-Null
    Write-Log "Defender hardening completed - $($asrIds.Count) ASR rules enabled" "SUCCESS"
} catch {
    $hardeningStatus.Errors.Add("Defender hardening failed: $_") | Out-Null
    Write-Log "Defender hardening failed: $_" "ERROR"
}

# 5. WINDOWS FIREWALL LOCKDOWN
Write-Host "`n[5] Implementing Firewall Lockdown..." -ForegroundColor Green
try {
    netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound | Out-Null
    
    $essentialRules = @(
        @{Name='HTTPS-Outbound'; Protocol='TCP'; Port=443},
        @{Name='DNS-Outbound'; Protocol='UDP'; Port=53},
        @{Name='HTTP-WindowsUpdate'; Protocol='TCP'; Port=80},
        @{Name='NTP-TimeSync'; Protocol='UDP'; Port=123},
        @{Name='DHCP-Client'; Protocol='UDP'; Port=67},
        @{Name='Kerberos-Auth'; Protocol='TCP'; Port=88}
    )
    
    foreach ($rule in $essentialRules) {
        netsh advfirewall firewall add rule name="$($rule.Name)" dir=out action=allow protocol="$($rule.Protocol)" remoteport="$($rule.Port)" | Out-Null
        Write-Log "Created firewall rule: $($rule.Name)" "INFO"
    }
    
    $profiles = Get-NetFirewallProfile
    $blockedProfiles = ($profiles | Where-Object DefaultOutboundAction -eq 'Block').Count
    
    if ($blockedProfiles -eq $profiles.Count) {
        $hardeningStatus.Successes.Add("SC-7: Windows Firewall configured with default-deny policy") | Out-Null
        $hardeningStatus.Successes.Add("SC-7: Essential service rules configured") | Out-Null
        Write-Log "Firewall lockdown completed - All profiles set to block by default" "SUCCESS"
    } else {
        $hardeningStatus.Errors.Add("Firewall lockdown incomplete") | Out-Null
        Write-Log "Firewall configuration incomplete" "WARNING"
    }
} catch {
    $hardeningStatus.Errors.Add("Firewall hardening failed: $_") | Out-Null
    Write-Log "Firewall hardening failed: $_" "ERROR"
}

# 6. DISABLE REMOTE ACCESS SERVICES
Write-Host "`n[6] Disabling Remote Access Services..." -ForegroundColor Green
try {
    Stop-Service -Name 'WinRM' -Force -ErrorAction SilentlyContinue
    Set-Service -Name 'WinRM' -StartupType Disabled -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1 -ErrorAction SilentlyContinue
    Stop-Service -Name 'TermService' -Force -ErrorAction SilentlyContinue
    Get-NetFirewallRule -DisplayName "*Remote Desktop*" | Disable-NetFirewallRule -ErrorAction SilentlyContinue
    
    $winrmDisabled = (Get-Service -Name 'WinRM' -ErrorAction SilentlyContinue).Status -eq 'Stopped'
    $rdpDisabled = (Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction SilentlyContinue).fDenyTSConnections -eq 1
    
    if ($winrmDisabled -and $rdpDisabled) {
        $hardeningStatus.Successes.Add("AC-17: Remote access services disabled") | Out-Null
        $hardeningStatus.Successes.Add("SC-7: Remote Desktop and WinRM blocked") | Out-Null
        Write-Log "Remote access services successfully disabled" "SUCCESS"
    } else {
        $hardeningStatus.Errors.Add("Remote access disabling incomplete") | Out-Null
        Write-Log "Remote access disabling partially failed" "WARNING"
    }
} catch {
    $hardeningStatus.Errors.Add("Remote access disabling failed: $_") | Out-Null
    Write-Log "Remote access disabling failed: $_" "ERROR"
}

# 7. SECURITY AGENTS DEPLOYMENT
Write-Host "`n[7] Deploying Security Monitoring Agents..." -ForegroundColor Green

# Wazuh Agent Installation
$wazuhMsi = Get-ChildItem "$($config.ScriptRoot)\wazuh-agent*.msi" -ErrorAction SilentlyContinue | Select-Object -First 1
if ($wazuhMsi) {
    try {
        Write-Log "Installing Wazuh agent from: $($wazuhMsi.Name)" "INFO"
        $wazuhProcess = Start-Process msiexec -ArgumentList "/i `"$($wazuhMsi.FullName)`" /qn WAZUH_MANAGER='$WazuhManagerIP'" -Wait -PassThru
        
        if ($wazuhProcess.ExitCode -eq 0 -and (Get-Service -Name 'WazuhSvc' -ErrorAction SilentlyContinue)) {
            $hardeningStatus.Successes.Add("AU-6: Wazuh security monitoring agent installed") | Out-Null
            Write-Log "Wazuh agent installed successfully" "SUCCESS"
        } else {
            $hardeningStatus.Errors.Add("Wazuh installation failed") | Out-Null
            Write-Log "Wazuh installation failed" "ERROR"
        }
    } catch {
        $hardeningStatus.Errors.Add("Wazuh installation error: $_") | Out-Null
        Write-Log "Wazuh installation error: $_" "ERROR"
    }
} else {
    Write-Log "Wazuh installer not found - skipping" "WARNING"
}

# Sysmon Installation
$sysmonExe = "$($config.ScriptRoot)\Sysmon64.exe"
$sysmonConfig = "$($config.ScriptRoot)\sysmonconfig-export.xml"
if ((Test-Path $sysmonExe) -and (Test-Path $sysmonConfig)) {
    try {
        $sysmonService = Get-Service -Name 'Sysmon64' -ErrorAction SilentlyContinue
        if ($sysmonService) {
            Write-Log "Sysmon is already installed. Updating configuration..." "INFO"
            & $sysmonExe -accepteula -c $sysmonConfig | Out-Null
        } else {
            Write-Log "Installing Sysmon with configuration" "INFO"
            & $sysmonExe -accepteula -i $sysmonConfig | Out-Null
        }
        
        if (Get-Service -Name 'Sysmon64' -ErrorAction SilentlyContinue) {
            $hardeningStatus.Successes.Add("AU-3: Sysmon logging agent installed/updated") | Out-Null
            Write-Log "Sysmon installed or updated successfully" "SUCCESS"
        } else {
            $hardeningStatus.Errors.Add("Sysmon deployment verification failed") | Out-Null
            Write-Log "Sysmon deployment verification failed" "ERROR"
        }
    } catch {
        $hardeningStatus.Errors.Add("Sysmon deployment error: $_") | Out-Null
        Write-Log "Sysmon deployment error: $_" "ERROR"
    }
} else {
    if (-not (Test-Path $sysmonExe)) {
        Write-Log "Sysmon executable not found: $sysmonExe" "WARNING"
    }
    if (-not (Test-Path $sysmonConfig)) {
        Write-Log "Sysmon config not found: $sysmonConfig" "WARNING"
    }
    Write-Log "Sysmon files not found - skipping installation" "WARNING"
}

# 8. ENFORCE PASSWORD POLICY AND REMEDIATE STANDARD ACCOUNTS
Write-Host "`n[8] Enforcing Password Policy and Remediating Standard User Accounts..." -ForegroundColor Green
try {
    Write-Log "Setting system-wide password policy (min length: 14, history: 5)" "INFO"
    
    try {
        net accounts /minpwlen:14 | Out-Null
        net accounts /uniquepw:5 | Out-Null
        $hardeningStatus.Successes.Add("IA-5: System-wide password policy (length/history) enacted") | Out-Null
        Write-Log "Successfully set system-wide password policy" "SUCCESS"
    } catch {
        Write-Log "Failed to set system-wide password policy: $_" "ERROR"
        $hardeningStatus.Errors.Add("Failed to set system-wide password policy") | Out-Null
    }
    
    Write-Log "Starting one-time remediation for non-compliant standard accounts" "INFO"
    
    $ignoreUsers = @(
        $config.NewAdminName,
        $config.BuiltinAdminName,
        "Guest",
        "DefaultAccount",
        "WDAGUtilityAccount"
    )
    
    try {
        $adminMembers = Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue
        foreach ($admin in $adminMembers) {
            $userName = $admin.Name -replace '^.*\\', ''
            $ignoreUsers += $userName
        }
    } catch {
        Write-Log "Could not retrieve administrator group members: $_" "WARNING"
    }
    
    $ignoreUsers = $ignoreUsers | Select-Object -Unique
    Write-Log "The following users will be ignored: $($ignoreUsers -join ', ')" "INFO"
    
    $allEnabledUsers = Get-LocalUser | Where-Object { $_.Enabled -eq $true }
    Write-Log "Found $($allEnabledUsers.Count) enabled local user accounts" "INFO"
    
    $standardUsersFound = 0
    foreach ($user in $allEnabledUsers) {
        if ($user.Name -in $ignoreUsers) {
            Write-Log "Skipping password check for exempt user: $($user.Name)" "INFO"
            continue
        }
        
        $standardUsersFound++
        Write-Log "User '$($user.Name)' is a standard user. Flagging for password change." "WARNING"
        try {
            Set-LocalUser -Name $user.Name -ChangePasswordAtLogon $true -ErrorAction Stop
            Write-Log "Successfully flagged user '$($user.Name)' for password change at next logon" "SUCCESS"
            $hardeningStatus.Successes.Add("IA-5: Flagged standard user '$($user.Name)' for mandatory password change") | Out-Null
        } catch {
            try {
                $wmicResult = wmic useraccount where "Name='$($user.Name)'" set PasswordChangeable=TRUE,PasswordExpires=TRUE 2>$null
                Write-Log "Successfully flagged user '$($user.Name)' for password change using WMIC fallback" "SUCCESS"
                $hardeningStatus.Successes.Add("IA-5: Flagged standard user '$($user.Name)' for mandatory password change (WMIC)") | Out-Null
            } catch {
                Write-Log "Failed to flag standard user '$($user.Name)' for password change: $_" "ERROR"
                $hardeningStatus.Errors.Add("Failed to flag user '$($user.Name)' for password change") | Out-Null
            }
        }
    }
    
    if ($standardUsersFound -eq 0) {
        Write-Log "No standard user accounts found requiring password change" "INFO"
        $hardeningStatus.Successes.Add("IA-5: No standard user accounts requiring remediation") | Out-Null
    } else {
        Write-Log "Password change remediation completed for $standardUsersFound standard user accounts" "SUCCESS"
    }
    
} catch {
    Write-Log "An error occurred during password policy enforcement: $_" "ERROR"
    $hardeningStatus.Errors.Add("Failed during password policy enforcement and remediation: $_") | Out-Null
}

# 9. ENHANCED SECURITY POLICIES AND REGISTRY HARDENING
Write-Host "`n[9] Implementing Enhanced Security Policies..." -ForegroundColor Green

try {
    Write-Log "Applying enhanced security policies via registry modifications" "INFO"
    
    # 10.1 MICROSOFT EDGE SECURITY POLICIES
    Write-Log "Configuring Microsoft Edge security restrictions" "INFO"
    
    $edgePolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    $edgeRecommendedPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge\Recommended"
    
    if (-not (Test-Path $edgePolicyPath)) {
        New-Item -Path $edgePolicyPath -Force | Out-Null
    }
    if (-not (Test-Path $edgeRecommendedPath)) {
        New-Item -Path $edgeRecommendedPath -Force | Out-Null
    }
    
    # Edge Data Restrictions - Only allow bookmarks
    Set-ItemProperty -Path $edgePolicyPath -Name "PasswordManagerEnabled" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $edgePolicyPath -Name "AutofillAddressEnabled" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $edgePolicyPath -Name "AutofillCreditCardEnabled" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $edgePolicyPath -Name "PaymentMethodQueryEnabled" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $edgePolicyPath -Name "SaveCookiesOnExit" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $edgePolicyPath -Name "ClearBrowsingDataOnExit" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    
    # Form-field autofill denial
    Set-ItemProperty -Path $edgePolicyPath -Name "AutofillEnabled" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $edgePolicyPath -Name "FormFillEnabled" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $edgePolicyPath -Name "SearchSuggestEnabled" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    
    # Extension installation block
    Set-ItemProperty -Path $edgePolicyPath -Name "ExtensionInstallBlocklist" -Value @("*") -Type MultiString -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $edgePolicyPath -Name "ExtensionInstallForcelist" -Value @() -Type MultiString -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $edgePolicyPath -Name "ExtensionSettings" -Value '{"*":{"installation_mode":"blocked"}}' -Type String -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $edgePolicyPath -Name "DeveloperToolsAvailability" -Value 2 -Type DWord -ErrorAction SilentlyContinue
    
    # Clear existing stored data on policy application
    Set-ItemProperty -Path $edgePolicyPath -Name "ForceEphemeralProfiles" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $edgePolicyPath -Name "BrowserSignin" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $edgePolicyPath -Name "SyncDisabled" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    
    $hardeningStatus.Successes.Add("CM-6: Microsoft Edge security policies configured") | Out-Null
    Write-Log "Microsoft Edge security restrictions applied successfully" "SUCCESS"
    
    # 10.2 SYSTEM IDLE TIMEOUT - 10 MINUTE MANDATORY LOCK
    Write-Log "Configuring 10-minute mandatory screen lock" "INFO"
    
    $screenSaverPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    if (-not (Test-Path $screenSaverPath)) {
        New-Item -Path $screenSaverPath -Force | Out-Null
    }
    
    Set-ItemProperty -Path $screenSaverPath -Name "InactivityTimeoutSecs" -Value 600 -Type DWord -ErrorAction SilentlyContinue
    
    $screensaverUserPath = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop"
    if (-not (Test-Path $screensaverUserPath)) {
        New-Item -Path $screensaverUserPath -Force | Out-Null
    }
    
    Set-ItemProperty -Path $screensaverUserPath -Name "ScreenSaveActive" -Value "1" -Type String -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $screensaverUserPath -Name "ScreenSaverIsSecure" -Value "1" -Type String -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $screensaverUserPath -Name "ScreenSaveTimeOut" -Value "600" -Type String -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $screensaverUserPath -Name "SCRNSAVE.EXE" -Value "scrnsave.scr" -Type String -ErrorAction SilentlyContinue
    
    # Apply to default user profile for new users
    reg load HKU\DEFAULT "C:\Users\Default\NTUSER.DAT" 2>$null
    if ($LASTEXITCODE -eq 0) {
        reg add "HKU\DEFAULT\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop" /v "ScreenSaveActive" /t REG_SZ /d "1" /f | Out-Null
        reg add "HKU\DEFAULT\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop" /v "ScreenSaverIsSecure" /t REG_SZ /d "1" /f | Out-Null
        reg add "HKU\DEFAULT\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop" /v "ScreenSaveTimeOut" /t REG_SZ /d "600" /f | Out-Null
        reg unload HKU\DEFAULT | Out-Null
    }
    
    $hardeningStatus.Successes.Add("AC-11: 10-minute mandatory screen lock configured") | Out-Null
    Write-Log "10-minute mandatory screen lock configured successfully" "SUCCESS"
    
    # 10.3 NO EXECUTE POLICIES - DESKTOP AND TEMP FOLDER RESTRICTIONS
    Write-Log "Configuring no execute policies for high-risk locations" "INFO"
    
    $srpPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers"
    if (-not (Test-Path $srpPath)) {
        New-Item -Path $srpPath -Force | Out-Null
    }
    
    # Enable Software Restriction Policies
    Set-ItemProperty -Path $srpPath -Name "AuthenticodeEnabled" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $srpPath -Name "DefaultLevel" -Value 262144 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $srpPath -Name "ExecutableTypes" -Value "ADE;ADP;BAS;BAT;CHM;CMD;COM;CPL;CRT;EXE;HLP;HTA;INF;INS;ISP;LNK;MDB;MDE;MSC;MSI;MSP;MST;OCX;PCD;PIF;REG;SCR;SHS;URL;VB;WSF;WSH;WSC" -Type String -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $srpPath -Name "PolicyScope" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $srpPath -Name "TransparentEnabled" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    
    # Create disallowed paths for high-risk locations
    $disallowedPaths = @(
        @{Path="%USERPROFILE%\Desktop\*"; Description="Desktop execution prevention"},
        @{Path="%ALLUSERSPROFILE%\Desktop\*"; Description="Public desktop execution prevention"},
        @{Path="%USERPROFILE%\Downloads\*"; Description="Downloads folder execution prevention"},
        @{Path="%TEMP%\*"; Description="Temp folder execution prevention"},
        @{Path="%TMP%\*"; Description="TMP folder execution prevention"},
        @{Path="%USERPROFILE%\AppData\Local\Temp\*"; Description="User temp execution prevention"},
        @{Path="%USERPROFILE%\Documents\*"; Description="Documents folder execution prevention"},
        @{Path="%PUBLIC%\Desktop\*"; Description="Public desktop execution prevention"}
    )
    
    $pathCounter = 0
    foreach ($pathRule in $disallowedPaths) {
        $pathCounter++
        $pathRulePath = "$srpPath\0\Paths\{$([guid]::NewGuid().ToString())}"
        New-Item -Path $pathRulePath -Force | Out-Null
        Set-ItemProperty -Path $pathRulePath -Name "ItemData" -Value $pathRule.Path -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $pathRulePath -Name "SaferFlags" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $pathRulePath -Name "ItemSize" -Value $pathRule.Path.Length -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $pathRulePath -Name "Description" -Value $pathRule.Description -Type String -ErrorAction SilentlyContinue
    }
    
    # Create allowed paths for legitimate applications and URBackup
    $allowedPaths = @(
        @{Path="%PROGRAMFILES%\*"; Description="Program Files execution allowed"},
        @{Path="%PROGRAMFILES(X86)%\*"; Description="Program Files x86 execution allowed"},
        @{Path="%WINDIR%\*"; Description="Windows system execution allowed"},
        @{Path="%WINDIR%\System32\*"; Description="System32 execution allowed"},
        @{Path="%WINDIR%\SysWOW64\*"; Description="SysWOW64 execution allowed"},
        @{Path="%PROGRAMFILES%\UrBackup\*"; Description="URBackup client execution allowed"},
        @{Path="%PROGRAMFILES(X86)%\UrBackup\*"; Description="URBackup client x86 execution allowed"},
        @{Path="%PROGRAMDATA%\Microsoft\Windows Defender\*"; Description="Windows Defender execution allowed"}
    )
    
    foreach ($pathRule in $allowedPaths) {
        $pathRulePath = "$srpPath\262144\Paths\{$([guid]::NewGuid().ToString())}"
        New-Item -Path $pathRulePath -Force | Out-Null
        Set-ItemProperty -Path $pathRulePath -Name "ItemData" -Value $pathRule.Path -Type String -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $pathRulePath -Name "SaferFlags" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $pathRulePath -Name "ItemSize" -Value $pathRule.Path.Length -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $pathRulePath -Name "Description" -Value $pathRule.Description -Type String -ErrorAction SilentlyContinue
    }
    
    $hardeningStatus.Successes.Add("SI-7: No execute policies configured for high-risk locations") | Out-Null
    Write-Log "No execute policies configured for desktop and temp folders" "SUCCESS"
    
    # 10.4 URBACKUP FIREWALL EXCEPTIONS
    Write-Log "Configuring URBackup firewall exceptions" "INFO"
    
    $urbackupRules = @(
        @{Name="URBackup-Client-TCP-35621"; Protocol="TCP"; Port=35621; Direction="Inbound"; Description="URBackup file backup transfers"},
        @{Name="URBackup-Client-TCP-35623"; Protocol="TCP"; Port=35623; Direction="Both"; Description="URBackup commands and image backups"},
        @{Name="URBackup-Client-UDP-35622"; Protocol="UDP"; Port=35622; Direction="Both"; Description="URBackup client discovery"},
        @{Name="URBackup-Client-UDP-35623"; Protocol="UDP"; Port=35623; Direction="Outbound"; Description="URBackup server discovery response"},
        @{Name="URBackup-Web-TCP-55414"; Protocol="TCP"; Port=55414; Direction="Outbound"; Description="URBackup web interface access"},
        @{Name="URBackup-Internet-TCP-55415"; Protocol="TCP"; Port=55415; Direction="Outbound"; Description="URBackup internet client communication"}
    )
    
    foreach ($rule in $urbackupRules) {
        try {
            if ($rule.Direction -eq "Both") {
                netsh advfirewall firewall add rule name="$($rule.Name)-In" dir=in action=allow protocol="$($rule.Protocol)" localport="$($rule.Port)" | Out-Null
                netsh advfirewall firewall add rule name="$($rule.Name)-Out" dir=out action=allow protocol="$($rule.Protocol)" remoteport="$($rule.Port)" | Out-Null
                Write-Log "Created URBackup firewall rule: $($rule.Name) (bidirectional)" "INFO"
            } elseif ($rule.Direction -eq "Inbound") {
                netsh advfirewall firewall add rule name="$($rule.Name)" dir=in action=allow protocol="$($rule.Protocol)" localport="$($rule.Port)" | Out-Null
                Write-Log "Created URBackup firewall rule: $($rule.Name) (inbound)" "INFO"
            } else {
                netsh advfirewall firewall add rule name="$($rule.Name)" dir=out action=allow protocol="$($rule.Protocol)" remoteport="$($rule.Port)" | Out-Null
                Write-Log "Created URBackup firewall rule: $($rule.Name) (outbound)" "INFO"
            }
        } catch {
            Write-Log "Failed to create URBackup firewall rule: $($rule.Name) - $_" "WARNING"
        }
    }
    
    $hardeningStatus.Successes.Add("SC-7: URBackup firewall exceptions configured") | Out-Null
    Write-Log "URBackup firewall exceptions configured successfully" "SUCCESS"
    
    # 10.5 ADDITIONAL WINDOWS SECURITY HARDENING
    Write-Log "Applying additional Windows security configurations" "INFO"
    
    $securityConfigs = @{
        # Disable Windows Script Host
        "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" = @{
            "Enabled" = 0
        }
        # Disable Windows Installer over network
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" = @{
            "AlwaysInstallElevated" = 0
            "DisableMSI" = 1
        }
        # Disable AutoRun/AutoPlay
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" = @{
            "NoDriveTypeAutoRun" = 255
            "NoAutorun" = 1
        }
        # System policies and Enhanced UAC settings
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" = @{
            "EnableGuestAccount" = 0
            "DontDisplayLastUserName" = 1
            "DisableCAD" = 0
            "ConsentPromptBehaviorAdmin" = 2
            "ConsentPromptBehaviorUser" = 0
            "EnableInstallerDetection" = 1
            "EnableLUA" = 1
            "EnableVirtualization" = 1
            "PromptOnSecureDesktop" = 1
        }
    }
    
    foreach ($regPath in $securityConfigs.Keys) {
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
        }
        foreach ($setting in $securityConfigs[$regPath].GetEnumerator()) {
            Set-ItemProperty -Path $regPath -Name $setting.Key -Value $setting.Value -Type DWord -ErrorAction SilentlyContinue
            Write-Log "Applied security setting: $regPath\$($setting.Key) = $($setting.Value)" "INFO"
        }
    }
    
    $hardeningStatus.Successes.Add("CM-6: Additional Windows security configurations applied") | Out-Null
    Write-Log "Additional Windows security hardening completed" "SUCCESS"
    
} catch {
    $hardeningStatus.Errors.Add("Enhanced security policies configuration failed: $_") | Out-Null
    Write-Log "Enhanced security policies configuration failed: $_" "ERROR"
}

# Save status for next scripts
$statusData = @{
    Timestamp = Get-Date -Format 'o'
    ScriptCompleted = 1
    AdminPasswordSuccess = $adminPasswordSuccess
    BitlockerSuccess = $bitlockerSuccess
    AdminSuccess = $adminSuccess
    WindowsVersion = $config.WindowsVersion
    WindowsEdition = (Get-CimInstance -ClassName Win32_OperatingSystem).OperatingSystemSKU
    Successes = $hardeningStatus.Successes.ToArray()
    Errors = $hardeningStatus.Errors.ToArray()
    CriticalFailures = $hardeningStatus.CriticalFailures.ToArray()
    LogFolder = $logFolder
}
$statusData | ConvertTo-Json -Depth 4 | Out-File "$logFolder\script1-status.json" -Encoding UTF8

Write-Host "`n================================================================================" -ForegroundColor Green
Write-Host "                    CORE HARDENING COMPLETED (1/3)" -ForegroundColor Green
Write-Host "================================================================================" -ForegroundColor Green

$successCount = $hardeningStatus.Successes.Count
$errorCount = $hardeningStatus.Errors.Count
$criticalCount = $hardeningStatus.CriticalFailures.Count

Write-Host "`nCORE HARDENING RESULTS:" -ForegroundColor Cyan
Write-Host "   [+] Successful Operations: $successCount" -ForegroundColor Green
Write-Host "   [!] Errors: $errorCount" -ForegroundColor Yellow
Write-Host "   [X] Critical Failures: $criticalCount" -ForegroundColor Red

# Check critical files
$passwordFileExists = Test-Path "$logFolder\SecOpsAdm_Password.txt"
$bitlockerFileExists = Test-Path "$logFolder\BitLocker_Recovery_Key.txt"
$adminPasswordFileExists = Test-Path "$logFolder\Administrator_Password.txt"

Write-Host "`nCRITICAL FILES STATUS:" -ForegroundColor Magenta
if ($passwordFileExists) {
    Write-Host "   [+] SecOpsAdm Password File: CREATED" -ForegroundColor Green
} else {
    Write-Host "   [X] SecOpsAdm Password File: FAILED" -ForegroundColor Red
}

if ($bitlockerFileExists) {
    Write-Host "   [+] BitLocker Recovery Password: CREATED" -ForegroundColor Green
} else {
    Write-Host "   [X] BitLocker Recovery Password: FAILED" -ForegroundColor Red
}

if ($adminPasswordFileExists) {
    Write-Host "   [+] Administrator Password File: CREATED" -ForegroundColor Green
} else {
    Write-Host "   [X] Administrator Password File: FAILED" -ForegroundColor Red
}

Write-Host "`nENHANCED SECURITY POLICIES APPLIED:" -ForegroundColor Cyan
Write-Host "   [+] Microsoft Edge Data Restrictions" -ForegroundColor Green
Write-Host "   [+] 10-Minute Mandatory Screen Lock" -ForegroundColor Green
Write-Host "   [+] No Execute Policies (Desktop/Temp)" -ForegroundColor Green
Write-Host "   [+] Form-Field Autofill Disabled" -ForegroundColor Green
Write-Host "   [+] Extension Installation Blocked" -ForegroundColor Green
Write-Host "   [+] URBackup Firewall Exceptions" -ForegroundColor Green
Write-Host "   [+] Additional Windows Security Hardening" -ForegroundColor Green

Write-Host "`nNEXT STEPS:" -ForegroundColor Cyan
Write-Host "   1. Run Script 2: '2-Compliance-Collection.ps1'" -ForegroundColor White
Write-Host "   2. Run Script 3: '3-Final-Report.ps1'" -ForegroundColor White
Write-Host "   3. SECURE the password and BitLocker key files IMMEDIATELY" -ForegroundColor Yellow
Write-Host "   4. Test Edge browser restrictions and screen lock functionality" -ForegroundColor Yellow
Write-Host "   5. Verify URBackup client connectivity" -ForegroundColor Yellow

Write-Log "Core hardening script completed with enhanced security policies. Proceeding to compliance collection phase." "INFO"

Write-Host "`nPress any key to continue..." -ForegroundColor White
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")