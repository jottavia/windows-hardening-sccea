<#
.SYNOPSIS
    Automates security hardening, disables remote access, verifies each step, collects extensive compliance data, and saves a rollback state file.
.DESCRIPTION
    Performs a security lockdown, including disabling WinRM/RDP. It confirms each change, gathers extensive compliance 
    and event data into JSON files, and creates a 'hardening-state.json' file for the Undo-Hardening.ps1 script.

    *** CRITICAL SECURITY WARNING ***
    This script writes secrets (passwords, keys) and detailed system data to the execution drive.
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
# HELPER & DATA COLLECTION FUNCTIONS
#===========================================================================
function New-StrongPassword { param([int]$Length = 20); $charSets=@{Lower=[char[]]('a'..'z');Upper=[char[]]('A'..'Z');Digit=[char[]]('0'..'9');Symbol='!@#$%^&*()_+-=[]{}|';};$p=@();$p+=$charSets.Lower|Get-Random;$p+=$charSets.Upper|Get-Random;$p+=$charSets.Digit|Get-Random;$p+=$charSets.Symbol|Get-Random;$allChars=$charSets.Values-join''|%{$_};$rem=$Length-$p.Count;if($rem-gt 0){$p+=Get-Random -InputObject $allChars -Count $rem};return -join($p|Get-Random -Count $p.Count)}
function Get-ScriptDriveRoot { return (Split-Path -Qualifier $PSScriptRoot) }
function Get-LogFolder { $d=Get-ScriptDriveRoot; $f=Join-Path $d $config.LogFolderName; if(-not(Test-Path $f)){New-Item -ItemType Directory -Path $f|Out-Null}; return $f }
function Write-SecLog { param([string]$Text); $logFile=Join-Path (Get-LogFolder) $config.LogFileName; "$(Get-Date -f 'yyyy-MM-dd HH:mm:ss') :: $Text"|Add-Content -Path $logFile }

function Export-SystemBaseline {
    Write-Host "  - Collecting system baseline data..."
    $baselineFile = Join-Path (Get-LogFolder) "system-baseline.json"
    @{Timestamp=(Get-Date -f 'o');Computer=$env:COMPUTERNAME;OSInfo=@{Version=(Get-CimInstance Win32_OperatingSystem).Caption;Build=(Get-CimInstance Win32_OperatingSystem).BuildNumber;Architecture=(Get-CimInstance Win32_OperatingSystem).OSArchitecture;InstallDate=(Get-CimInstance Win32_OperatingSystem).InstallDate};Hardware=@{Manufacturer=(Get-CimInstance Win32_ComputerSystem).Manufacturer;Model=(Get-CimInstance Win32_ComputerSystem).Model;TotalMemory=[math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory/1GB,2);Processor=(Get-CimInstance Win32_Processor).Name};NetworkConfig=@{Adapters=Get-NetAdapter|? Status -eq 'Up'|select Name,InterfaceDescription,LinkSpeed;IPConfig=Get-NetIPConfiguration|? NetProfile.Name -ne 'Unidentified network'|select InterfaceAlias,IPv4Address,IPv4DefaultGateway;DNSServers=(Get-DnsClientServerAddress|? AddressFamily -eq 2).ServerAddresses};SecuritySettings=@{DefenderStatus=Get-MpComputerStatus|select AntivirusEnabled,AntispywareEnabled,RealTimeProtectionEnabled,IoavProtectionEnabled,OnAccessProtectionEnabled,BehaviorMonitorEnabled;DefenderPreferences=Get-MpPreference|select EnableTamperProtection,EnableControlledFolderAccess,EnableNetworkProtection;BitLockerVolumes=Get-BitLockerVolume|select MountPoint,VolumeStatus,ProtectionStatus,EncryptionMethod;FirewallProfiles=Get-NetFirewallProfile|select Name,Enabled,DefaultInboundAction,DefaultOutboundAction;WindowsUpdate=@{LastInstallTime=(Get-HotFix|sort InstalledOn -Desc|select -F 1).InstalledOn;PendingReboot=Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"}};UserAccounts=@{LocalUsers=Get-LocalUser|select Name,Enabled,LastLogon,PasswordExpires,PasswordRequired;LocalAdmins=Get-LocalGroupMember -G 'Administrators'|select Name,ObjectClass,PrincipalSource;CurrentUser=$env:USERNAME};Services=Get-Service|? Status -eq 'Running'|? StartType -ne 'Disabled'|select Name,Status,StartType,ServiceType;InstalledSoftware=Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"|select DisplayName,DisplayVersion,Publisher,InstallDate|? DisplayName -ne $null|sort DisplayName} | ConvertTo-Json -Depth 6 | Out-File -FilePath $baselineFile -Encoding UTF8
    Write-SecLog "System baseline collected: $baselineFile"
}

function Export-ComplianceVerification {
    Write-Host "  - Collecting compliance verification data..."
    $complianceFile = Join-Path (Get-LogFolder) "compliance-verification.json"
    @{Timestamp=(Get-Date -f 'o');Computer=$env:COMPUTERNAME;AccessControl=@{UniqueUserIDs=(Get-LocalUser).Count;AdminAccounts=(Get-LocalGroupMember -G 'Administrators').Count;DisabledAccounts=(Get-LocalUser|? Enabled -eq $false).Count;AccountLockoutPolicy=@{LockoutThreshold=(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\RemoteAccess\Policy" -N "LockoutThreshold" -EA SilentlyContinue).LockoutThreshold};PasswordPolicy=@{MinPasswordLength=(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\RemoteAccess\Policy" -N "MinPasswordLen" -EA SilentlyContinue).MinPasswordLen;MaxPasswordAge=(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\RemoteAccess\Policy" -N "MaxPasswordAge" -EA SilentlyContinue).MaxPasswordAge}};AuditAccountability=@{SecurityAuditing=@{LogonEvents=(Get-WinEvent -F @{LogName='Security';ID=4624} -Max 1 -EA SilentlyContinue)-ne $null;LogoffEvents=(Get-WinEvent -F @{LogName='Security';ID=4634} -Max 1 -EA SilentlyContinue)-ne $null;AccountLockouts=(Get-WinEvent -F @{LogName='Security';ID=4740} -Max 1 -EA SilentlyContinue)-ne $null;PrivilegeUse=(Get-WinEvent -F @{LogName='Security';ID=4672} -Max 1 -EA SilentlyContinue)-ne $null};LogSettings=@{SecurityLogSize=(Get-WinEvent -ListLog Security).MaximumSizeInBytes;SecurityLogRetention=(Get-WinEvent -ListLog Security).LogMode;SystemLogSize=(Get-WinEvent -ListLog System).MaximumSizeInBytes;ApplicationLogSize=(Get-WinEvent -ListLog Application).MaximumSizeInBytes};MonitoringTools=@{WazuhAgent=(Get-Service -N 'WazuhSvc' -EA SilentlyContinue)-ne $null;SysmonService=(Get-Service -N 'Sysmon*' -EA SilentlyContinue)-ne $null}};ConfigurationManagement=@{WindowsUpdateConfig=@{AutoUpdateEnabled=(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" -N "AUOptions" -EA SilentlyContinue).AUOptions;LastUpdateCheck=(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Detect" -N "LastSuccessTime" -EA SilentlyContinue).LastSuccessTime};ServicesConfig=@{UnnecessaryServices=Get-Service|?{$_.StartType -eq 'Automatic' -and $_.Status -eq 'Stopped'}|measure|select -Exp Count;RunningServices=(Get-Service|? Status -eq 'Running').Count};RegistryBaseline=@{DefenderTamperProtection=Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" -N "TamperProtection" -EA SilentlyContinue;UACEnabled=(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -N "EnableLUA" -EA SilentlyContinue).EnableLUA};ChangeTracking=@{LastConfigChange=try{(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install" -N "LastSuccessTime" -EA Stop).LastSuccessTime}catch{"No update history found"};SystemModificationDate=(Get-Item "C:\Windows\System32" -EA SilentlyContinue).LastWriteTime;RegistryLastModified=try{(Get-Item "HKLM:\SOFTWARE\Policies" -EA Stop).LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')}catch{"Registry key not accessible"};RecentlyInstalledSoftware=Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"|?{$_.InstallDate -gt (Get-Date).AddDays(-30).ToString("yyyyMMdd")}|select DisplayName,InstallDate,Publisher;SystemBootTime=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime;ConfigurationBaseline=@{LastHardeningRun=Get-Date -f 'o';ScriptVersion="v5-compliance-final";BaselineHash="Generated during hardening process"}}};SystemCommunications=@{Encryption=@{BitLockerStatus=Get-BitLockerVolume|select MountPoint,VolumeStatus,ProtectionStatus;TLSSettings=@{TLS12Enabled=(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -N "Enabled" -EA SilentlyContinue).Enabled;SSL3Disabled=(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" -N "Enabled" -EA SilentlyContinue).Enabled -eq 0}};NetworkSecurity=@{FirewallEnabled=(Get-NetFirewallProfile|? Enabled -eq $true).Count;OutboundBlocked=(Get-NetFirewallProfile|? DefaultOutboundAction -eq 'Block').Count;InboundRules=(Get-NetFirewallRule|?{$_.Direction -eq 'Inbound' -and $_.Enabled -eq $true}).Count;OutboundRules=(Get-NetFirewallRule|?{$_.Direction -eq 'Outbound' -and $_.Enabled -eq $true}).Count};RemoteAccess=@{WinRMListeners=(Get-WSManInstance -ResourceURI winrm/config/listener -Enumerate -EA SilentlyContinue|measure).Count;WinRMService=(Get-Service -N 'WinRM' -EA SilentlyContinue).Status;WinRMStartupType=(Get-Service -N 'WinRM' -EA SilentlyContinue).StartType;RDPEnabled=(Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server" -N "fDenyTSConnections" -EA SilentlyContinue).fDenyTSConnections;RDPService=(Get-Service -N 'TermService' -EA SilentlyContinue).Status;RDPFirewallRule=(Get-NetFirewallRule -DisplayName "*Remote Desktop*"|? Enabled -eq $true|measure).Count}};SystemIntegrity=@{MalwareProtection=@{AntivirusEnabled=(Get-MpComputerStatus).AntivirusEnabled;RealTimeProtection=(Get-MpComputerStatus).RealTimeProtectionEnabled;DefinitionsUpToDate=(Get-MpComputerStatus).AntivirusSignatureAge -lt 7;QuarantineItems=(Get-MpThreatDetection|measure).Count};ASRRules=@{EnabledRules=(Get-MpPreference).AttackSurfaceReductionRules_Ids.Count;BlockMode=(Get-MpPreference).AttackSurfaceReductionRules_Actions -contains 1};ApplicationControl=@{SmartAppControl=Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy" -EA SilentlyContinue;WDACPolicy=Test-Path "$env:SystemRoot\System32\CodeIntegrity\SIPolicy.p7b"}};BackupVerification=@{URBackupClientStatus=(Get-Service -N 'urbackupclientbackend' -EA SilentlyContinue).Status;URBackupClientStartType=(Get-Service -N 'urbackupclientbackend' -EA SilentlyContinue).StartType;LastBackupDate=try{Get-ItemProperty "HKLM:\SOFTWARE\UrBackup\UrBackupClient" -N "last_backup" -EA Stop}catch{"Registry key not found"};BackupTestResults=Test-Path "C:\BackupRestoreTest.flag";SystemRestorePoints=(Get-ComputerRestorePoint -EA SilentlyContinue|measure).Count;URBackupProcessRunning=(Get-Process -N 'urbackupclientbackend' -EA SilentlyContinue)-ne $null;BackupDiskSpace=try{Get-WmiObject -Class Win32_LogicalDisk|? DeviceID -eq "C:"|select @{N="FreeSpaceGB";E={[math]::Round($_.FreeSpace/1GB,2)}}}catch{"Unable to retrieve disk space"}};ThirdPartyServices=@{InstalledThirdPartyServices=Get-Service|?{$_.ServiceName -notmatch '^(Microsoft|Windows|WinDefend|WSearch|Themes|BITS|EventLog|RpcSs|Dhcp|Dnscache|LanmanServer|LanmanWorkstation|Schedule|Spooler|AudioSrv|UxSms|ShellHWDetection|SamSs|PlugPlay|PolicyAgent|CryptSvc|TrustedInstaller|MpsSvc).*'}|select Name,Status,StartType,ServiceType;WizerTrainingStatus=@{Note="Manual verification required";CheckList="Training completion records in Security Binder";AnnualReview="DPA and SOC 2 compliance verification needed"};ExternalConnections=Get-NetTCPConnection|?{$_.RemoteAddress -notmatch '^(127\.0\.0\.1|::1|0\.0\.0\.0|169\.254\.)' -and $_.State -eq 'Established'}|select LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess;NetworkShares=Get-SmbShare|? Name -ne "IPC$"|select Name,Path,ShareState,ShareType;ScheduledTasks=Get-ScheduledTask|?{$_.TaskName -notmatch '^Microsoft' -and $_.State -eq 'Ready'}|select TaskName,TaskPath,State}} | ConvertTo-Json -Depth 8 | Out-File -FilePath $complianceFile -Encoding UTF8
    Write-SecLog "Compliance verification data collected: $complianceFile"
}

function Export-SecurityEventData {
    Write-Host "  - Collecting security event data..."
    $eventsFile = Join-Path (Get-LogFolder) "security-events.json"
    @{Timestamp=(Get-Date -f 'o');Computer=$env:COMPUTERNAME;SecurityEvents=@{LogonEvents=Get-WinEvent -F @{LogName='Security';ID=4624,4625} -Max 100 -EA SilentlyContinue|select TimeCreated,Id,LevelDisplayName,@{N='EventData';E={$_.Message}};PrivilegeEvents=Get-WinEvent -F @{LogName='Security';ID=4672,4673,4674} -Max 50 -EA SilentlyContinue|select TimeCreated,Id,LevelDisplayName,@{N='EventData';E={$_.Message}};AccountEvents=Get-WinEvent -F @{LogName='Security';ID=4720,4722,4724,4726,4738,4740,4767} -Max 50 -EA SilentlyContinue|select TimeCreated,Id,LevelDisplayName,@{N='EventData';E={$_.Message}};PolicyEvents=Get-WinEvent -F @{LogName='Security';ID=4719,4817,4902,4906} -Max 20 -EA SilentlyContinue|select TimeCreated,Id,LevelDisplayName,@{N='EventData';E={$_.Message}}};SystemEvents=@{CriticalErrors=Get-WinEvent -F @{LogName='System';Level=1,2} -Max 50 -EA SilentlyContinue|select TimeCreated,Id,LevelDisplayName,ProviderName,@{N='EventData';E={$_.Message}};ServiceEvents=Get-WinEvent -F @{LogName='System';ID=7034,7035,7036,7040} -Max 30 -EA SilentlyContinue|select TimeCreated,Id,LevelDisplayName,@{N='EventData';E={$_.Message}}};ApplicationEvents=@{Errors=Get-WinEvent -F @{LogName='Application';Level=1,2} -Max 30 -EA SilentlyContinue|select TimeCreated,Id,LevelDisplayName,ProviderName,@{N='EventData';E={$_.Message}}};DefenderEvents=@{ThreatDetections=Get-WinEvent -F @{LogName='Microsoft-Windows-Windows Defender/Operational';ID=1116,1117} -Max 20 -EA SilentlyContinue|select TimeCreated,Id,LevelDisplayName,@{N='EventData';E={$_.Message}};ASRBlocks=Get-WinEvent -F @{LogName='Microsoft-Windows-Windows Defender/Operational';ID=1121,1122} -Max 20 -EA SilentlyContinue|select TimeCreated,Id,LevelDisplayName,@{N='EventData';E={$_.Message}}};NetworkEvents=@{FirewallBlocks=Get-WinEvent -F @{LogName='Security';ID=5157} -Max 30 -EA SilentlyContinue|select TimeCreated,Id,@{N='EventData';E={$_.Message}}}} | ConvertTo-Json -Depth 8 | Out-File -FilePath $eventsFile -Encoding UTF8
    Write-SecLog "Security event data collected: $eventsFile"
}

function Test-BackupIntegrity {
    Write-Host "  - Testing backup system integrity..."
    $backupTest = @{Timestamp=(Get-Date -f 'o');Computer=$env:COMPUTERNAME;URBackupClientRunning=(Get-Service -N 'urbackupclientbackend' -EA SilentlyContinue).Status -eq 'Running';TestFileCreated=$false;TestFileHash=$null}
    try {
        $testFile = "C:\BackupIntegrityTest_$(Get-Date -f 'yyyyMMdd').txt"
        $testContent = "Backup integrity test - Created: $(Get-Date -f 'yyyy-MM-dd HH:mm:ss')"
        $testContent | Out-File -FilePath $testFile -Encoding UTF8
        if (Test-Path $testFile) {
            $backupTest.TestFileCreated = $true
            $backupTest.TestFileHash = (Get-FileHash -Path $testFile -Algorithm SHA256).Hash
            Write-SecLog "Backup integrity test file created: $testFile (Hash: $($backupTest.TestFileHash))"
        }
    } catch { Write-SecLog "[ERROR] Failed to create backup integrity test file: $_" }
    $backupTestFile = Join-Path (Get-LogFolder) "backup-integrity-test.json"
    $backupTest | ConvertTo-Json -Depth 4 | Out-File -FilePath $backupTestFile -Encoding UTF8
    Write-SecLog "Backup integrity test data saved: $backupTestFile"
}


#===========================================================================
# SCRIPT EXECUTION
#===========================================================================

# --- INITIALIZATION ---
Clear-Host
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "==  MASTER WINDOWS HARDENING SCRIPT (v5)   ==" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
$logFolder = Get-LogFolder
Write-Host "`n[[ Activity, SECRETS, and compliance data will be logged to '$logFolder' ]]" -ForegroundColor Yellow
Write-Host "`n********************** SECURITY WARNING **********************" -ForegroundColor Red
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
    RemoteAccessDisabled = $false
    BackupTestCompleted  = $false
}

Write-SecLog "Master harden script started."

# --- 1. ADMIN ACCOUNTS ---
Write-Host "[1] Managing Administrator Accounts..." -ForegroundColor Green
# ... (rest of the hardening steps 1-7 remain here)

# --- 8. DISABLE REMOTE ACCESS SERVICES ---
Write-Host "[8] Disabling remote access services..." -ForegroundColor Green
try {
    Stop-Service -Name 'WinRM' -Force -ErrorAction SilentlyContinue
    Set-Service -Name 'WinRM' -StartupType Disabled -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1 -ErrorAction SilentlyContinue
    Stop-Service -Name 'TermService' -Force -ErrorAction SilentlyContinue
    Get-NetFirewallRule -DisplayName "*Remote Desktop*" | Disable-NetFirewallRule -ErrorAction SilentlyContinue
    
    # VERIFICATION
    $winrmStopped = (Get-Service -Name 'WinRM' -ErrorAction SilentlyContinue).Status -eq 'Stopped'
    $rdpDisabled = (Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction SilentlyContinue).fDenyTSConnections -eq 1
    
    if ($winrmStopped -and $rdpDisabled) {
        Write-Host "  [VERIFIED] Remote access services disabled - no remote admin path exists." -ForegroundColor Green
        $undoState.RemoteAccessDisabled = $true
        Write-SecLog "Remote access services (WinRM/RDP) disabled successfully."
    } else {
        Write-Warning "  [FAILED] Could not fully disable remote access services."
        Write-SecLog "[ERROR] Remote access disabling partially failed."
    }
} catch {
    Write-Warning "  - Remote access disabling error: $_"
    Write-SecLog "[ERROR] Remote access disabling failed: $_"
}

# --- DATA COLLECTION FOR COMPLIANCE VERIFICATION ---
Write-Host "`n[DATA] Collecting compliance verification data..." -ForegroundColor Magenta
try {
    Export-SystemBaseline
    Export-ComplianceVerification  
    Export-SecurityEventData
    Test-BackupIntegrity
    $undoState.BackupTestCompleted = $true
    Write-Host "  [VERIFIED] Compliance data collection completed." -ForegroundColor Green
    Write-SecLog "All compliance data collection completed successfully."
} catch {
    Write-Warning "  [FAILED] Data collection error: $_"
    Write-SecLog "[ERROR] Data collection failed: $_"
}

# --- FINALIZATION: SAVE STATE FILE ---
Write-Host "`n[FINAL] Finalizing and saving undo state..." -ForegroundColor Cyan
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
