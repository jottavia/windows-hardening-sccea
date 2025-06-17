<#
.SYNOPSIS
    Collects extensive system, security, and event data for compliance verification and auditing.
.DESCRIPTION
    This script is designed to be run periodically after a system has been hardened. It gathers detailed
    information about the system's configuration and security state, saving it into a set of JSON files.
    This allows for ongoing monitoring and provides evidence for compliance audits without making any
    changes to the system. It requires administrative privileges to gather all necessary data.
.NOTES
    Version: 2.0 (Enhanced Compliance Data)
    This script is a component of the PowerShell Windows Hardening & Management Toolkit.
    It creates the following files in a timestamped subfolder:
    - system-baseline.json
    - compliance-verification.json
    - security-events.json
#>

[CmdletBinding()]
param()

# --- Initial Setup and Admin Check ---
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script requires administrative privileges to collect all necessary security data. Please re-run from an elevated PowerShell prompt."
    exit 1
}

# --- Configuration ---
$config = @{
    LogFolderName     = "PC-$env:COMPUTERNAME-AUDITS"
    LogFileName       = "collection-log.txt"
}

#===========================================================================
# HELPER FUNCTIONS
#===========================================================================
function Get-ScriptDriveRoot { return (Split-Path -Qualifier $PSScriptRoot) }

function Get-LogFolder {
    # Creates a unique, timestamped folder for each run to avoid overwriting previous audits.
    $rootLogFolder = Join-Path (Get-ScriptDriveRoot) $config.LogFolderName
    if (-not(Test-Path $rootLogFolder)) { New-Item -ItemType Directory -Path $rootLogFolder | Out-Null }
    
    $timestampFolder = "AUDIT-$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss')"
    $finalPath = Join-Path $rootLogFolder $timestampFolder
    if (-not(Test-Path $finalPath)) { New-Item -ItemType Directory -Path $finalPath | Out-Null }
    
    return $finalPath
}

function Write-CollectionLog {
    param([string]$Text)
    $logFile = Join-Path $script:logFolderPath $config.LogFileName # Use global scope variable for folder
    "$(Get-Date -f 'yyyy-MM-dd HH:mm:ss') :: $Text" | Add-Content -Path $logFile
}

#===========================================================================
# DATA COLLECTION FUNCTIONS
#===========================================================================

function Export-SystemBaseline {
    Write-Host "  - Collecting system baseline data..."
    $baselineFile = Join-Path $script:logFolderPath "system-baseline.json"
    @{Timestamp=(Get-Date -f 'o');Computer=$env:COMPUTERNAME;OSInfo=@{Version=(Get-CimInstance Win32_OperatingSystem).Caption;Build=(Get-CimInstance Win32_OperatingSystem).BuildNumber;Architecture=(Get-CimInstance Win32_OperatingSystem).OSArchitecture;InstallDate=(Get-CimInstance Win32_OperatingSystem).InstallDate};Hardware=@{Manufacturer=(Get-CimInstance Win32_ComputerSystem).Manufacturer;Model=(Get-CimInstance Win32_ComputerSystem).Model;TotalMemory=[math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory/1GB,2);Processor=(Get-CimInstance Win32_Processor).Name};NetworkConfig=@{Adapters=Get-NetAdapter|? Status -eq 'Up'|select Name,InterfaceDescription,LinkSpeed;IPConfig=Get-NetIPConfiguration|? NetProfile.Name -ne 'Unidentified network'|select InterfaceAlias,IPv4Address,IPv4DefaultGateway;DNSServers=(Get-DnsClientServerAddress|? AddressFamily -eq 2).ServerAddresses};SecuritySettings=@{DefenderStatus=Get-MpComputerStatus|select AntivirusEnabled,AntispywareEnabled,RealTimeProtectionEnabled,IoavProtectionEnabled,OnAccessProtectionEnabled,BehaviorMonitorEnabled;DefenderPreferences=Get-MpPreference|select EnableTamperProtection,EnableControlledFolderAccess,EnableNetworkProtection;BitLockerVolumes=Get-BitLockerVolume|select MountPoint,VolumeStatus,ProtectionStatus,EncryptionMethod;FirewallProfiles=Get-NetFirewallProfile|select Name,Enabled,DefaultInboundAction,DefaultOutboundAction;WindowsUpdate=@{LastInstallTime=(Get-HotFix|sort InstalledOn -Desc|select -F 1).InstalledOn;PendingReboot=Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"}};UserAccounts=@{LocalUsers=Get-LocalUser|select Name,Enabled,LastLogon,PasswordExpires,PasswordRequired;LocalAdmins=Get-LocalGroupMember -G 'Administrators'|select Name,ObjectClass,PrincipalSource;CurrentUser=$env:USERNAME};Services=Get-Service|? Status -eq 'Running'|? StartType -ne 'Disabled'|select Name,Status,StartType,ServiceType;InstalledSoftware=Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"|select DisplayName,DisplayVersion,Publisher,InstallDate|? DisplayName -ne $null|sort DisplayName} | ConvertTo-Json -Depth 6 | Out-File -FilePath $baselineFile -Encoding UTF8
    Write-CollectionLog "System baseline collected: $baselineFile"
}

function Export-ComplianceVerification {
    Write-Host "  - Collecting compliance verification data..."
    $complianceFile = Join-Path $script:logFolderPath "compliance-verification.json"
    @{Timestamp=(Get-Date -f 'o');Computer=$env:COMPUTERNAME;AccessControl=@{UniqueUserIDs=(Get-LocalUser).Count;AdminAccounts=(Get-LocalGroupMember -G 'Administrators').Count;DisabledAccounts=(Get-LocalUser|? Enabled -eq $false).Count;AccountLockoutPolicy=@{LockoutThreshold=(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\RemoteAccess\Policy" -N "LockoutThreshold" -EA SilentlyContinue).LockoutThreshold};PasswordPolicy=@{MinPasswordLength=(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\RemoteAccess\Policy" -N "MinPasswordLen" -EA SilentlyContinue).MinPasswordLen;MaxPasswordAge=(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\RemoteAccess\Policy" -N "MaxPasswordAge" -EA SilentlyContinue).MaxPasswordAge}};AuditAccountability=@{SecurityAuditing=@{LogonEvents=(Get-WinEvent -F @{LogName='Security';ID=4624} -Max 1 -EA SilentlyContinue)-ne $null;LogoffEvents=(Get-WinEvent -F @{LogName='Security';ID=4634} -Max 1 -EA SilentlyContinue)-ne $null;AccountLockouts=(Get-WinEvent -F @{LogName='Security';ID=4740} -Max 1 -EA SilentlyContinue)-ne $null;PrivilegeUse=(Get-WinEvent -F @{LogName='Security';ID=4672} -Max 1 -EA SilentlyContinue)-ne $null};LogSettings=@{SecurityLogSize=(Get-WinEvent -ListLog Security).MaximumSizeInBytes;SecurityLogRetention=(Get-WinEvent -ListLog Security).LogMode;SystemLogSize=(Get-WinEvent -ListLog System).MaximumSizeInBytes;ApplicationLogSize=(Get-WinEvent -ListLog Application).MaximumSizeInBytes};MonitoringTools=@{WazuhAgent=(Get-Service -N 'WazuhSvc' -EA SilentlyContinue)-ne $null;SysmonService=(Get-Service -N 'Sysmon*' -EA SilentlyContinue)-ne $null}};ConfigurationManagement=@{WindowsUpdateConfig=@{AutoUpdateEnabled=(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" -N "AUOptions" -EA SilentlyContinue).AUOptions;LastUpdateCheck=(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Detect" -N "LastSuccessTime" -EA SilentlyContinue).LastSuccessTime};ServicesConfig=@{UnnecessaryServices=Get-Service|?{$_.StartType -eq 'Automatic' -and $_.Status -eq 'Stopped'}|measure|select -Exp Count;RunningServices=(Get-Service|? Status -eq 'Running').Count};RegistryBaseline=@{DefenderTamperProtection=Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" -N "TamperProtection" -EA SilentlyContinue;UACEnabled=(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -N "EnableLUA" -EA SilentlyContinue).EnableLUA};ChangeTracking=@{LastConfigChange=try{(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install" -N "LastSuccessTime" -EA Stop).LastSuccessTime}catch{"No update history found"};SystemModificationDate=(Get-Item "C:\Windows\System32" -EA SilentlyContinue).LastWriteTime;RegistryLastModified=try{(Get-Item "HKLM:\SOFTWARE\Policies" -EA Stop).LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')}catch{"Registry key not accessible"};RecentlyInstalledSoftware=Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"|?{$_.InstallDate -gt (Get-Date).AddDays(-30).ToString("yyyyMMdd")}|select DisplayName,InstallDate,Publisher;SystemBootTime=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime;ConfigurationBaseline=@{LastHardeningRun=Get-Date -f 'o';ScriptVersion="v2-compliance-enhanced";BaselineHash="Generated during collection process"}}};SystemCommunications=@{Encryption=@{BitLockerStatus=Get-BitLockerVolume|select MountPoint,VolumeStatus,ProtectionStatus;TLSSettings=@{TLS12Enabled=(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -N "Enabled" -EA SilentlyContinue).Enabled;SSL3Disabled=(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" -N "Enabled" -EA SilentlyContinue).Enabled -eq 0}};NetworkSecurity=@{FirewallEnabled=(Get-NetFirewallProfile|? Enabled -eq $true).Count;OutboundBlocked=(Get-NetFirewallProfile|? DefaultOutboundAction -eq 'Block').Count;InboundRules=(Get-NetFirewallRule|?{$_.Direction -eq 'Inbound' -and $_.Enabled -eq $true}).Count;OutboundRules=(Get-NetFirewallRule|?{$_.Direction -eq 'Outbound' -and $_.Enabled -eq $true}).Count};RemoteAccess=@{WinRMListeners=(Get-WSManInstance -ResourceURI winrm/config/listener -Enumerate -EA SilentlyContinue|measure).Count;WinRMService=(Get-Service -N 'WinRM' -EA SilentlyContinue).Status;WinRMStartupType=(Get-Service -N 'WinRM' -EA SilentlyContinue).StartType;RDPEnabled=(Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server" -N "fDenyTSConnections" -EA SilentlyContinue).fDenyTSConnections;RDPService=(Get-Service -N 'TermService' -EA SilentlyContinue).Status;RDPFirewallRule=(Get-NetFirewallRule -DisplayName "*Remote Desktop*"|? Enabled -eq $true|measure).Count}};SystemIntegrity=@{MalwareProtection=@{AntivirusEnabled=(Get-MpComputerStatus).AntivirusEnabled;RealTimeProtection=(Get-MpComputerStatus).RealTimeProtectionEnabled;DefinitionsUpToDate=(Get-MpComputerStatus).AntivirusSignatureAge -lt 7;QuarantineItems=(Get-MpThreatDetection|measure).Count};ASRRules=@{EnabledRules=(Get-MpPreference).AttackSurfaceReductionRules_Ids.Count;BlockMode=(Get-MpPreference).AttackSurfaceReductionRules_Actions -contains 1};ApplicationControl=@{SmartAppControl=Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy" -EA SilentlyContinue;WDACPolicy=Test-Path "$env:SystemRoot\System32\CodeIntegrity\SIPolicy.p7b"}};BackupVerification=@{URBackupClientStatus=(Get-Service -N 'urbackupclientbackend' -EA SilentlyContinue).Status;URBackupClientStartType=(Get-Service -N 'urbackupclientbackend' -EA SilentlyContinue).StartType;LastBackupDate=try{Get-ItemProperty "HKLM:\SOFTWARE\UrBackup\UrBackupClient" -N "last_backup" -EA Stop}catch{"Registry key not found"};BackupTestResults=Test-Path "C:\BackupRestoreTest.flag";SystemRestorePoints=(Get-ComputerRestorePoint -EA SilentlyContinue|measure).Count;URBackupProcessRunning=(Get-Process -N 'urbackupclientbackend' -EA SilentlyContinue)-ne $null;BackupDiskSpace=try{Get-WmiObject -Class Win32_LogicalDisk|? DeviceID -eq "C:"|select @{N="FreeSpaceGB";E={[math]::Round($_.FreeSpace/1GB,2)}}}catch{"Unable to retrieve disk space"}};ThirdPartyServices=@{InstalledThirdPartyServices=Get-Service|?{$_.ServiceName -notmatch '^(Microsoft|Windows|WinDefend|WSearch|Themes|BITS|EventLog|RpcSs|Dhcp|Dnscache|LanmanServer|LanmanWorkstation|Schedule|Spooler|AudioSrv|UxSms|ShellHWDetection|SamSs|PlugPlay|PolicyAgent|CryptSvc|TrustedInstaller|MpsSvc).*'}|select Name,Status,StartType,ServiceType;WizerTrainingStatus=@{Note="Manual verification required";CheckList="Training completion records in Security Binder";AnnualReview="DPA and SOC 2 compliance verification needed"};ExternalConnections=Get-NetTCPConnection|?{$_.RemoteAddress -notmatch '^(127\.0\.0\.1|::1|0\.0\.0\.0|169\.254\.)' -and $_.State -eq 'Established'}|select LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess;NetworkShares=Get-SmbShare|? Name -ne "IPC$"|select Name,Path,ShareState,ShareType;ScheduledTasks=Get-ScheduledTask|?{$_.TaskName -notmatch '^Microsoft' -and $_.State -eq 'Ready'}|select TaskName,TaskPath,State}} | ConvertTo-Json -Depth 8 | Out-File -FilePath $complianceFile -Encoding UTF8
    Write-CollectionLog "Compliance verification data collected: $complianceFile"
}

function Export-SecurityEventData {
    Write-Host "  - Collecting security event data..."
    $eventsFile = Join-Path $script:logFolderPath "security-events.json"
    @{Timestamp=(Get-Date -f 'o');Computer=$env:COMPUTERNAME;SecurityEvents=@{LogonEvents=Get-WinEvent -F @{LogName='Security';ID=4624,4625} -Max 100 -EA SilentlyContinue|select TimeCreated,Id,LevelDisplayName,@{N='EventData';E={$_.Message}};PrivilegeEvents=Get-WinEvent -F @{LogName='Security';ID=4672,4673,4674} -Max 50 -EA SilentlyContinue|select TimeCreated,Id,LevelDisplayName,@{N='EventData';E={$_.Message}};AccountEvents=Get-WinEvent -F @{LogName='Security';ID=4720,4722,4724,4726,4738,4740,4767} -Max 50 -EA SilentlyContinue|select TimeCreated,Id,LevelDisplayName,@{N='EventData';E={$_.Message}}};SystemEvents=@{CriticalErrors=Get-WinEvent -F @{LogName='System';Level=1,2} -Max 50 -EA SilentlyContinue|select TimeCreated,Id,LevelDisplayName,ProviderName,@{N='EventData';E={$_.Message}};ServiceEvents=Get-WinEvent -F @{LogName='System';ID=7034,7035,7036,7040} -Max 30 -EA SilentlyContinue|select TimeCreated,Id,LevelDisplayName,@{N='EventData';E={$_.Message}}};ApplicationEvents=@{Errors=Get-WinEvent -F @{LogName='Application';Level=1,2} -Max 30 -EA SilentlyContinue|select TimeCreated,Id,LevelDisplayName,ProviderName,@{N='EventData';E={$_.Message}}};DefenderEvents=@{ThreatDetections=Get-WinEvent -F @{LogName='Microsoft-Windows-Windows Defender/Operational';ID=1116,1117} -Max 20 -EA SilentlyContinue|select TimeCreated,Id,LevelDisplayName,@{N='EventData';E={$_.Message}};ASRBlocks=Get-WinEvent -F @{LogName='Microsoft-Windows-Windows Defender/Operational';ID=1121,1122} -Max 20 -EA SilentlyContinue|select TimeCreated,Id,LevelDisplayName,@{N='EventData';E={$_.Message}}}} | ConvertTo-Json -Depth 8 | Out-File -FilePath $eventsFile -Encoding UTF8
    Write-CollectionLog "Security event data collected: $eventsFile"
}

#===========================================================================
# SCRIPT EXECUTION
#===========================================================================

Clear-Host
Write-Host "=============================================" -ForegroundColor Magenta
Write-Host "==   COMPLIANCE DATA COLLECTION SCRIPT     ==" -ForegroundColor Magenta
Write-Host "=============================================" -ForegroundColor Magenta
Write-Host

$script:logFolderPath = Get-LogFolder

Write-Host "Data will be saved to: $script:logFolderPath" -ForegroundColor Yellow
Write-Host

try {
    Export-SystemBaseline
    Export-ComplianceVerification  
    Export-SecurityEventData
    Write-Host "`n[SUCCESS] Compliance data collection completed successfully." -ForegroundColor Green
    Write-CollectionLog "All compliance data collection completed successfully."
} catch {
    Write-Warning "`n[FAILED] A data collection error occurred: $_"
    Write-CollectionLog "[ERROR] Data collection failed: $_"
}

Write-Host
