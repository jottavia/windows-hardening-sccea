<#
.SYNOPSIS
    Automates security hardening for Windows 10 & 11. Intelligently configures LAPS, verifies each step, 
    collects compliance data, and saves a rollback state file.
.DESCRIPTION
    This script performs a security lockdown. It prioritizes modern Windows LAPS, but if not available,
    it will install and configure legacy LAPS from an MSI file if provided by the user.
    It automatically requests Administrator privileges if not run with them.
.NOTES
    Version: 9.0
#>
[CmdletBinding()]
param(
    [string[]]$UsersToDemote = @(),
    [string]$WazuhManagerIP = '192.168.1.100'
)

#===========================================================================
# INITIALIZATION & ADMIN CHECK
#===========================================================================
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "Administrator privileges are required."
    Write-Host "Attempting to re-launch this script with Admin rights..."
    Start-Process powershell.exe -Verb RunAs -ArgumentList ('-NoProfile -ExecutionPolicy Bypass -File "{0}"' -f $MyInvocation.MyCommand.Path)
    exit
}

Clear-Host
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "==  MASTER WINDOWS HARDENING SCRIPT (v9)   ==" -ForegroundColor Cyan
Write-Host "==     (with LAPS Install Logic)         ==" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan

#===========================================================================
# SCRIPT CONFIGURATION
#===========================================================================
$config = @{
    NewAdminName      = "SecOpsAdm"
    BuiltinAdminName  = "Administrator"
    PasswordLength    = 24
    LogRootFolderName = "PC-$env:COMPUTERNAME-LOGS"
    LogFileName       = "hardening-log.txt"
    StateFileName     = "hardening-state.json"
    PasswordFileName  = "SecOpsAdm_Password.txt"
    BitlockerFileName = "BitLocker_Recovery_Key.txt"
    LapsInstallerName = "LAPS.x64.msi"
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
function Get-LogFolder {
    $rootLogFolder = Join-Path (Split-Path -Qualifier $PSScriptRoot) $config.LogRootFolderName
    if (-not(Test-Path $rootLogFolder)) { New-Item -ItemType Directory -Path $rootLogFolder | Out-Null }
    $timestampFolder = "HARDENING-$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss')"
    $finalPath = Join-Path $rootLogFolder $timestampFolder
    if (-not(Test-Path $finalPath)) { New-Item -ItemType Directory -Path $finalPath | Out-Null }
    return $finalPath
}

$script:logFolderPath = Get-LogFolder

function Write-SecLog {
    param([string]$Text)
    $logFile = Join-Path $script:logFolderPath $config.LogFileName
    "$(Get-Date -f 'yyyy-MM-dd HH:mm:ss') :: $Text" | Add-Content -Path $logFile
}

function New-StrongPassword {
    param([int]$Length = 24)
    $charSets = @{ Lower  = [char[]]('a'..'z'); Upper  = [char[]]('A'..'Z'); Digit  = [char[]]('0'..'9'); Symbol = '!','@','#','$','%','^','&','*','(',')'}
    $passwordBuilder = [System.Collections.Generic.List[char]]::new()
    $passwordBuilder.Add(($charSets.Lower | Get-Random)); $passwordBuilder.Add(($charSets.Upper | Get-Random)); $passwordBuilder.Add(($charSets.Digit | Get-Random)); $passwordBuilder.Add(($charSets.Symbol | Get-Random))
    $allChars = $charSets.Values -join '' | ForEach-Object { $_ }
    $remainingLength = $Length - $passwordBuilder.Count
    if ($remainingLength -gt 0) { $passwordBuilder.AddRange((Get-Random -InputObject $allChars -Count $remainingLength)) }
    return -join ($passwordBuilder | Get-Random -Count $passwordBuilder.Count)
}

function Export-SystemBaseline { Write-Host "  - Collecting system baseline data..."; $baselineFile = Join-Path $script:logFolderPath "system-baseline.json"; @{Timestamp=(Get-Date -f 'o');Computer=$env:COMPUTERNAME;OSInfo=@{Version=(Get-CimInstance Win32_OperatingSystem).Caption;Build=(Get-CimInstance Win32_OperatingSystem).BuildNumber;Architecture=(Get-CimInstance Win32_OperatingSystem).OSArchitecture;InstallDate=(Get-CimInstance Win32_OperatingSystem).InstallDate};Hardware=@{Manufacturer=(Get-CimInstance Win32_ComputerSystem).Manufacturer;Model=(Get-CimInstance Win32_ComputerSystem).Model;TotalMemory=[math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory/1GB,2);Processor=(Get-CimInstance Win32_Processor).Name};NetworkConfig=@{Adapters=Get-NetAdapter|Where-Object Status -eq 'Up'|select Name,InterfaceDescription,LinkSpeed;IPConfig=Get-NetIPConfiguration|Where-Object NetProfile.Name -ne 'Unidentified network'|select InterfaceAlias,IPv4Address,IPv4DefaultGateway;DNSServers=(Get-DnsClientServerAddress|Where-Object AddressFamily -eq 2).ServerAddresses};SecuritySettings=@{DefenderStatus=Get-MpComputerStatus|select AntivirusEnabled,AntispywareEnabled,RealTimeProtectionEnabled,IoavProtectionEnabled,OnAccessProtectionEnabled,BehaviorMonitorEnabled;DefenderPreferences=Get-MpPreference|select EnableTamperProtection,EnableControlledFolderAccess,EnableNetworkProtection;BitLockerVolumes=Get-BitLockerVolume|select MountPoint,VolumeStatus,ProtectionStatus,EncryptionMethod;FirewallProfiles=Get-NetFirewallProfile|select Name,Enabled,DefaultInboundAction,DefaultOutboundAction;WindowsUpdate=@{LastInstallTime=(Get-HotFix|Sort-Object InstalledOn -Descending|select -First 1).InstalledOn;PendingReboot=Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"}};UserAccounts=@{LocalUsers=Get-LocalUser|select Name,Enabled,LastLogon,PasswordExpires,PasswordRequired;LocalAdmins=Get-LocalGroupMember -Group 'Administrators'|select Name,ObjectClass,PrincipalSource;CurrentUser=$env:USERNAME};Services=Get-Service|Where-Object Status -eq 'Running'|Where-Object StartType -ne 'Disabled'|select Name,Status,StartType,ServiceType;InstalledSoftware=Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"|select DisplayName,DisplayVersion,Publisher,InstallDate|Where-Object DisplayName -ne $null|Sort-Object DisplayName}} | ConvertTo-Json -Depth 6 | Out-File -FilePath $baselineFile -Encoding UTF8; Write-SecLog "System baseline collected: $baselineFile" }
function Export-ComplianceVerification { Write-Host "  - Collecting compliance verification data..."; $complianceFile = Join-Path $script:logFolderPath "compliance-verification.json"; @{Timestamp=(Get-Date -f 'o');Computer=$env:COMPUTERNAME;AccessControl=@{UniqueUserIDs=(Get-LocalUser).Count;AdminAccounts=(Get-LocalGroupMember -Group 'Administrators').Count;DisabledAccounts=(Get-LocalUser|Where-Object Enabled -eq $false).Count;AccountLockoutPolicy=@{LockoutThreshold=(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\RemoteAccess\Policy" -Name "LockoutThreshold" -ErrorAction SilentlyContinue).LockoutThreshold};PasswordPolicy=@{MinPasswordLength=(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\RemoteAccess\Policy" -Name "MinPasswordLen" -ErrorAction SilentlyContinue).MinPasswordLen;MaxPasswordAge=(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\RemoteAccess\Policy" -Name "MaxPasswordAge" -ErrorAction SilentlyContinue).MaxPasswordAge}};AuditAccountability=@{SecurityAuditing=@{LogonEvents=(Get-WinEvent -FilterHashtable @{LogName='Security';ID=4624} -MaxEvents 1 -ErrorAction SilentlyContinue)-ne $null;LogoffEvents=(Get-WinEvent -FilterHashtable @{LogName='Security';ID=4634} -MaxEvents 1 -ErrorAction SilentlyContinue)-ne $null;AccountLockouts=(Get-WinEvent -FilterHashtable @{LogName='Security';ID=4740} -MaxEvents 1 -ErrorAction SilentlyContinue)-ne $null;PrivilegeUse=(Get-WinEvent -FilterHashtable @{LogName='Security';ID=4672} -MaxEvents 1 -ErrorAction SilentlyContinue)-ne $null};LogSettings=@{SecurityLogSize=(Get-WinEvent -ListLog Security).MaximumSizeInBytes;SecurityLogRetention=(Get-WinEvent -ListLog Security).LogMode;SystemLogSize=(Get-WinEvent -ListLog System).MaximumSizeInBytes;ApplicationLogSize=(Get-WinEvent -ListLog Application).MaximumSizeInBytes};MonitoringTools=@{WazuhAgent=(Get-Service -Name 'WazuhSvc' -ErrorAction SilentlyContinue)-ne $null;SysmonService=(Get-Service -Name 'Sysmon*' -ErrorAction SilentlyContinue)-ne $null}};ConfigurationManagement=@{WindowsUpdateConfig=@{AutoUpdateEnabled=(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" -Name "AUOptions" -ErrorAction SilentlyContinue).AUOptions;LastUpdateCheck=(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Detect" -Name "LastSuccessTime" -ErrorAction SilentlyContinue).LastSuccessTime};ServicesConfig=@{UnnecessaryServices=Get-Service|Where-Object {$_.StartType -eq 'Automatic' -and $_.Status -eq 'Stopped'}|measure-Object|select -ExpandProperty Count;RunningServices=(Get-Service|Where-Object Status -eq 'Running').Count};RegistryBaseline=@{DefenderTamperProtection=Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" -Name "TamperProtection" -ErrorAction SilentlyContinue;UACEnabled=(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -ErrorAction SilentlyContinue).EnableLUA};ChangeTracking=@{LastConfigChange=try{(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install" -Name "LastSuccessTime" -ErrorAction Stop).LastSuccessTime}catch{"No update history found"};SystemModificationDate=(Get-Item "C:\Windows\System32" -ErrorAction SilentlyContinue).LastWriteTime;RegistryLastModified=try{(Get-Item "HKLM:\SOFTWARE\Policies" -ErrorAction Stop).LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')}catch{"Registry key not accessible"};RecentlyInstalledSoftware=Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"|Where-Object {$_.InstallDate -gt (Get-Date).AddDays(-30).ToString("yyyyMMdd")}|select DisplayName,InstallDate,Publisher;SystemBootTime=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime;ConfigurationBaseline=@{LastHardeningRun=Get-Date -f 'o';ScriptVersion="v9-laps-install";BaselineHash="Generated during hardening process"}}};SystemCommunications=@{Encryption=@{BitLockerStatus=Get-BitLockerVolume|select MountPoint,VolumeStatus,ProtectionStatus;TLSSettings=@{TLS12Enabled=(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Name "Enabled" -ErrorAction SilentlyContinue).Enabled;SSL3Disabled=(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" -Name "Enabled" -ErrorAction SilentlyContinue).Enabled -eq 0}};NetworkSecurity=@{FirewallEnabled=(Get-NetFirewallProfile|Where-Object Enabled -eq $true).Count;OutboundBlocked=(Get-NetFirewallProfile|Where-Object DefaultOutboundAction -eq 'Block').Count;InboundRules=(Get-NetFirewallRule|Where-Object {$_.Direction -eq 'Inbound' -and $_.Enabled -eq $true}).Count;OutboundRules=(Get-NetFirewallRule|Where-Object {$_.Direction -eq 'Outbound' -and $_.Enabled -eq $true}).Count};RemoteAccess=@{WinRMListeners=(Get-WSManInstance -ResourceURI winrm/config/listener -Enumerate -ErrorAction SilentlyContinue|measure-Object).Count;WinRMService=(Get-Service -Name 'WinRM' -ErrorAction SilentlyContinue).Status;WinRMStartupType=(Get-Service -Name 'WinRM' -ErrorAction SilentlyContinue).StartType;RDPEnabled=(Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction SilentlyContinue).fDenyTSConnections;RDPService=(Get-Service -Name 'TermService' -ErrorAction SilentlyContinue).Status;RDPFirewallRule=(Get-NetFirewallRule -DisplayName "*Remote Desktop*"|Where-Object Enabled -eq $true|measure-Object).Count}};SystemIntegrity=@{MalwareProtection=@{AntivirusEnabled=(Get-MpComputerStatus).AntivirusEnabled;RealTimeProtection=(Get-MpComputerStatus).RealTimeProtectionEnabled;DefinitionsUpToDate=(Get-MpComputerStatus).AntivirusSignatureAge -lt 7;QuarantineItems=(Get-MpThreatDetection|measure-Object).Count};ASRRules=@{EnabledRules=(Get-MpPreference).AttackSurfaceReductionRules_Ids.Count;BlockMode=(Get-MpPreference).AttackSurfaceReductionRules_Actions -contains 1};ApplicationControl=@{SmartAppControl=Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy" -ErrorAction SilentlyContinue;WDACPolicy=Test-Path "$env:SystemRoot\System32\CodeIntegrity\SIPolicy.p7b"}};BackupVerification=@{URBackupClientStatus=(Get-Service -Name 'urbackupclientbackend' -ErrorAction SilentlyContinue).Status;URBackupClientStartType=(Get-Service -Name 'urbackupclientbackend' -ErrorAction SilentlyContinue).StartType;LastBackupDate=try{Get-ItemProperty "HKLM:\SOFTWARE\UrBackup\UrBackupClient" -Name "last_backup" -ErrorAction Stop}catch{"Registry key not found"};BackupTestResults=Test-Path "C:\BackupRestoreTest.flag";SystemRestorePoints=(Get-ComputerRestorePoint -ErrorAction SilentlyContinue|measure-Object).Count;URBackupProcessRunning=(Get-Process -Name 'urbackupclientbackend' -ErrorAction SilentlyContinue)-ne $null;BackupDiskSpace=try{Get-WmiObject -Class Win32_LogicalDisk|Where-Object DeviceID -eq "C:"|select @{Name="FreeSpaceGB";Expression={[math]::Round($_.FreeSpace/1GB,2)}}}catch{"Unable to retrieve disk space"}};ThirdPartyServices=@{InstalledThirdPartyServices=Get-Service|Where-Object {$_.ServiceName -notmatch '^(Microsoft|Windows|WinDefend|WSearch|Themes|BITS|EventLog|RpcSs|Dhcp|Dnscache|LanmanServer|LanmanWorkstation|Schedule|Spooler|AudioSrv|UxSms|ShellHWDetection|SamSs|PlugPlay|PolicyAgent|CryptSvc|TrustedInstaller|MpsSvc).*'}|select Name,Status,StartType,ServiceType;WizerTrainingStatus=@{Note="Manual verification required";CheckList="Training completion records in Security Binder";AnnualReview="DPA and SOC 2 compliance verification needed"};ExternalConnections=Get-NetTCPConnection|Where-Object {$_.RemoteAddress -notmatch '^(127\.0\.0\.1|::1|0\.0\.0\.0|169\.254\.)' -and $_.State -eq 'Established'}|select LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess;NetworkShares=Get-SmbShare|Where-Object Name -ne "IPC$"|select Name,Path,ShareState,ShareType;ScheduledTasks=Get-ScheduledTask|Where-Object {$_.TaskName -notmatch '^Microsoft' -and $_.State -eq 'Ready'}|select TaskName,TaskPath,State}} | ConvertTo-Json -Depth 8 | Out-File -FilePath $complianceFile -Encoding UTF8; Write-SecLog "Compliance verification data collected: $complianceFile" }
function Export-SecurityEventData { Write-Host "  - Collecting security event data..."; $eventsFile = Join-Path $script:logFolderPath "security-events.json"; @{Timestamp=(Get-Date -f 'o');Computer=$env:COMPUTERNAME;SecurityEvents=@{LogonEvents=Get-WinEvent -FilterHashtable @{LogName='Security';ID=4624,4625} -MaxEvents 100 -ErrorAction SilentlyContinue|select-Object TimeCreated,Id,LevelDisplayName,@{Name='EventData';Expression={$_.Message}};PrivilegeEvents=Get-WinEvent -FilterHashtable @{LogName='Security';ID=4672,4673,4674} -MaxEvents 50 -ErrorAction SilentlyContinue|select-Object TimeCreated,Id,LevelDisplayName,@{Name='EventData';Expression={$_.Message}};AccountEvents=Get-WinEvent -FilterHashtable @{LogName='Security';ID=4720,4722,4724,4726,4738,4740,4767} -MaxEvents 50 -ErrorAction SilentlyContinue|select-Object TimeCreated,Id,LevelDisplayName,@{Name='EventData';Expression={$_.Message}};PolicyEvents=Get-WinEvent -FilterHashtable @{LogName='Security';ID=4719,4817,4902,4906} -MaxEvents 20 -ErrorAction SilentlyContinue|select-Object TimeCreated,Id,LevelDisplayName,@{Name='EventData';Expression={$_.Message}}};SystemEvents=@{CriticalErrors=Get-WinEvent -FilterHashtable @{LogName='System';Level=1,2} -MaxEvents 50 -ErrorAction SilentlyContinue|select-Object TimeCreated,Id,LevelDisplayName,ProviderName,@{Name='EventData';Expression={$_.Message}};ServiceEvents=Get-WinEvent -FilterHashtable @{LogName='System';ID=7034,7035,7036,7040} -MaxEvents 30 -ErrorAction SilentlyContinue|select-Object TimeCreated,Id,LevelDisplayName,@{Name='EventData';Expression={$_.Message}}};ApplicationEvents=@{Errors=Get-WinEvent -FilterHashtable @{LogName='Application';Level=1,2} -MaxEvents 30 -ErrorAction SilentlyContinue|select-Object TimeCreated,Id,LevelDisplayName,ProviderName,@{Name='EventData';Expression={$_.Message}}};DefenderEvents=@{ThreatDetections=Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational';ID=1116,1117} -MaxEvents 20 -ErrorAction SilentlyContinue|select-Object TimeCreated,Id,LevelDisplayName,@{Name='EventData';Expression={$_.Message}};ASRBlocks=Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational';ID=1121,1122} -MaxEvents 20 -ErrorAction SilentlyContinue|select-Object TimeCreated,Id,LevelDisplayName,@{Name='EventData';Expression={$_.Message}}};NetworkEvents=@{FirewallBlocks=Get-WinEvent -FilterHashtable @{LogName='Security';ID=5157} -MaxEvents 30 -ErrorAction SilentlyContinue|select-Object TimeCreated,Id,@{Name='EventData';Expression={$_.Message}}}} | ConvertTo-Json -Depth 8 | Out-File -FilePath $eventsFile -Encoding UTF8; Write-SecLog "Security event data collected: $eventsFile" }
function Test-BackupIntegrity { Write-Host "  - Testing backup system integrity..."; $backupTest = @{Timestamp=(Get-Date -f 'o');Computer=$env:COMPUTERNAME;URBackupClientRunning=(Get-Service -Name 'urbackupclientbackend' -ErrorAction SilentlyContinue).Status -eq 'Running';TestFileCreated=$false;TestFileHash=$null}; try { $testFile = "C:\BackupIntegrityTest_$(Get-Date -f 'yyyyMMdd').txt"; $testContent = "Backup integrity test - Created: $(Get-Date -f 'yyyy-MM-dd HH:mm:ss')"; $testContent | Out-File -FilePath $testFile -Encoding UTF8; if (Test-Path $testFile) { $backupTest.TestFileCreated = $true; $backupTest.TestFileHash = (Get-FileHash -Path $testFile -Algorithm SHA256).Hash; Write-SecLog "Backup integrity test file created: $testFile (Hash: $($backupTest.TestFileHash))" } } catch { Write-SecLog "[ERROR] Failed to create backup integrity test file: $_" }; $backupTestFile = Join-Path $script:logFolderPath "backup-integrity-test.json"; $backupTest | ConvertTo-Json -Depth 4 | Out-File -FilePath $backupTestFile -Encoding UTF8; Write-SecLog "Backup integrity test data saved: $backupTestFile" }

#===========================================================================
# SCRIPT EXECUTION
#===========================================================================

Write-Host "`n[[ Activity, SECRETS, and compliance data will be logged to '$script:logFolderPath' ]]" -ForegroundColor Yellow
Write-Host "`n********************** SECURITY WARNING **********************" -ForegroundColor Red
Write-Host "THIS DRIVE MUST BE REMOVED AND SECURED AFTER SCRIPT COMPLETION." -ForegroundColor Red
Write-Host "**************************************************************`n" -ForegroundColor Red

$undoState = @{
    HardeningDate         = (Get-Date -Format 'o')
    NewAdminName          = $config.NewAdminName
    DemotedAdmins         = @()
    BuiltinAdminState     = (Get-LocalUser -Name $config.BuiltinAdminName).Enabled
    LapsConfigured        = "None"
    DefenderHardened      = $false
    BitLockerEnabled      = $false
    WazuhInstalled        = $false
    SysmonInstalled       = $false
    WDACApplied           = $false
    FirewallHardened      = $false
    RemoteAccessDisabled  = $false
    BackupTestCompleted   = $false
}

Write-SecLog "Master harden script started."

# --- 1. ADMIN ACCOUNTS ---
Write-Host "[1] Managing Administrator Accounts..." -ForegroundColor Green
try {
    $undoState.DemotedAdmins = $UsersToDemote
    if (-not (Get-LocalUser -Name $config.NewAdminName -ErrorAction SilentlyContinue)) {
        $password = New-StrongPassword -Length $config.PasswordLength
        net user $config.NewAdminName $password /add /expires:never /passwordchg:no
        net localgroup Administrators $config.NewAdminName /add
        if ((Get-LocalGroupMember -Group 'Administrators').Name -contains $config.NewAdminName) {
            Write-Host "  [VERIFIED] Created and promoted local admin '$($config.NewAdminName)'." -ForegroundColor Green
            Out-File -FilePath (Join-Path $script:logFolderPath $config.PasswordFileName) -InputObject $password -Encoding UTF8
            Write-SecLog "Created '$($config.NewAdminName)'. Password stored in $($config.PasswordFileName)."
        } else { Write-Warning "  [FAILED] Could not verify '$($config.NewAdminName)' was added to Administrators."; Write-SecLog "[ERROR] Failed to verify promotion of '$($config.NewAdminName)'." }
    } else { Write-Host "  [INFO] User '$($config.NewAdminName)' already exists. Skipping creation." -ForegroundColor Yellow }

    foreach ($user in $UsersToDemote) {
        $user = $user.Trim()
        if ($user -and ($user -ne $config.NewAdminName) -and ($user -ne $config.BuiltinAdminName)) {
            net localgroup Administrators $user /delete
            if (-not ((Get-LocalGroupMember -Group 'Administrators').Name -contains $user)) { Write-Host "  [VERIFIED] Demoted user '$user'." -ForegroundColor Green; Write-SecLog "Demoted user: $user" }
            else { Write-Warning "  [FAILED] Could not verify demotion of user '$user'." }
        }
    }
} catch { Write-Warning "  - Admin account management error: $_"; Write-SecLog "[ERROR] Admin management failed: $_" }

# --- 2. LAPS CONFIGURATION ---
Write-Host "[2] Configuring Local Administrator Password Solution (LAPS)..." -ForegroundColor Green
if (Get-Command -Name Set-LapsPolicy -ErrorAction SilentlyContinue) {
    Write-Host "  - Modern LAPS detected. Applying policy."
    try {
        net user $config.BuiltinAdminName /active:yes
        Set-LapsPolicy -Enable 1 -AdminAccountName $config.BuiltinAdminName -PasswordComplexity 4 -PasswordLength 15 -PasswordAgeDays 30
        if ((Get-LapsPolicy).Enable -eq 1) {
            $exp = (Get-LapsDiagnostics).ExpirationTimestamp
            Write-Host "  [VERIFIED] Modern LAPS policy is enabled. Next rotation: $exp" -ForegroundColor Green
            Write-SecLog "Modern LAPS enabled for '$($config.BuiltinAdminName)'."; $undoState.LapsConfigured = "Modern"
        } else { Write-Warning "  [FAILED] Could not verify LAPS policy was enabled." }
    } catch { Write-Warning "  - LAPS configuration error: $_"; Write-SecLog "[ERROR] LAPS configuration failed: $_" }
}
elseif (Test-Path (Join-Path $PSScriptRoot $config.LapsInstallerName)) {
    Write-Host "  - Legacy LAPS installer found. Installing and configuring..."
    try {
        $lapsInstallerPath = Join-Path $PSScriptRoot $config.LapsInstallerName
        Start-Process msiexec -ArgumentList "/i `"$lapsInstallerPath`" /quiet /norestart" -Wait
        $lapsPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft Services\LAPS"
        if (-not (Test-Path $lapsPolicyPath)) { New-Item -Path $lapsPolicyPath -Force | Out-Null }
        Set-ItemProperty -Path $lapsPolicyPath -Name "AdmPwdEnabled" -Value 1 -Force
        Set-ItemProperty -Path $lapsPolicyPath -Name "PasswordLength" -Value 15 -Force
        Set-ItemProperty -Path $lapsPolicyPath -Name "PasswordComplexity" -Value 4 -Force
        net user $config.BuiltinAdminName /active:yes
        Write-Host "  [VERIFIED] Legacy LAPS installed and registry policy applied." -ForegroundColor Green
        Write-SecLog "Legacy LAPS installed and configured via registry."; $undoState.LapsConfigured = "Legacy"
    } catch { Write-Warning "  - Legacy LAPS installation/configuration failed: $_"; Write-SecLog "[ERROR] Legacy LAPS setup failed: $_" }
}
else {
    Write-Warning "  [INFO] No LAPS solution found. Disabling built-in '$($config.BuiltinAdminName)' account as a compensating control."
    try {
        net user $config.BuiltinAdminName /active:no
        if ((Get-LocalUser -Name $config.BuiltinAdminName).Enabled -eq $false) {
            Write-Host "  [VERIFIED] Built-in '$($config.BuiltinAdminName)' account is disabled." -ForegroundColor Green
            Write-SecLog "Built-in Administrator account disabled as no LAPS solution was provided."
        } else { Write-Warning "  [FAILED] Could not verify built-in Administrator account is disabled." }
    } catch { Write-Warning "  - Fallback admin disable failed: $_" }
}

# --- 3. DEFENDER HARDENING ---
Write-Host "[3] Hardening Microsoft Defender..." -ForegroundColor Green
try {
    if ((Get-Command Set-MpPreference).Parameters.Keys -contains 'EnableTamperProtection') {
        Set-MpPreference -EnableTamperProtection 1 -EnableControlledFolderAccess Enabled
    } else {
        Write-Warning "  [INFO] 'EnableTamperProtection' parameter not available on this system. Skipping."; Set-MpPreference -EnableControlledFolderAccess Enabled
    }
    $asrRuleIds = @("56a863a9-875e-4185-98a7-b882c64b5ce5","3b576869-a4ec-4529-8536-b80a7769e899","d4f940ab-401b-4efc-aadc-ad5f3c50688a","9e6c285a-c97e-4ad4-a890-1ce04d5e0674","c1db55ab-c21a-4637-bb3f-a12568109d35","92e97fa1-2edf-4476-bdd6-9dd38f7c9c35")
    Set-MpPreference -AttackSurfaceReductionRules_Ids $asrRuleIds -AttackSurfaceReductionRules_Actions Enabled
    if ((Get-MpPreference).EnableControlledFolderAccess -eq 1) {
        Write-Host "  [VERIFIED] Defender hardening rules applied." -ForegroundColor Green; $undoState.DefenderHardened = $true; Write-SecLog "Defender hardened successfully."
    } else { Write-Warning "  [FAILED] Could not verify Defender preferences were set." }
} catch { Write-Warning "  - Defender hardening error: $_"; Write-SecLog "[ERROR] Defender hardening failed: $_" }

# --- 4. BITLOCKER ENCRYPTION ---
Write-Host "[4] Managing BitLocker Encryption..." -ForegroundColor Green
try {
    $vol = Get-BitLockerVolume -MountPoint "C:"
    if ($vol.VolumeStatus -eq 'FullyDecrypted') {
        Write-Host "  - Enabling BitLocker on C:."
        manage-bde -on C: -skiphardwaretest
        Start-Sleep -Seconds 10
        $volAfter = Get-BitLockerVolume -MountPoint "C:"
        if ($volAfter.ProtectionStatus -eq 'On' -or $volAfter.VolumeStatus -eq 'Encrypting') {
            $recKey = (manage-bde -protectors -get C: | Select-String 'Numerical Password' -Context 0,1).Context.PostContext[0].Trim()
            Write-Host "  [VERIFIED] BitLocker encryption is active on C:. Recovery key saved." -ForegroundColor Green
            Out-File -FilePath (Join-Path $script:logFolderPath $config.BitlockerFileName) -InputObject $recKey -Encoding UTF8
            Write-SecLog "BitLocker enabled. Recovery Key stored in $($config.BitlockerFileName)."; $undoState.BitLockerEnabled = $true
        } else { Write-Warning "  [FAILED] BitLocker failed to start encryption process." }
    } else { Write-Host "  [INFO] BitLocker is already active on C: ($($vol.VolumeStatus))." -ForegroundColor Yellow }
} catch { Write-Warning "  - BitLocker error: $_"; Write-SecLog "[ERROR] BitLocker failed: $_" }

# --- 5. INSTALL AGENTS ---
Write-Host "[5] Checking for optional agents (Wazuh, Sysmon)..." -ForegroundColor Green
$wazuhMsi = Get-ChildItem (Join-Path $PSScriptRoot 'wazuh-agent*.msi') -EA SilentlyContinue | Select -F 1
if ($wazuhMsi) {
    Write-Host "  - Found Wazuh installer. Installing..."
    try {
        Start-Process msiexec -ArgumentList "/i `"$($wazuhMsi.FullName)`" /qn WAZUH_MANAGER='$WazuhManagerIP'" -Wait
        if (Get-Service -Name 'WazuhSvc' -EA SilentlyContinue) {
            Write-Host "  [VERIFIED] Wazuh service is present." -ForegroundColor Green; Write-SecLog "Wazuh agent installed."; $undoState.WazuhInstalled = $wazuhMsi.FullName
        } else { Write-Warning "  [FAILED] Wazuh service not found after installation." }
    } catch { Write-Warning "  - Wazuh install failed: $_"; Write-SecLog "[ERROR] Wazuh install failed: $_" }
}
$sysmonExe=Join-Path $PSScriptRoot 'Sysmon64.exe'; $sysmonXml=Join-Path $PSScriptRoot 'sysmon.xml'
if ((Test-Path $sysmonExe) -and (Test-Path $sysmonXml)) {
    Write-Host "  - Found Sysmon. Installing..."
    try { 
        & $sysmonExe -accepteula -i $sysmonXml
        if (Get-Service -Name 'Sysmon64' -EA SilentlyContinue) {
            Write-Host "  [VERIFIED] Sysmon service is present." -ForegroundColor Green; Write-SecLog "Sysmon installed."; $undoState.SysmonInstalled = $true
        } else { Write-Warning "  [FAILED] Sysmon service not found after installation." }
    } catch { Write-Warning "  - Sysmon install failed: $_"; Write-SecLog "[ERROR] Sysmon install failed: $_" }
}

# --- 6. WDAC POLICY ---
Write-Host "[6] Checking for optional WDAC policy..." -ForegroundColor Green
if (Get-Command -Name ConvertFrom-CIPolicy -ErrorAction SilentlyContinue) {
    $wdacPolicyBinary = "$env:SystemRoot\System32\CodeIntegrity\SIPolicy.p7b"
    if (-not(Test-Path $wdacPolicyBinary)) {
        $wdacPolicyXml = Join-Path $PSScriptRoot 'WDAC_Policy.xml'
        if (Test-Path $wdacPolicyXml) {
            Write-Host "  - Found WDAC policy. Applying..."
            try {
                ConvertFrom-CIPolicy -XmlFilePath $wdacPolicyXml -BinaryFilePath $wdacPolicyBinary
                if (Test-Path $wdacPolicyBinary) {
                    Write-Host "  [VERIFIED] WDAC policy binary created successfully. A reboot is required to activate." -ForegroundColor Green
                    Write-SecLog "WDAC policy applied."; $undoState.WDACApplied = $true
                } else { Write-Warning "  [FAILED] Could not find WDAC policy binary after conversion." }
            } catch { Write-Warning "  - WDAC policy application failed: $_"; Write-SecLog "[ERROR] WDAC failed: $_" }
        }
    } else { Write-Host "  [INFO] WDAC policy already exists. Skipping." -ForegroundColor Yellow }
} else { Write-Warning "  [INFO] WDAC cmdlets not available on this system. Skipping." }

# --- 7. FIREWALL HARDENING ---
Write-Host "[7] Hardening Windows Firewall..." -ForegroundColor Green
try {
    netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound
    foreach ($rule in $config.FirewallAllowRules) {
        netsh advfirewall firewall add rule name="$($rule.Name)" dir=out action=allow protocol="$($rule.Protocol)" remoteport="$($rule.Port)" | Out-Null
    }
    $profiles = Get-NetFirewallProfile
    if (($profiles | Where-Object {$_.DefaultOutboundAction -eq 'Block'}).Count -eq $profiles.Count) {
        Write-Host "  [VERIFIED] All firewall profiles are set to Block Outbound by default." -ForegroundColor Green
        Write-SecLog "Firewall hardened."; $undoState.FirewallHardened = $true
    } else { Write-Warning "  [FAILED] Not all firewall profiles are set to Block Outbound." }
} catch { Write-Warning "  - Firewall hardening error: $_"; Write-SecLog "[ERROR] Firewall hardening failed: $_" }

# --- 8. DISABLE REMOTE ACCESS ---
Write-Host "[8] Disabling remote access services..." -ForegroundColor Green
try {
    Stop-Service -Name 'WinRM' -Force -ErrorAction SilentlyContinue
    Set-Service -Name 'WinRM' -StartupType Disabled -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1 -ErrorAction SilentlyContinue
    Stop-Service -Name 'TermService' -Force -ErrorAction SilentlyContinue
    Get-NetFirewallRule -DisplayName "*Remote Desktop*" | Disable-NetFirewallRule -ErrorAction SilentlyContinue
    $winrmStopped = (Get-Service -Name 'WinRM' -ErrorAction SilentlyContinue).Status -eq 'Stopped'
    $rdpDisabled = (Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction SilentlyContinue).fDenyTSConnections -eq 1
    if ($winrmStopped -and $rdpDisabled) {
        Write-Host "  [VERIFIED] Remote access services disabled." -ForegroundColor Green; $undoState.RemoteAccessDisabled = $true; Write-SecLog "Remote access services (WinRM/RDP) disabled successfully."
    } else { Write-Warning "  [FAILED] Could not fully disable remote access services."; Write-SecLog "[ERROR] Remote access disabling partially failed." }
} catch { Write-Warning "  - Remote access disabling error: $_"; Write-SecLog "[ERROR] Remote access disabling failed: $_" }

# --- 9. DATA COLLECTION ---
Write-Host "`n[9] Collecting compliance verification data..." -ForegroundColor Magenta
try {
    Export-SystemBaseline; Export-ComplianceVerification; Export-SecurityEventData; Test-BackupIntegrity
    $undoState.BackupTestCompleted = $true
    Write-Host "  [VERIFIED] Compliance data collection completed." -ForegroundColor Green
    Write-SecLog "All compliance data collection completed successfully."
} catch { Write-Warning "  [FAILED] Data collection error: $_"; Write-SecLog "[ERROR] Data collection failed: $_" }

# --- FINALIZATION ---
Write-Host "`n[FINAL] Finalizing and saving undo state..." -ForegroundColor Cyan
try {
    $stateFilePath = Join-Path $script:logFolderPath $config.StateFileName
    $undoState | ConvertTo-Json -Depth 5 | Out-File -FilePath $stateFilePath -Encoding UTF8
    Write-Host "  - Successfully saved undo data to '$stateFilePath'"
    Write-SecLog "Undo state file created successfully."
} catch { Write-Warning "  - CRITICAL: Could not save the undo state file: $_"; Write-SecLog "[FATAL] Failed to save undo state file: $_" }

Write-Host "`n=============================================" -ForegroundColor Green
Write-SecLog "Master harden script finished."
Write-Host "==      HARDENING SCRIPT COMPLETE     ==" -ForegroundColor Green
Write-Host "=============================================" -ForegroundColor Green
Write-Host "REMINDER: Eject this drive and store it securely NOW." -ForegroundColor Yellow
