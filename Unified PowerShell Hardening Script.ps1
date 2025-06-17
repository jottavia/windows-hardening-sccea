<#
.SYNOPSIS
    Automates security hardening, verifies each step, collects compliance data, and saves a rollback state file.
.DESCRIPTION
    Performs a security lockdown, confirms each change, gathers extensive compliance and event data into JSON files,
    and creates a 'hardening-state.json' file for the Undo-Hardening.ps1 script.

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
# HELPER FUNCTIONS
#===========================================================================
function New-StrongPassword { param([int]$Length = 20); $charSets=@{Lower=[char[]]('a'..'z');Upper=[char[]]('A'..'Z');Digit=[char[]]('0'..'9');Symbol='!@#$%^&*()_+-=[]{}|';};$p=@();$p+=$charSets.Lower|Get-Random;$p+=$charSets.Upper|Get-Random;$p+=$charSets.Digit|Get-Random;$p+=$charSets.Symbol|Get-Random;$allChars=$charSets.Values-join''|%{$_};$rem=$Length-$p.Count;if($rem-gt 0){$p+=Get-Random -InputObject $allChars -Count $rem};return -join($p|Get-Random -Count $p.Count)}
function Get-ScriptDriveRoot { return (Split-Path -Qualifier $PSScriptRoot) }
function Get-LogFolder { $d=Get-ScriptDriveRoot; $f=Join-Path $d $config.LogFolderName; if(-not(Test-Path $f)){New-Item -ItemType Directory -Path $f|Out-Null}; return $f }
function Write-SecLog { param([string]$Text); $logFile=Join-Path (Get-LogFolder) $config.LogFileName; "$(Get-Date -f 'yyyy-MM-dd HH:mm:ss') :: $Text"|Add-Content -Path $logFile }

# --- New Data Collection Functions ---

function Export-SystemBaseline {
    Write-Host "  - Collecting system baseline data..."
    
    $baseline = @{
        Timestamp = Get-Date -Format 'o'
        Computer = $env:COMPUTERNAME
        OSInfo = @{
            Version = (Get-CimInstance Win32_OperatingSystem).Caption
            Build = (Get-CimInstance Win32_OperatingSystem).BuildNumber
            Architecture = (Get-CimInstance Win32_OperatingSystem).OSArchitecture
            InstallDate = (Get-CimInstance Win32_OperatingSystem).InstallDate
        }
        Hardware = @{
            Manufacturer = (Get-CimInstance Win32_ComputerSystem).Manufacturer
            Model = (Get-CimInstance Win32_ComputerSystem).Model
            TotalMemory = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2)
            Processor = (Get-CimInstance Win32_Processor).Name
        }
        NetworkConfig = @{
            Adapters = Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object Name, InterfaceDescription, LinkSpeed
            IPConfig = Get-NetIPConfiguration | Where-Object NetProfile.Name -ne 'Unidentified network' | Select-Object InterfaceAlias, IPv4Address, IPv4DefaultGateway
            DNSServers = (Get-DnsClientServerAddress | Where-Object AddressFamily -eq 2).ServerAddresses
        }
        SecuritySettings = @{
            DefenderStatus = Get-MpComputerStatus | Select-Object AntivirusEnabled, AntispywareEnabled, RealTimeProtectionEnabled, IoavProtectionEnabled, OnAccessProtectionEnabled, BehaviorMonitorEnabled
            DefenderPreferences = Get-MpPreference | Select-Object EnableTamperProtection, EnableControlledFolderAccess, EnableNetworkProtection
            BitLockerVolumes = Get-BitLockerVolume | Select-Object MountPoint, VolumeStatus, ProtectionStatus, EncryptionMethod
            FirewallProfiles = Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction
            WindowsUpdate = @{
                LastInstallTime = (Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1).InstalledOn
                PendingReboot = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
            }
        }
        UserAccounts = @{
            LocalUsers = Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordExpires, PasswordRequired
            LocalAdmins = Get-LocalGroupMember -Group 'Administrators' | Select-Object Name, ObjectClass, PrincipalSource
            CurrentUser = $env:USERNAME
        }
        Services = Get-Service | Where-Object Status -eq 'Running' | Where-Object StartType -ne 'Disabled' | Select-Object Name, Status, StartType, ServiceType
        InstalledSoftware = Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" | 
                           Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | 
                           Where-Object DisplayName -ne $null | Sort-Object DisplayName
    }
    
    $baselineFile = Join-Path (Get-LogFolder) "system-baseline.json"
    $baseline | ConvertTo-Json -Depth 6 | Out-File -FilePath $baselineFile -Encoding UTF8
    Write-SecLog "System baseline collected: $baselineFile"
}

function Export-ComplianceVerification {
    Write-Host "  - Collecting compliance verification data..."
    
    $compliance = @{
        Timestamp = Get-Date -Format 'o'
        Computer = $env:COMPUTERNAME
        
        # Access Control (AC) Verification
        AccessControl = @{
            UniqueUserIDs = (Get-LocalUser).Count
            AdminAccounts = (Get-LocalGroupMember -Group 'Administrators').Count
            DisabledAccounts = (Get-LocalUser | Where-Object Enabled -eq $false).Count
            AccountLockoutPolicy = @{
                LockoutThreshold = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\RemoteAccess\Policy" -Name "LockoutThreshold" -ErrorAction SilentlyContinue).LockoutThreshold
            }
            PasswordPolicy = @{
                MinPasswordLength = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\RemoteAccess\Policy" -Name "MinPasswordLen" -ErrorAction SilentlyContinue).MinPasswordLen
                MaxPasswordAge = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\RemoteAccess\Policy" -Name "MaxPasswordAge" -ErrorAction SilentlyContinue).MaxPasswordAge
            }
        }
        
        # Audit and Accountability (AU) Verification
        AuditAccountability = @{
            SecurityAuditing = @{
                LogonEvents = (Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} -MaxEvents 1 -ErrorAction SilentlyContinue) -ne $null
                LogoffEvents = (Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4634} -MaxEvents 1 -ErrorAction SilentlyContinue) -ne $null
                AccountLockouts = (Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4740} -MaxEvents 1 -ErrorAction SilentlyContinue) -ne $null
                PrivilegeUse = (Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4672} -MaxEvents 1 -ErrorAction SilentlyContinue) -ne $null
            }
            LogSettings = @{
                SecurityLogSize = (Get-WinEvent -ListLog Security).MaximumSizeInBytes
                SecurityLogRetention = (Get-WinEvent -ListLog Security).LogMode
                SystemLogSize = (Get-WinEvent -ListLog System).MaximumSizeInBytes
                ApplicationLogSize = (Get-WinEvent -ListLog Application).MaximumSizeInBytes
            }
            MonitoringTools = @{
                WazuhAgent = (Get-Service -Name 'WazuhSvc' -ErrorAction SilentlyContinue) -ne $null
                SysmonService = (Get-Service -Name 'Sysmon*' -ErrorAction SilentlyContinue) -ne $null
            }
        }
        
        # Configuration Management (CM) Verification
        ConfigurationManagement = @{
            WindowsUpdateConfig = @{
                AutoUpdateEnabled = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" -Name "AUOptions" -ErrorAction SilentlyContinue).AUOptions
                LastUpdateCheck = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Detect" -Name "LastSuccessTime" -ErrorAction SilentlyContinue).LastSuccessTime
            }
            ServicesConfig = @{
                UnnecessaryServices = Get-Service | Where-Object {$_.StartType -eq 'Automatic' -and $_.Status -eq 'Stopped'} | Measure-Object | Select-Object -ExpandProperty Count
                RunningServices = (Get-Service | Where-Object Status -eq 'Running').Count
            }
            RegistryBaseline = @{
                DefenderTamperProtection = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" -Name "TamperProtection" -ErrorAction SilentlyContinue
                UACEnabled = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -ErrorAction SilentlyContinue).EnableLUA
            }
        }
        
        # System Communications Protection (SC) Verification
        SystemCommunications = @{
            Encryption = @{
                BitLockerStatus = Get-BitLockerVolume | Select-Object MountPoint, VolumeStatus, ProtectionStatus
                TLSSettings = @{
                    TLS12Enabled = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Name "Enabled" -ErrorAction SilentlyContinue).Enabled
                    SSL3Disabled = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" -Name "Enabled" -ErrorAction SilentlyContinue).Enabled -eq 0
                }
            }
            NetworkSecurity = @{
                FirewallEnabled = (Get-NetFirewallProfile | Where-Object Enabled -eq $true).Count
                OutboundBlocked = (Get-NetFirewallProfile | Where-Object DefaultOutboundAction -eq 'Block').Count
                InboundRules = (Get-NetFirewallRule | Where-Object {$_.Direction -eq 'Inbound' -and $_.Enabled -eq $true}).Count
                OutboundRules = (Get-NetFirewallRule | Where-Object {$_.Direction -eq 'Outbound' -and $_.Enabled -eq $true}).Count
            }
        }
        
        # System and Information Integrity (SI) Verification
        SystemIntegrity = @{
            MalwareProtection = @{
                AntivirusEnabled = (Get-MpComputerStatus).AntivirusEnabled
                RealTimeProtection = (Get-MpComputerStatus).RealTimeProtectionEnabled
                DefinitionsUpToDate = (Get-MpComputerStatus).AntivirusSignatureAge -lt 7
                QuarantineItems = (Get-MpThreatDetection | Measure-Object).Count
            }
            ASRRules = @{
                EnabledRules = (Get-MpPreference).AttackSurfaceReductionRules_Ids.Count
                BlockMode = (Get-MpPreference).AttackSurfaceReductionRules_Actions -contains 1
            }
            ApplicationControl = @{
                SmartAppControl = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy" -ErrorAction SilentlyContinue
                WDACPolicy = Test-Path "$env:SystemRoot\System32\CodeIntegrity\SIPolicy.p7b"
            }
        }
        
        # Physical and Environmental Protection (PE) Data
        PhysicalEnvironmental = @{
            SystemInfo = @{
                LastBootTime = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
                SystemUptime = (Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
                PowerSettings = powercfg /query SCHEME_CURRENT SUB_SLEEP | Select-String "Standby\|Hibernate"
            }
            SecurityFeatures = @{
                SecureBoot = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State" -Name "UEFISecureBootEnabled" -ErrorAction SilentlyContinue
                TPMPresent = (Get-Tpm -ErrorAction SilentlyContinue).TpmPresent
                ScreenSaver = @{
                    Enabled = (Get-ItemProperty "HKCU:\Control Panel\Desktop" -Name "ScreenSaveActive" -ErrorAction SilentlyContinue).ScreenSaveActive
                    Timeout = (Get-ItemProperty "HKCU:\Control Panel\Desktop" -Name "ScreenSaveTimeOut" -ErrorAction SilentlyContinue).ScreenSaveTimeOut
                    Secure = (Get-ItemProperty "HKCU:\Control Panel\Desktop" -Name "ScreenSaverIsSecure" -ErrorAction SilentlyContinue).ScreenSaverIsSecure
                }
            }
        }
        
        # Risk Assessment (RA) Data Points
        RiskAssessment = @{
            ThreatIndicators = @{
                FailedLogons = (Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} -MaxEvents 50 -ErrorAction SilentlyContinue | Measure-Object).Count
                SecurityAlerts = (Get-WinEvent -FilterHashtable @{LogName='System'; Level=2} -MaxEvents 20 -ErrorAction SilentlyContinue | Measure-Object).Count
                UnexpectedProcesses = Get-Process | Where-Object {$_.ProcessName -notmatch '^(System|Idle|csrss|winlogon|services|lsass|svchost|explorer|dwm)$'} | Measure-Object | Select-Object -ExpandProperty Count
            }
            VulnerabilityIndicators = @{
                OutdatedSoftware = Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" | Where-Object {$_.InstallDate -lt (Get-Date).AddDays(-365).ToString("yyyyMMdd")} | Measure-Object | Select-Object -ExpandProperty Count
                MissingUpdates = (Get-HotFix | Where-Object InstalledOn -gt (Get-Date).AddDays(-30) | Measure-Object).Count
                OpenPorts = Get-NetTCPConnection | Where-Object State -eq 'Listen' | Select-Object LocalAddress, LocalPort, OwningProcess
            }
        }
    }
    
    $complianceFile = Join-Path (Get-LogFolder) "compliance-verification.json"
    $compliance | ConvertTo-Json -Depth 8 | Out-File -FilePath $complianceFile -Encoding UTF8
    Write-SecLog "Compliance verification data collected: $complianceFile"
}

function Export-SecurityEventData {
    Write-Host "  - Collecting security event data..."
    
    $events = @{
        Timestamp = Get-Date -Format 'o'
        Computer = $env:COMPUTERNAME
        
        # Recent Security Events
        SecurityEvents = @{
            LogonEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624,4625} -MaxEvents 100 -ErrorAction SilentlyContinue | 
                         Select-Object TimeCreated, Id, LevelDisplayName, @{Name='EventData';Expression={$_.Message}}
            
            PrivilegeEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4672,4673,4674} -MaxEvents 50 -ErrorAction SilentlyContinue | 
                             Select-Object TimeCreated, Id, LevelDisplayName, @{Name='EventData';Expression={$_.Message}}
            
            AccountEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4720,4722,4724,4726,4738,4740,4767} -MaxEvents 50 -ErrorAction SilentlyContinue | 
                           Select-Object TimeCreated, Id, LevelDisplayName, @{Name='EventData';Expression={$_.Message}}
            
            PolicyEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4719,4817,4902,4906} -MaxEvents 20 -ErrorAction SilentlyContinue | 
                          Select-Object TimeCreated, Id, LevelDisplayName, @{Name='EventData';Expression={$_.Message}}
        }
        
        # System Events
        SystemEvents = @{
            CriticalErrors = Get-WinEvent -FilterHashtable @{LogName='System'; Level=1,2} -MaxEvents 50 -ErrorAction SilentlyContinue | 
                           Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, @{Name='EventData';Expression={$_.Message}}
            
            ServiceEvents = Get-WinEvent -FilterHashtable @{LogName='System'; ID=7034,7035,7036,7040} -MaxEvents 30 -ErrorAction SilentlyContinue | 
                          Select-Object TimeCreated, Id, LevelDisplayName, @{Name='EventData';Expression={$_.Message}}
        }
        
        # Application Events
        ApplicationEvents = @{
            Errors = Get-WinEvent -FilterHashtable @{LogName='Application'; Level=1,2} -MaxEvents 30 -ErrorAction SilentlyContinue | 
                    Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, @{Name='EventData';Expression={$_.Message}}
        }
        
        # Defender Events
        DefenderEvents = @{
            ThreatDetections = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; ID=1116,1117} -MaxEvents 20 -ErrorAction SilentlyContinue | 
                             Select-Object TimeCreated, Id, LevelDisplayName, @{Name='EventData';Expression={$_.Message}}
            
            ASRBlocks = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; ID=1121,1122} -MaxEvents 20 -ErrorAction SilentlyContinue | 
                       Select-Object TimeCreated, Id, LevelDisplayName, @{Name='EventData';Expression={$_.Message}}
        }
        
        # Network Events
        NetworkEvents = @{
            FirewallBlocks = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=5157} -MaxEvents 30 -ErrorAction SilentlyContinue | 
                           Select-Object TimeCreated, Id, @{Name='EventData';Expression={$_.Message}}
        }
    }
    
    $eventsFile = Join-Path (Get-LogFolder) "security-events.json"
    $events | ConvertTo-Json -Depth 8 | Out-File -FilePath $eventsFile -Encoding UTF8
    Write-SecLog "Security event data collected: $eventsFile"
}

#===========================================================================
# SCRIPT EXECUTION
#===========================================================================

# --- INITIALIZATION ---
Clear-Host
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "==  MASTER WINDOWS HARDENING SCRIPT (v4)   ==" -ForegroundColor Cyan
Write-Host "==   (with Compliance Data Collection)     ==" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
# ... (The rest of the script from section 1 through 7 remains the same) ...

# --- DATA COLLECTION FOR COMPLIANCE VERIFICATION ---
Write-Host "`n[DATA] Collecting compliance verification data..." -ForegroundColor Magenta
try {
    Export-SystemBaseline
    Export-ComplianceVerification  
    Export-SecurityEventData
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
