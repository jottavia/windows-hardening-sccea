<#
.SYNOPSIS
    Collects extensive system, security, and event data for compliance verification and auditing.
.DESCRIPTION
    This script is designed to be run periodically after a system has been hardened. It gathers detailed
    information about the system's configuration and security state, saving it into a set of JSON files.
    This allows for ongoing monitoring and provides evidence for compliance audits without making any
    changes to the system. It requires administrative privileges to gather all necessary data.
.NOTES
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
    
    $baselineFile = Join-Path $script:logFolderPath "system-baseline.json"
    $baseline | ConvertTo-Json -Depth 6 | Out-File -FilePath $baselineFile -Encoding UTF8
    Write-CollectionLog "System baseline collected: $baselineFile"
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
    }
    
    $complianceFile = Join-Path $script:logFolderPath "compliance-verification.json"
    $compliance | ConvertTo-Json -Depth 8 | Out-File -FilePath $complianceFile -Encoding UTF8
    Write-CollectionLog "Compliance verification data collected: $complianceFile"
}

function Export-SecurityEventData {
    Write-Host "  - Collecting security event data..."
    
    $events = @{
        Timestamp = Get-Date -Format 'o'
        Computer = $env:COMPUTERNAME
        SecurityEvents = @{
            LogonEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624,4625} -MaxEvents 100 -ErrorAction SilentlyContinue | Select-Object TimeCreated, Id, LevelDisplayName, @{Name='EventData';Expression={$_.Message}}
            PrivilegeEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4672,4673,4674} -MaxEvents 50 -ErrorAction SilentlyContinue | Select-Object TimeCreated, Id, LevelDisplayName, @{Name='EventData';Expression={$_.Message}}
            AccountEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4720,4722,4724,4726,4738,4740,4767} -MaxEvents 50 -ErrorAction SilentlyContinue | Select-Object TimeCreated, Id, LevelDisplayName, @{Name='EventData';Expression={$_.Message}}
        }
        SystemEvents = @{
            CriticalErrors = Get-WinEvent -FilterHashtable @{LogName='System'; Level=1,2} -MaxEvents 50 -ErrorAction SilentlyContinue | Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, @{Name='EventData';Expression={$_.Message}}
            ServiceEvents = Get-WinEvent -FilterHashtable @{LogName='System'; ID=7034,7035,7036,7040} -MaxEvents 30 -ErrorAction SilentlyContinue | Select-Object TimeCreated, Id, LevelDisplayName, @{Name='EventData';Expression={$_.Message}}
        }
        ApplicationEvents = @{
            Errors = Get-WinEvent -FilterHashtable @{LogName='Application'; Level=1,2} -MaxEvents 30 -ErrorAction SilentlyContinue | Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, @{Name='EventData';Expression={$_.Message}}
        }
        DefenderEvents = @{
            ThreatDetections = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; ID=1116,1117} -MaxEvents 20 -ErrorAction SilentlyContinue | Select-Object TimeCreated, Id, LevelDisplayName, @{Name='EventData';Expression={$_.Message}}
            ASRBlocks = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; ID=1121,1122} -MaxEvents 20 -ErrorAction SilentlyContinue | Select-Object TimeCreated, Id, LevelDisplayName, @{Name='EventData';Expression={$_.Message}}
        }
    }
    
    $eventsFile = Join-Path $script:logFolderPath "security-events.json"
    $events | ConvertTo-Json -Depth 8 | Out-File -FilePath $eventsFile -Encoding UTF8
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

# Set a global scope variable for the log folder path so all functions can access it
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
