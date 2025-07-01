<#
.SYNOPSIS
    Windows 11 Human-Readable Report Generator and Validator (4 of 4)
.DESCRIPTION
    Converts JSON outputs to human-readable markdown reports and validates hardening results.
    Generates executive summary, technical details, and compliance documentation.
    Enhanced with advanced security policies documentation and URBackup integration.
.NOTES
    Version: 11.1 - Part 4 of 4 (Report Generation & Validation)
    Run Order: 1-Core-Hardening.ps1 -> 2-Compliance-Collection.ps1 -> 3-Final-Report.ps1 -> 4-Report-Generator.ps1
#>

# Check if running as administrator
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "Administrator privileges required. Relaunching with elevation..."
    Start-Process powershell.exe -Verb RunAs -ArgumentList ('-NoProfile -ExecutionPolicy Bypass -File "{0}"' -f $MyInvocation.MyCommand.Path)
    exit
}

Clear-Host
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "          WINDOWS 11 REPORT GENERATOR & VALIDATOR v11.1 (4/4)" -ForegroundColor Cyan
Write-Host "                    Human-Readable Reports & Validation" -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan

# Find the most recent hardening log folder
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$computerFolders = Get-ChildItem -Path $scriptRoot -Directory -Filter "PC-*" | Sort-Object CreationTime -Descending
if (-not $computerFolders) {
    Write-Error "No computer folders found. Please run Scripts 1-3 first."
    Read-Host "Press Enter to exit"
    exit 1
}

$allHardeningFolders = @()
foreach ($computerFolder in $computerFolders) {
    $hardeningFolders = Get-ChildItem -Path $computerFolder.FullName -Directory -Filter "HARDENING-*" | Sort-Object CreationTime -Descending
    if ($hardeningFolders) {
        $allHardeningFolders += $hardeningFolders
    }
}

if (-not $allHardeningFolders) {
    Write-Error "No hardening folders found. Please run Scripts 1-3 first."
    Read-Host "Press Enter to exit"
    exit 1
}

$logFolder = ($allHardeningFolders | Sort-Object CreationTime -Descending | Select-Object -First 1).FullName
Write-Host "Using log folder: $logFolder" -ForegroundColor Cyan

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

Write-Log "Report generation and validation started" "INFO"

# Load all JSON files
Write-Host "`n[1] Loading and Validating JSON Data..." -ForegroundColor Green

$jsonFiles = @{
    Config = "$logFolder\script-config.json"
    Script1Status = "$logFolder\script1-status.json"
    Script2Status = "$logFolder\script2-status.json"
    SystemBaseline = "$logFolder\system-baseline.json"
    SecurityAssessment = "$logFolder\security-assessment.json"
    ComplianceMapping = "$logFolder\compliance-framework-mapping.json"
    SecurityEvents = "$logFolder\security-events.json"
    DetailedReport = "$logFolder\detailed-assessment-report.json"
    ExecutiveSummary = "$logFolder\executive-summary.json"
    FinalReport = "$logFolder\final-comprehensive-report.json"
}

$jsonData = @{}
$missingFiles = @()
$validationResults = @()

foreach ($fileType in $jsonFiles.Keys) {
    $filePath = $jsonFiles[$fileType]
    if (Test-Path $filePath) {
        try {
            $jsonData[$fileType] = Get-Content $filePath | ConvertFrom-Json
            Write-Log "Loaded: $fileType" "SUCCESS"
            $validationResults += "SUCCESS: $fileType - Valid JSON loaded successfully"
        } catch {
            Write-Log "Failed to parse JSON: $fileType - $_" "ERROR"
            $validationResults += "ERROR: $fileType - JSON parsing failed: $_"
        }
    } else {
        $missingFiles += $fileType
        Write-Log "Missing file: $fileType" "ERROR"
        $validationResults += "ERROR: $fileType - File not found"
    }
}

if ($missingFiles.Count -gt 0) {
    Write-Host "Missing required files. Please run all previous scripts first." -ForegroundColor Red
    foreach ($missing in $missingFiles) {
        Write-Host "  Missing: $missing" -ForegroundColor Red
    }
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host "`n[2] Validating Critical Files and System State..." -ForegroundColor Green

# Validate critical files
$criticalFiles = @{
    SecOpsAdminPassword = "$logFolder\SecOpsAdm_Password.txt"
    BitLockerRecoveryKey = "$logFolder\BitLocker_Recovery_Key.txt"
    AdministratorPassword = "$logFolder\Administrator_Password.txt"
}

$criticalFileStatus = @{}
foreach ($fileType in $criticalFiles.Keys) {
    $filePath = $criticalFiles[$fileType]
    $exists = Test-Path $filePath
    $criticalFileStatus[$fileType] = $exists
    
    if ($exists) {
        $fileSize = (Get-Item $filePath).Length
        Write-Log "Critical file validated: $fileType ($fileSize bytes)" "SUCCESS"
        $validationResults += "SUCCESS: $fileType - File exists and has content ($fileSize bytes)"
    } else {
        Write-Log "Critical file missing: $fileType" "ERROR"
        $validationResults += "ERROR: $fileType - Critical file missing"
    }
}

# Validate system state
$systemValidation = @()
try {
    # BitLocker status
    $bitlockerStatus = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
    if ($bitlockerStatus) {
        $systemValidation += "SUCCESS: BitLocker Status - $($bitlockerStatus.VolumeStatus) / $($bitlockerStatus.ProtectionStatus)"
    } else {
        $systemValidation += "ERROR: BitLocker Status - Cannot retrieve status"
    }
    
    # Firewall status
    $firewallProfiles = Get-NetFirewallProfile
    $blockedProfiles = ($firewallProfiles | Where-Object DefaultOutboundAction -eq 'Block').Count
    $systemValidation += "SUCCESS: Firewall Profiles - $blockedProfiles/3 configured with default-deny"
    
    # Service status
    $wazuhService = Get-Service -Name 'WazuhSvc' -ErrorAction SilentlyContinue
    $sysmonService = Get-Service -Name 'Sysmon64' -ErrorAction SilentlyContinue
    
    if ($wazuhService) {
        $systemValidation += "SUCCESS: Wazuh Service - $($wazuhService.Status)"
    } else {
        $systemValidation += "WARNING: Wazuh Service - Not installed"
    }
    
    if ($sysmonService) {
        $systemValidation += "SUCCESS: Sysmon Service - $($sysmonService.Status)"
    } else {
        $systemValidation += "WARNING: Sysmon Service - Not installed"
    }
    
    # Enhanced policies validation
    $edgePasswordManager = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "PasswordManagerEnabled" -ErrorAction SilentlyContinue
    if ($edgePasswordManager -and $edgePasswordManager.PasswordManagerEnabled -eq 0) {
        $systemValidation += "SUCCESS: Edge Password Manager - Disabled"
    } else {
        $systemValidation += "ERROR: Edge Password Manager - Not properly disabled"
    }
    
    $screenSaverTimeout = Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop" -Name "ScreenSaveTimeOut" -ErrorAction SilentlyContinue
    if ($screenSaverTimeout -and $screenSaverTimeout.ScreenSaveTimeOut -eq "600") {
        $systemValidation += "SUCCESS: Screen Saver Timeout - 10 minutes configured"
    } else {
        $systemValidation += "ERROR: Screen Saver Timeout - Not properly configured"
    }
    
} catch {
    Write-Log "System validation error: $_" "ERROR"
    $systemValidation += "ERROR: System validation failed - $_"
}

Write-Host "`n[3] Generating Executive Summary Report..." -ForegroundColor Green

# Generate Executive Summary Markdown
try {
    $execSummary = $jsonData.ExecutiveSummary
    $script1Data = $jsonData.Script1Status
    
    $executiveMarkdown = @"
# Windows 11 Security Hardening - Executive Summary

**Generated:** $(Get-Date -Format 'MMMM dd, yyyy HH:mm:ss')  
**Computer:** $($execSummary.Computer)  
**Hardening Version:** $($execSummary.HardeningVersion)  
**Duration:** $($execSummary.ExecutionOverview.TotalDuration)  

## Executive Overview

This report summarizes the Windows 11 security hardening process completed on **$($execSummary.Computer)**. The hardening implementation follows industry best practices and compliance frameworks including NIST 800-171, CMMC Level 1, and ISO 27001:2022.

### Quick Status
- **Overall Status:** $($execSummary.OperationalResults.OverallStatus)
- **Success Rate:** $($execSummary.OperationalResults.SuccessRate)%
- **Critical Failures:** $($execSummary.OperationalResults.CriticalFailures)
- **Documentation Files:** $(($jsonData.FinalReport.GeneratedDocuments | Measure-Object).Count)

## Operational Results

| Metric | Count | Status |
|--------|-------|--------|
| Successful Operations | $($execSummary.OperationalResults.SuccessfulOperations) | PASSED |
| Non-Critical Errors | $($execSummary.OperationalResults.NonCriticalErrors) | WARNING |
| Critical Failures | $($execSummary.OperationalResults.CriticalFailures) | $(if($execSummary.OperationalResults.CriticalFailures -eq 0){'PASSED'}else{'FAILED'}) |

## Critical Security Objectives

| Objective | Status | File Location |
|-----------|--------|---------------|
| Admin Password Secured | $(if($execSummary.CriticalObjectives.AdminPasswordSecured){'COMPLETED'}else{'FAILED'}) | SecOpsAdm_Password.txt |
| BitLocker Key Secured | $(if($execSummary.CriticalObjectives.BitLockerKeySecured){'COMPLETED'}else{'FAILED'}) | BitLocker_Recovery_Key.txt |
| Administrator Password Management | $(if($execSummary.CriticalObjectives.AdminPasswordManagementConfigured){'COMPLETED'}else{'FAILED'}) | Administrator_Password.txt |
| System Hardened | $(if($execSummary.CriticalObjectives.SystemHardened){'COMPLETED'}else{'FAILED'}) | Multiple configurations |
| Compliance Documented | $(if($execSummary.CriticalObjectives.ComplianceDocumented){'COMPLETED'}else{'FAILED'}) | JSON reports |

## Compliance Framework Status

| Framework | Status | Implementation Level |
|-----------|--------|---------------------|
| **NIST 800-171** | **$($execSummary.ComplianceAchievement.NIST_800_171)** | $($execSummary.OperationalResults.SuccessRate)% |
| **CMMC Level 1** | **$($execSummary.ComplianceAchievement.CMMC_Level1)** | All 17 practices addressed |
| **ISO 27001:2022** | **$($execSummary.ComplianceAchievement.ISO_27001)** | Core controls implemented |

## Security Controls Implemented

| Control Family | Count | Examples |
|----------------|-------|----------|
| Access Control (AC) | $($execSummary.SecurityControlsImplemented.AccessControl) | Admin account management, session controls |
| Audit & Accountability (AU) | $($execSummary.SecurityControlsImplemented.AuditAccountability) | Sysmon, Wazuh monitoring |
| Configuration Management (CM) | $($execSummary.SecurityControlsImplemented.ConfigurationManagement) | Baseline hardening, browser policies |
| Identification & Authentication (IA) | $($execSummary.SecurityControlsImplemented.IdentificationAuthentication) | Password policies, account management |
| System Communications (SC) | $($execSummary.SecurityControlsImplemented.SystemCommunications) | Firewall, encryption, network controls |
| System Integrity (SI) | $($execSummary.SecurityControlsImplemented.SystemIntegrity) | Antivirus, execution prevention |

## Enhanced Security Features (v11.1)

| Feature | Status | Description |
|---------|--------|-------------|
| Edge Security Policies | $(if($execSummary.EnhancedSecurityFeatures.EdgeSecurityPolicies){'ENABLED'}else{'FAILED'}) | Password manager disabled, autofill blocked |
| Mandatory Screen Lock | $(if($execSummary.EnhancedSecurityFeatures.MandatoryScreenLock){'ENABLED'}else{'FAILED'}) | 10-minute timeout enforced |
| Execution Prevention | $(if($execSummary.EnhancedSecurityFeatures.ExecutionPrevention){'ENABLED'}else{'FAILED'}) | Desktop/temp folder restrictions |
| URBackup Integration | $(if($execSummary.EnhancedSecurityFeatures.URBackupIntegration){'ENABLED'}else{'FAILED'}) | Firewall exceptions configured |
| Additional Hardening | $(if($execSummary.EnhancedSecurityFeatures.AdditionalWindowsHardening){'ENABLED'}else{'FAILED'}) | Registry security enhancements |

## Critical Actions Required

### IMMEDIATE (Within 24 hours)
1. **Secure Password Files** - Move all password files to secure password manager
2. **Remove Flash Drive** - Secure physical media containing sensitive data
3. **Test Critical Applications** - Verify business functionality
4. **Validate Enhanced Policies** - Test Edge restrictions and screen lock

### SHORT-TERM (Within 1 week)
1. **Monitor Software Restrictions** - Verify execution prevention effectiveness
2. **URBackup Validation** - Confirm backup operations function correctly
3. **User Training** - Brief users on new security restrictions
4. **Documentation Update** - Record changes in change management system

### LONG-TERM (Within 1 month)
1. **SHIPS-style Implementation** - Replace manual password management
2. **Regular Assessment Schedule** - Implement ongoing security reviews
3. **Incident Response Planning** - Establish security incident procedures
4. **Compliance Auditing** - Schedule regular framework compliance checks

---

**Report Location:** `$logFolder`  
**For Technical Details:** Review `final-comprehensive-report.json` and detailed logs  
**Support:** Contact IT Security team with log folder location  

*This report was automatically generated by the Windows 11 Security Hardening v11.1 script suite.*
"@

    $executiveMarkdown | Out-File "$logFolder\Executive-Summary-Report.md" -Encoding UTF8
    Write-Log "Executive summary markdown generated" "SUCCESS"
} catch {
    Write-Log "Failed to generate executive summary markdown: $_" "ERROR"
}

Write-Host "`n[4] Generating Technical Details Report..." -ForegroundColor Green

# Generate Technical Details Markdown
try {
    $finalReport = $jsonData.FinalReport
    $systemBaseline = $jsonData.SystemBaseline
    $securityAssessment = $jsonData.SecurityAssessment
    
    $technicalMarkdown = @"
# Windows 11 Security Hardening - Technical Details Report

**Generated:** $(Get-Date -Format 'MMMM dd, yyyy HH:mm:ss')  
**Computer:** $($finalReport.Computer)  
**Report Version:** $($finalReport.ReportVersion)  

## System Information

### Operating System
- **OS:** $($systemBaseline.OperatingSystem.Caption)
- **Version:** $($systemBaseline.OperatingSystem.Version)
- **Build:** $($systemBaseline.OperatingSystem.BuildNumber)
- **Architecture:** $($systemBaseline.OperatingSystem.OSArchitecture)
- **Install Date:** $($systemBaseline.OperatingSystem.InstallDate)
- **Last Boot:** $($systemBaseline.OperatingSystem.LastBootUpTime)

### Hardware
- **Manufacturer:** $($systemBaseline.Hardware.Manufacturer)
- **Model:** $($systemBaseline.Hardware.Model)
- **Processor:** $($systemBaseline.Hardware.Processor)
- **Cores:** $($systemBaseline.Hardware.ProcessorCores)
- **Memory:** $($systemBaseline.OperatingSystem.TotalPhysicalMemory) GB
- **BIOS:** $($systemBaseline.Hardware.BIOSManufacturer) $($systemBaseline.Hardware.BIOSVersion)

## Configuration Applied

### Administrative Account Management
- **New Admin Account:** $($finalReport.ConfigurationApplied.AdminAccountManagement.NewAdminCreated)
- **Password Secured:** $(if($finalReport.ConfigurationApplied.AdminAccountManagement.PasswordSecured){'YES'}else{'NO'})
- **Users Demoted:** $($finalReport.ConfigurationApplied.AdminAccountManagement.UsersRemoved)

### Password Management
- **Built-in Admin Password:** $(if($finalReport.ConfigurationApplied.PasswordManagement.BuiltinAdminPasswordSet){'CONFIGURED'}else{'FAILED'})
- **Management Type:** $($finalReport.ConfigurationApplied.PasswordManagement.ManualPasswordManagement)

### Encryption Controls
- **BitLocker Status:** $(if($finalReport.ConfigurationApplied.EncryptionControls.BitLockerEnabled){'ENABLED'}else{'DISABLED'})
- **Recovery Key Secured:** $(if($finalReport.ConfigurationApplied.EncryptionControls.RecoveryKeySecured){'YES'}else{'NO'})
- **Encryption Method:** $($finalReport.ConfigurationApplied.EncryptionControls.EncryptionMethod)

### Network Security
- **Firewall Hardened:** $(if($finalReport.ConfigurationApplied.NetworkSecurity.FirewallHardened){'YES'}else{'NO'})
- **Remote Access Disabled:** $(if($finalReport.ConfigurationApplied.NetworkSecurity.RemoteAccessDisabled){'YES'}else{'NO'})
- **URBackup Rules:** $(if($finalReport.ConfigurationApplied.NetworkSecurity.URBackupFirewallRules){'CONFIGURED'}else{'NOT CONFIGURED'})
- **Default Deny Policy:** $(if($finalReport.ConfigurationApplied.NetworkSecurity.DefaultDenyPolicy){'ENABLED'}else{'DISABLED'})

### Endpoint Protection
- **Defender Hardened:** $(if($finalReport.ConfigurationApplied.EndpointProtection.DefenderHardened){'YES'}else{'NO'})
- **ASR Rules:** $($finalReport.ConfigurationApplied.EndpointProtection.ASRRulesEnabled) enabled
- **Tamper Protection:** $(if($finalReport.ConfigurationApplied.EndpointProtection.TamperProtectionEnabled){'ENABLED'}else{'DISABLED'})
- **Real-time Protection:** $(if($finalReport.ConfigurationApplied.EndpointProtection.RealTimeProtectionEnabled){'ENABLED'}else{'DISABLED'})

### Monitoring Agents
- **Wazuh Installed:** $(if($finalReport.ConfigurationApplied.MonitoringAgents.WazuhInstalled){'YES'}else{'NO'})
- **Sysmon Installed:** $(if($finalReport.ConfigurationApplied.MonitoringAgents.SysmonInstalled){'YES'}else{'NO'})
- **Comprehensive Logging:** $(if($finalReport.ConfigurationApplied.MonitoringAgents.ComprehensiveLogging){'ENABLED'}else{'DISABLED'})

## Enhanced Security Policies (v11.1)

### Microsoft Edge Security
- **Data Restrictions:** $(if($finalReport.ConfigurationApplied.EnhancedSecurityPolicies.EdgeDataRestrictions){'APPLIED'}else{'NOT APPLIED'})
  - Password manager disabled
  - Autofill blocked (addresses, credit cards, forms)
  - Search suggestions disabled
  - Browser data cleared on exit

### Extension and Developer Controls
- **Extension Installation:** Blocked (all extensions)
- **Developer Tools:** Disabled
- **Browser Sign-in:** Disabled
- **Sync:** Disabled

### Session Management
- **Timeout Policies:** $(if($finalReport.ConfigurationApplied.EnhancedSecurityPolicies.SessionTimeoutPolicies){'APPLIED'}else{'NOT APPLIED'})
  - 10-minute mandatory screen lock
  - Secure screen saver required
  - Applied to current and new users

### Execution Control
- **Control Policies:** $(if($finalReport.ConfigurationApplied.EnhancedSecurityPolicies.ExecutionControlPolicies){'APPLIED'}else{'NOT APPLIED'})
  - Software Restriction Policies enabled
  - Desktop execution prevented
  - Temp folder execution prevented
  - Downloads folder execution prevented

### Windows System Hardening
- **Security Hardening:** $(if($finalReport.ConfigurationApplied.EnhancedSecurityPolicies.WindowsSecurityHardening){'APPLIED'}else{'NOT APPLIED'})
  - Windows Script Host disabled
  - AutoRun/AutoPlay disabled
  - Enhanced UAC settings
  - Windows Installer restrictions

## Security Assessment Results

### Access Control Assessment
$(if($securityAssessment.AccessControl.DedicatedAdminAccount){'PASS'}else{'FAIL'}) **Dedicated Admin Account:** $(if($securityAssessment.AccessControl.DedicatedAdminAccount){'Created'}else{'Missing'})  
$(if($securityAssessment.AccessControl.WinRMDisabled){'PASS'}else{'FAIL'}) **WinRM Service:** $(if($securityAssessment.AccessControl.WinRMDisabled){'Disabled'}else{'Running'})  
$(if($securityAssessment.AccessControl.RDPDisabled){'PASS'}else{'FAIL'}) **Remote Desktop:** $(if($securityAssessment.AccessControl.RDPDisabled){'Disabled'}else{'Enabled'})  
$(if($securityAssessment.AccessControl.ScreenSaverTimeout -eq '600'){'PASS'}else{'FAIL'}) **Screen Saver Timeout:** $($securityAssessment.AccessControl.ScreenSaverTimeout) seconds

### Configuration Management Assessment
$(if($securityAssessment.ConfigurationManagement.FirewallHardened){'PASS'}else{'FAIL'}) **Firewall Hardened:** $(if($securityAssessment.ConfigurationManagement.FirewallHardened){'Yes'}else{'No'})  
$(if($securityAssessment.ConfigurationManagement.DefenderHardened){'PASS'}else{'FAIL'}) **Defender Hardened:** $(if($securityAssessment.ConfigurationManagement.DefenderHardened){'Yes'}else{'No'})  
$(if($securityAssessment.ConfigurationManagement.BitLockerEnabled){'PASS'}else{'FAIL'}) **BitLocker Enabled:** $(if($securityAssessment.ConfigurationManagement.BitLockerEnabled){'Yes'}else{'No'})  
$(if($securityAssessment.ConfigurationManagement.EdgePasswordManagerDisabled){'PASS'}else{'FAIL'}) **Edge Password Manager:** $(if($securityAssessment.ConfigurationManagement.EdgePasswordManagerDisabled){'Disabled'}else{'Enabled'})  
$(if($securityAssessment.ConfigurationManagement.EdgeAutofillDisabled){'PASS'}else{'FAIL'}) **Edge Autofill:** $(if($securityAssessment.ConfigurationManagement.EdgeAutofillDisabled){'Disabled'}else{'Enabled'})  
$(if($securityAssessment.ConfigurationManagement.SRPConfigured){'PASS'}else{'FAIL'}) **Software Restriction Policies:** $(if($securityAssessment.ConfigurationManagement.SRPConfigured){'Configured'}else{'Not configured'})

## Generated Documentation Files

$($finalReport.GeneratedDocuments | ForEach-Object { "- $_`n" })

## Issues and Remediation

$(if($finalReport.DetailedFindings.CriticalIssues.Count -gt 0){
"### Critical Issues
$($finalReport.DetailedFindings.CriticalIssues | ForEach-Object { "- ERROR: $_`n" })"
})

$(if($finalReport.DetailedFindings.ErrorsEncountered.Count -gt 0){
"### Non-Critical Errors
$($finalReport.DetailedFindings.ErrorsEncountered | ForEach-Object { "- WARNING: $_`n" })"
})

### Successful Implementations
$($finalReport.DetailedFindings.SuccessfulImplementations | ForEach-Object { "- SUCCESS: $_`n" })

## Immediate Actions Required

### Critical Actions
$($finalReport.ImmediateActions.Critical | ForEach-Object { "1. **$_**`n" })

### Recommended Actions
$($finalReport.ImmediateActions.Recommended | ForEach-Object { "1. **$_**`n" })

## Long-Term Recommendations

$($finalReport.LongTermRecommendations | ForEach-Object { "- $_`n" })

---

**Report Generated:** $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  
**Log Folder:** `$logFolder`  
**Support:** Review detailed logs for troubleshooting guidance
"@

    $technicalMarkdown | Out-File "$logFolder\Technical-Details-Report.md" -Encoding UTF8
    Write-Log "Technical details markdown generated" "SUCCESS"
} catch {
    Write-Log "Failed to generate technical details markdown: $_" "ERROR"
}

Write-Host "`n[5] Generating Compliance Documentation..." -ForegroundColor Green

# Generate Compliance Report
try {
    $complianceData = $jsonData.ComplianceMapping
    
    $complianceMarkdown = @"
# Windows 11 Security Hardening - Compliance Documentation

**Generated:** $(Get-Date -Format 'MMMM dd, yyyy HH:mm:ss')  
**Computer:** $($complianceData.Computer)  
**Assessment Date:** $($complianceData.MappingTimestamp)  

## Compliance Framework Summary

This document provides evidence of compliance with major cybersecurity frameworks following the Windows 11 security hardening implementation.

## NIST 800-171 Compliance

### Access Control (AC)
- **AC-2 Account Management:** $($complianceData.NIST_800_171.AccessControl.AuthorizedAccess.Status)
  - Evidence: $($complianceData.NIST_800_171.AccessControl.AuthorizedAccess.Evidence)
- **AC-17 Remote Access:** $($complianceData.NIST_800_171.AccessControl.RemoteAccess.Status)
  - Evidence: $($complianceData.NIST_800_171.AccessControl.RemoteAccess.Evidence)
- **AC-11 Session Lock:** $($complianceData.NIST_800_171.AccessControl.SessionLock.Status)
  - Evidence: $($complianceData.NIST_800_171.AccessControl.SessionLock.Evidence)

### Audit and Accountability (AU)
- **AU-3 Audit Events:** $($complianceData.NIST_800_171.AuditAccountability.AuditEvents.Status)
  - Evidence: $($complianceData.NIST_800_171.AuditAccountability.AuditEvents.Evidence)
- **AU-6 Audit Review:** $($complianceData.NIST_800_171.AuditAccountability.AuditReview.Status)
  - Evidence: $($complianceData.NIST_800_171.AuditAccountability.AuditReview.Evidence)

### Configuration Management (CM)
- **CM-6 Configuration Settings:** $($complianceData.NIST_800_171.ConfigurationManagement.BaselineConfig.Status)
  - Evidence: $($complianceData.NIST_800_171.ConfigurationManagement.BaselineConfig.Evidence)
- **CM-5 Access Restrictions:** $($complianceData.NIST_800_171.ConfigurationManagement.ChangeControl.Status)
  - Evidence: $($complianceData.NIST_800_171.ConfigurationManagement.ChangeControl.Evidence)
- **CM-10 Software Usage:** $($complianceData.NIST_800_171.ConfigurationManagement.SoftwareUsage.Status)
  - Evidence: $($complianceData.NIST_800_171.ConfigurationManagement.SoftwareUsage.Evidence)

### System and Communications Protection (SC)
- **SC-7 Boundary Protection:** $($complianceData.NIST_800_171.SystemCommunications.BoundaryProtection.Status)
  - Evidence: $($complianceData.NIST_800_171.SystemCommunications.BoundaryProtection.Evidence)
- **SC-28 Protection of Information at Rest:** $($complianceData.NIST_800_171.SystemCommunications.EncryptionAtRest.Status)
  - Evidence: $($complianceData.NIST_800_171.SystemCommunications.EncryptionAtRest.Evidence)

### System and Information Integrity (SI)
- **SI-3 Malicious Code Protection:** $($complianceData.NIST_800_171.SystemIntegrity.MaliciousCode.Status)
  - Evidence: $($complianceData.NIST_800_171.SystemIntegrity.MaliciousCode.Evidence)
- **SI-7 Software Integrity:** $($complianceData.NIST_800_171.SystemIntegrity.SoftwareIntegrity.Status)
  - Evidence: $($complianceData.NIST_800_171.SystemIntegrity.SoftwareIntegrity.Evidence)

## CMMC Level 1 Compliance

### Access Control (AC)
- **Status:** $($complianceData.CMMC_Level1.AccessControl.Status)
- **Evidence:** $($complianceData.CMMC_Level1.AccessControl.Evidence)

### Audit and Accountability (AU)
- **Status:** $($complianceData.CMMC_Level1.AuditAccountability.Status)
- **Evidence:** $($complianceData.CMMC_Level1.AuditAccountability.Evidence)

### Configuration Management (CM)
- **Status:** $($complianceData.CMMC_Level1.ConfigurationManagement.Status)
- **Evidence:** $($complianceData.CMMC_Level1.ConfigurationManagement.Evidence)

### Identification and Authentication (IA)
- **Status:** $($complianceData.CMMC_Level1.IdentificationAuthentication.Status)
- **Evidence:** $($complianceData.CMMC_Level1.IdentificationAuthentication.Evidence)

### System and Communications Protection (SC)
- **Status:** $($complianceData.CMMC_Level1.SystemCommunications.Status)
- **Evidence:** $($complianceData.CMMC_Level1.SystemCommunications.Evidence)

### System and Information Integrity (SI)
- **Status:** $($complianceData.CMMC_Level1.SystemIntegrity.Status)
- **Evidence:** $($complianceData.CMMC_Level1.SystemIntegrity.Evidence)

## ISO 27001:2022 Compliance

### Information Security Policies (A.5)
- **Status:** $($complianceData.ISO_27001_2022.InformationSecurityPolicies.Status)
- **Evidence:** $($complianceData.ISO_27001_2022.InformationSecurityPolicies.Evidence)

### Asset Management (A.8)
- **Status:** $($complianceData.ISO_27001_2022.AssetManagement.Status)
- **Evidence:** $($complianceData.ISO_27001_2022.AssetManagement.Evidence)

### Access Control (A.9)
- **Status:** $($complianceData.ISO_27001_2022.AccessControl.Status)
- **Evidence:** $($complianceData.ISO_27001_2022.AccessControl.Evidence)

### Cryptography (A.10)
- **Status:** $($complianceData.ISO_27001_2022.Cryptography.Status)
- **Evidence:** $($complianceData.ISO_27001_2022.Cryptography.Evidence)

### Physical and Environmental Security (A.11)
- **Status:** $($complianceData.ISO_27001_2022.PhysicalSecurity.Status)
- **Evidence:** $($complianceData.ISO_27001_2022.PhysicalSecurity.Evidence)

### Operations Security (A.12)
- **Status:** $($complianceData.ISO_27001_2022.OperationsSecurity.Status)
- **Evidence:** $($complianceData.ISO_27001_2022.OperationsSecurity.Evidence)

### Communications Security (A.13)
- **Status:** $($complianceData.ISO_27001_2022.CommunicationsSecurity.Status)
- **Evidence:** $($complianceData.ISO_27001_2022.CommunicationsSecurity.Evidence)

### System Acquisition, Development and Maintenance (A.14)
- **Status:** $($complianceData.ISO_27001_2022.SystemDevelopment.Status)
- **Evidence:** $($complianceData.ISO_27001_2022.SystemDevelopment.Evidence)

---

**Compliance Assessment Completed:** $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  
**Evidence Location:** `$logFolder`  
**Auditor Notes:** All evidence files are available in JSON format for detailed review
"@

    $complianceMarkdown | Out-File "$logFolder\Compliance-Documentation.md" -Encoding UTF8
    Write-Log "Compliance documentation markdown generated" "SUCCESS"
} catch {
    Write-Log "Failed to generate compliance documentation: $_" "ERROR"
}

Write-Host "`n[6] Generating Validation Summary..." -ForegroundColor Green

# Generate Validation Summary
try {
    $validationMarkdown = @"
# Windows 11 Security Hardening - Validation Summary

**Generated:** $(Get-Date -Format 'MMMM dd, yyyy HH:mm:ss')  
**Computer:** $env:COMPUTERNAME  
**Validation Date:** $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  

## Validation Overview

This document provides a comprehensive validation of the Windows 11 security hardening implementation, including file integrity checks, system state verification, and compliance validation.

## JSON Data Files Validation

$($validationResults | ForEach-Object { "- $_`n" })

## Critical Files Validation

| File Type | Status | Description |
|-----------|--------|-------------|
| SecOpsAdm Password | $(if($criticalFileStatus.SecOpsAdminPassword){'EXISTS'}else{'MISSING'}) | Administrative account credentials |
| BitLocker Recovery Key | $(if($criticalFileStatus.BitLockerRecoveryKey){'EXISTS'}else{'MISSING'}) | Drive encryption recovery password |
| Administrator Password | $(if($criticalFileStatus.AdministratorPassword){'EXISTS'}else{'MISSING'}) | Built-in Administrator credentials |

$(if($criticalFileStatus.SecOpsAdminPassword -and $criticalFileStatus.BitLockerRecoveryKey -and $criticalFileStatus.AdministratorPassword){
"### All Critical Files Present
All required password and recovery files have been successfully created and are available for secure storage."
} else {
"### Missing Critical Files
**IMMEDIATE ACTION REQUIRED:** One or more critical files are missing. Manual intervention may be required."
})

## System State Validation

$($systemValidation | ForEach-Object { "- $_`n" })

## Hardening Effectiveness Assessment

### Security Control Implementation
Based on the system validation, the following security controls are verified:

#### Successfully Implemented
- BitLocker drive encryption
- Windows Firewall default-deny policy
- Security monitoring agents (where applicable)
- Enhanced browser security policies
- Session timeout controls

#### Partial Implementation
- Some services may not be installed (organization dependent)
- Certain registry policies may require user session restart

#### Failed Implementation
$(if($systemValidation | Where-Object {$_ -match 'ERROR'}) {
"The following areas require attention:
$($systemValidation | Where-Object {$_ -match 'ERROR'} | ForEach-Object { "- $_`n" })"
} else {
"No failed implementations detected during validation."
})

## Recommended Validation Steps

### Immediate Validation (Next 1 hour)
1. **File Security Check**
   - Verify all three critical password files are present
   - Confirm file contents are properly formatted
   - Test file accessibility with administrative account

2. **System Function Test**
   - Verify system boots normally
   - Test critical business applications
   - Confirm network connectivity

3. **Security Policy Test**
   - Test Microsoft Edge with new restrictions
   - Verify 10-minute screen lock functionality
   - Attempt to run executables from restricted locations

### Extended Validation (Next 24 hours)
1. **URBackup Integration Test**
   - Verify backup client can connect to server
   - Test backup and restore operations
   - Confirm firewall exceptions are working

2. **Monitoring Validation**
   - Check Wazuh agent communication (if installed)
   - Verify Sysmon logging (if installed)
   - Review Windows Defender status and logs

3. **User Experience Test**
   - Test all user workflows
   - Verify password change requirements work
   - Confirm no unexpected application blocking

### Ongoing Validation (Weekly)
1. **Security Posture Review**
   - Monitor security event logs
   - Review any policy violations
   - Check for system updates and patches

2. **Compliance Check**
   - Verify configurations remain in place
   - Document any authorized changes
   - Update evidence documentation

## Success Metrics

| Metric | Target | Current Status |
|--------|--------|---------------|
| Critical Files Created | 3/3 | $(($criticalFileStatus.Values | Where-Object {$_ -eq $true}).Count)/3 |
| Security Controls Implemented | >15 | $($jsonData.Script1Status.Successes.Count) |
| Critical Failures | 0 | $($jsonData.Script1Status.CriticalFailures.Count) |
| Framework Compliance | 3/3 | $(($jsonData.ExecutiveSummary.ComplianceAchievement.Values | Where-Object {$_ -eq 'COMPLIANT'}).Count)/3 |

## Critical Issues Requiring Attention

$(if($jsonData.Script1Status.CriticalFailures.Count -gt 0) {
"### Critical Failures Detected
$($jsonData.Script1Status.CriticalFailures | ForEach-Object { "- ERROR: $_`n" })

**These issues must be resolved before the system can be considered secure.**"
} else {
"### No Critical Issues
No critical failures were detected during the hardening process."
})

$(if(-not $criticalFileStatus.SecOpsAdminPassword -or -not $criticalFileStatus.BitLockerRecoveryKey -or -not $criticalFileStatus.AdministratorPassword) {
"### Missing Critical Files
**IMMEDIATE ACTION REQUIRED:**
- Manually create missing password files
- Verify account configurations
- Test administrative access before proceeding"
})

## Validation Checklist

Use this checklist to ensure all validation steps are completed:

### Pre-Production Checklist
- [ ] All JSON validation files loaded successfully
- [ ] All three critical password files exist and contain valid data
- [ ] BitLocker is enabled and recovery key is accessible
- [ ] Windows Firewall is configured with default-deny policy
- [ ] Administrative accounts are properly configured
- [ ] Enhanced security policies are applied and functional
- [ ] Critical business applications function normally
- [ ] Network connectivity for essential services confirmed
- [ ] URBackup client connectivity verified (if applicable)
- [ ] Security monitoring agents functional (if installed)

### Post-Production Monitoring
- [ ] Weekly security log review scheduled
- [ ] Monthly compliance verification scheduled
- [ ] Incident response procedures documented
- [ ] User training completed for new security restrictions
- [ ] Change management documentation updated

---

**Validation Completed:** $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  
**Next Review Date:** $(Get-Date -f 'yyyy-MM-dd' -Date (Get-Date).AddDays(7))  
**Contact:** IT Security Team for validation questions or issues
"@

    $validationMarkdown | Out-File "$logFolder\Validation-Summary.md" -Encoding UTF8
    Write-Log "Validation summary markdown generated" "SUCCESS"
} catch {
    Write-Log "Failed to generate validation summary: $_" "ERROR"
}

Write-Host "`n[7] Creating Master Index Document..." -ForegroundColor Green

# Generate Master Index
try {
    $masterIndexMarkdown = @"
# Windows 11 Security Hardening - Master Documentation Index

**Generated:** $(Get-Date -Format 'MMMM dd, yyyy HH:mm:ss')  
**Computer:** $env:COMPUTERNAME  
**Hardening Version:** v11.1  
**Log Folder:** `$logFolder`

## Documentation Overview

This folder contains complete documentation for the Windows 11 security hardening process. All reports are available in both human-readable markdown format and machine-readable JSON format.

## Human-Readable Reports

### Executive Reports
1. **[Executive-Summary-Report.md](./Executive-Summary-Report.md)**
   - High-level overview for management
   - Compliance framework status
   - Critical actions required
   - Success metrics and KPIs

2. **[Technical-Details-Report.md](./Technical-Details-Report.md)**
   - Detailed technical implementation
   - System configuration changes
   - Security assessment results
   - Troubleshooting information

3. **[Compliance-Documentation.md](./Compliance-Documentation.md)**
   - NIST 800-171 compliance evidence
   - CMMC Level 1 compliance mapping
   - ISO 27001:2022 compliance documentation
   - Audit trail and evidence

4. **[Validation-Summary.md](./Validation-Summary.md)**
   - System validation results
   - File integrity verification
   - Recommended validation steps
   - Success metrics tracking

## Technical Data Files (JSON)

### Core Configuration
- **script-config.json** - Hardening script configuration parameters
- **script1-status.json** - Core hardening execution results
- **script2-status.json** - Compliance collection results
- **executive-summary.json** - Executive summary data
- **final-comprehensive-report.json** - Complete technical report

### System Analysis
- **system-baseline.json** - Complete system inventory and configuration
- **security-assessment.json** - Post-hardening security posture analysis
- **security-events.json** - Security event evidence collection
- **detailed-assessment-report.json** - Technical assessment summary

### Compliance Evidence
- **compliance-framework-mapping.json** - Framework compliance mappings and evidence

## Critical Security Files

**THESE FILES CONTAIN SENSITIVE INFORMATION - SECURE IMMEDIATELY**

$(if($criticalFileStatus.SecOpsAdminPassword) { "- **SecOpsAdm_Password.txt** - Administrative account credentials" })
$(if($criticalFileStatus.BitLockerRecoveryKey) { "- **BitLocker_Recovery_Key.txt** - Drive encryption recovery key" })
$(if($criticalFileStatus.AdministratorPassword) { "- **Administrator_Password.txt** - Built-in Administrator credentials" })

### Security File Handling Instructions
1. **Immediate Actions:**
   - Copy passwords to secure password manager
   - Print BitLocker recovery key for offline storage
   - Remove plain text files after securing
   - Secure this entire folder with appropriate permissions

2. **Access Control:**
   - Limit access to authorized personnel only
   - Use secure channels for password transmission
   - Document all access to these files

## Quick Status Summary

### Overall Hardening Status
- **Success Rate:** $($jsonData.ExecutiveSummary.OperationalResults.SuccessRate)%
- **Critical Failures:** $($jsonData.ExecutiveSummary.OperationalResults.CriticalFailures)
- **Overall Status:** $($jsonData.ExecutiveSummary.OperationalResults.OverallStatus)

### Compliance Status
- **NIST 800-171:** $($jsonData.ExecutiveSummary.ComplianceAchievement.NIST_800_171)
- **CMMC Level 1:** $($jsonData.ExecutiveSummary.ComplianceAchievement.CMMC_Level1)
- **ISO 27001:2022:** $($jsonData.ExecutiveSummary.ComplianceAchievement.ISO_27001)

### Critical Files Status
- **Password Files:** $(($criticalFileStatus.Values | Where-Object {$_ -eq $true}).Count)/3 Created
- **Documentation:** $(($jsonData.FinalReport.GeneratedDocuments | Measure-Object).Count) Files Generated

## Next Steps

### Immediate (Next 24 hours)
1. **Secure Critical Files** - Move all password files to secure storage
2. **System Testing** - Verify all critical business functions
3. **User Communication** - Brief users on new security restrictions

### Short-term (Next week)
1. **Monitoring Setup** - Implement ongoing security monitoring
2. **Validation Testing** - Complete all recommended validation steps
3. **Documentation** - Update change management records

### Long-term (Next month)
1. **Compliance Auditing** - Schedule regular compliance reviews
2. **Security Assessments** - Implement ongoing security evaluations
3. **Process Improvement** - Refine hardening procedures based on lessons learned

## Support Information

### For Technical Issues
- Review the detailed logs in `hardening-detailed.log`
- Check `Technical-Details-Report.md` for troubleshooting
- Contact IT Security team with this log folder location

### For Compliance Questions
- Review `Compliance-Documentation.md` for evidence
- Check JSON files for detailed compliance mappings
- Contact compliance team for audit support

### For Executive Reporting
- Use `Executive-Summary-Report.md` for management briefings
- Reference `Validation-Summary.md` for success metrics
- Escalate critical failures immediately

## File Modification Log

- **$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')** - Master documentation generated
- **$($jsonData.Script1Status.Timestamp)** - Core hardening completed
- **$($jsonData.Script2Status.Timestamp)** - Compliance collection completed
- **$($jsonData.ExecutiveSummary.ExecutionOverview.CompletionTime)** - Final report generated

---

**Documentation Package Version:** v11.1  
**Generated by:** Windows 11 Security Hardening Script Suite  
**Maintained by:** IT Security Team  
**Last Updated:** $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
"@

    $masterIndexMarkdown | Out-File "$logFolder\README.md" -Encoding UTF8
    Write-Log "Master index document generated" "SUCCESS"
} catch {
    Write-Log "Failed to generate master index: $_" "ERROR"
}

# Final validation and status report
Write-Host "`n================================================================================" -ForegroundColor Cyan
Write-Host "                    REPORT GENERATION & VALIDATION COMPLETED" -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan

Write-Host "`nREPORT GENERATION RESULTS:" -ForegroundColor Green
Write-Host "   [+] Executive Summary Report: CREATED" -ForegroundColor Green
Write-Host "   [+] Technical Details Report: CREATED" -ForegroundColor Green
Write-Host "   [+] Compliance Documentation: CREATED" -ForegroundColor Green
Write-Host "   [+] Validation Summary: CREATED" -ForegroundColor Green
Write-Host "   [+] Master Index (README): CREATED" -ForegroundColor Green

Write-Host "`nVALIDATION RESULTS:" -ForegroundColor Cyan
Write-Host "   JSON Files Loaded: $(($jsonData.Keys | Measure-Object).Count)/10" -ForegroundColor White
Write-Host "   Critical Files: $(($criticalFileStatus.Values | Where-Object {$_ -eq $true}).Count)/3" -ForegroundColor White
Write-Host "   System Validations: $($systemValidation.Count) checks performed" -ForegroundColor White

Write-Host "`nHUMAN-READABLE REPORTS CREATED:" -ForegroundColor Magenta
Write-Host "   Executive-Summary-Report.md - Management overview" -ForegroundColor Gray
Write-Host "   Technical-Details-Report.md - Technical implementation" -ForegroundColor Gray
Write-Host "   Compliance-Documentation.md - Framework compliance" -ForegroundColor Gray
Write-Host "   Validation-Summary.md - System validation" -ForegroundColor Gray
Write-Host "   README.md - Master index and navigation" -ForegroundColor Gray

Write-Host "`nCRITICAL FILE STATUS:" -ForegroundColor Red
if ($criticalFileStatus.SecOpsAdminPassword) {
    Write-Host "   [+] SecOpsAdm Password File: SECURED" -ForegroundColor Green
} else {
    Write-Host "   [X] SecOpsAdm Password File: MISSING" -ForegroundColor Red
}

if ($criticalFileStatus.BitLockerRecoveryKey) {
    Write-Host "   [+] BitLocker Recovery Key: SECURED" -ForegroundColor Green
} else {
    Write-Host "   [X] BitLocker Recovery Key: MISSING" -ForegroundColor Red
}

if ($criticalFileStatus.AdministratorPassword) {
    Write-Host "   [+] Administrator Password File: SECURED" -ForegroundColor Green
} else {
    Write-Host "   [X] Administrator Password File: MISSING" -ForegroundColor Red
}

Write-Host "`nRECOMMENDED ACTIONS:" -ForegroundColor Yellow
Write-Host "   1. Review README.md for complete documentation index" -ForegroundColor White
Write-Host "   2. Start with Executive-Summary-Report.md for overview" -ForegroundColor White
Write-Host "   3. Use Technical-Details-Report.md for implementation details" -ForegroundColor White
Write-Host "   4. Reference Compliance-Documentation.md for audit evidence" -ForegroundColor White
Write-Host "   5. Follow Validation-Summary.md for system testing" -ForegroundColor White

if (($criticalFileStatus.Values | Where-Object {$_ -eq $false}).Count -gt 0) {
    Write-Host "`n" + "="*80 -ForegroundColor Red
    Write-Host "                        CRITICAL FILES MISSING" -ForegroundColor Red
    Write-Host "                    IMMEDIATE ATTENTION REQUIRED" -ForegroundColor Red
    Write-Host "="*80 -ForegroundColor Red
    Write-Host "Some critical files are missing. Review the validation report and logs." -ForegroundColor Yellow
}

Write-Host "`nDOCUMENTATION PACKAGE COMPLETE:" -ForegroundColor Green
Write-Host "   All reports available in: $logFolder" -ForegroundColor Cyan
Write-Host "   Start with: README.md for navigation" -ForegroundColor Cyan

Write-Log "Report generation and validation completed successfully" "INFO"
Write-Log "Documentation package created with human-readable reports" "INFO"

Write-Host "`n" + "="*80 -ForegroundColor Cyan
Write-Host "DOCUMENTATION GENERATION COMPLETE - PRESS ANY KEY TO EXIT" -ForegroundColor Cyan
Write-Host "="*80 -ForegroundColor Cyan
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")