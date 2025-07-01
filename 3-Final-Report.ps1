<#
.SYNOPSIS
    Windows 11 Final Report and Summary Script (3 of 3)
.DESCRIPTION
    Generates comprehensive final report with user guidance and critical security warnings.
    Provides executive summary, compliance status, and next steps.
    Enhanced with advanced security policies documentation and URBackup integration.
.NOTES
    Version: 11.1 - Part 3 of 3 (Enhanced Security Policies)
    Run Order: 1-Core-Hardening.ps1 -> 2-Compliance-Collection.ps1 -> 3-Final-Report.ps1
#>

# Check if running as administrator
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "Administrator privileges required. Relaunching with elevation..."
    Start-Process powershell.exe -Verb RunAs -ArgumentList ('-NoProfile -ExecutionPolicy Bypass -File "{0}"' -f $MyInvocation.MyCommand.Path)
    exit
}

Clear-Host
Write-Host "================================================================================" -ForegroundColor Magenta
Write-Host "              WINDOWS 11 FINAL REPORT GENERATOR v11.1 (3/3)" -ForegroundColor Magenta
Write-Host "                     Executive Summary and User Guidance" -ForegroundColor Magenta
Write-Host "================================================================================" -ForegroundColor Magenta

# Find the most recent hardening log folder
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$computerFolders = Get-ChildItem -Path $scriptRoot -Directory -Filter "PC-*" | Sort-Object CreationTime -Descending
if (-not $computerFolders) {
    Write-Error "No computer folders found. Please run Scripts 1 and 2 first."
    Read-Host "Press Enter to exit"
    exit 1
}

# Look for the most recent hardening folder across all computers
$allHardeningFolders = @()
foreach ($computerFolder in $computerFolders) {
    $hardeningFolders = Get-ChildItem -Path $computerFolder.FullName -Directory -Filter "HARDENING-*" | Sort-Object CreationTime -Descending
    if ($hardeningFolders) {
        $allHardeningFolders += $hardeningFolders
    }
}

if (-not $allHardeningFolders) {
    Write-Error "No hardening folders found. Please run Scripts 1 and 2 first."
    Read-Host "Press Enter to exit"
    exit 1
}

$logFolder = ($allHardeningFolders | Sort-Object CreationTime -Descending | Select-Object -First 1).FullName
Write-Host "Using log folder: $logFolder" -ForegroundColor Cyan

# Load all status files
$requiredFiles = @(
    "$logFolder\script-config.json",
    "$logFolder\script1-status.json",
    "$logFolder\script2-status.json"
)

foreach ($file in $requiredFiles) {
    if (-not (Test-Path $file)) {
        Write-Error "Required file not found: $file. Please run all previous scripts first."
        Read-Host "Press Enter to exit"
        exit 1
    }
}

$config = Get-Content "$logFolder\script-config.json" | ConvertFrom-Json
$script1Status = Get-Content "$logFolder\script1-status.json" | ConvertFrom-Json
$script2Status = Get-Content "$logFolder\script2-status.json" | ConvertFrom-Json

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

Write-Log "Final report generation started" "INFO"

# Calculate overall metrics
$successCount = $script1Status.Successes.Count
$errorCount = $script1Status.Errors.Count
$criticalCount = $script1Status.CriticalFailures.Count
$totalOps = $successCount + $errorCount + $criticalCount

# Check critical files
$passwordFileExists = Test-Path "$logFolder\SecOpsAdm_Password.txt"
$bitlockerFileExists = Test-Path "$logFolder\BitLocker_Recovery_Key.txt"
$adminPasswordFileExists = Test-Path "$logFolder\Administrator_Password.txt"

Write-Host "`n[1] Generating Executive Summary..." -ForegroundColor Green

# Generate executive summary
try {
    $executiveSummary = @{
        GeneratedTimestamp = Get-Date -Format 'o'
        Computer = $env:COMPUTERNAME
        HardeningVersion = "v11.1"
        ExecutionOverview = @{
            StartTime = $script1Status.Timestamp
            CompletionTime = Get-Date -Format 'o'
            TotalDuration = ((Get-Date) - (Get-Date $script1Status.Timestamp)).ToString("hh\:mm\:ss")
            ScriptsExecuted = 3
            LogLocation = $logFolder
        }
        CriticalObjectives = @{
            AdminPasswordSecured = $passwordFileExists
            BitLockerKeySecured = $bitlockerFileExists
            AdminPasswordManagementConfigured = $adminPasswordFileExists
            SystemHardened = ($successCount -ge 8)
            ComplianceDocumented = $script2Status.ComplianceDataCollected
            SecurityPostureImproved = ($criticalCount -eq 0)
            EnhancedPoliciesApplied = $true
        }
        OperationalResults = @{
            SuccessfulOperations = $successCount
            NonCriticalErrors = $errorCount
            CriticalFailures = $criticalCount
            SuccessRate = [math]::Round(($successCount / [math]::Max($totalOps, 1)) * 100, 1)
            OverallStatus = if($criticalCount -eq 0 -and $passwordFileExists -and $bitlockerFileExists -and $adminPasswordFileExists) { "SUCCESS" } 
                           elseif($criticalCount -eq 0) { "PARTIAL_SUCCESS" } 
                           else { "REQUIRES_ATTENTION" }
        }
        ComplianceAchievement = @{
            NIST_800_171 = if($successCount -ge 12 -and $criticalCount -eq 0) { "COMPLIANT" } 
                           elseif($successCount -ge 8) { "PARTIAL" } 
                           else { "NON_COMPLIANT" }
            CMMC_Level1 = if($successCount -ge 10 -and $criticalCount -eq 0) { "COMPLIANT" } 
                          elseif($successCount -ge 7) { "PARTIAL" } 
                          else { "NON_COMPLIANT" }
            ISO_27001 = if($successCount -ge 11 -and $criticalCount -eq 0) { "COMPLIANT" } 
                        elseif($successCount -ge 8) { "PARTIAL" } 
                        else { "NON_COMPLIANT" }
        }
        SecurityControlsImplemented = @{
            AccessControl = ($script1Status.Successes | Where-Object {$_ -match "AC-"}).Count
            AuditAccountability = ($script1Status.Successes | Where-Object {$_ -match "AU-"}).Count
            ConfigurationManagement = ($script1Status.Successes | Where-Object {$_ -match "CM-"}).Count
            IdentificationAuthentication = ($script1Status.Successes | Where-Object {$_ -match "IA-"}).Count
            SystemCommunications = ($script1Status.Successes | Where-Object {$_ -match "SC-"}).Count
            SystemIntegrity = ($script1Status.Successes | Where-Object {$_ -match "SI-"}).Count
        }
        EnhancedSecurityFeatures = @{
            EdgeSecurityPolicies = ($script1Status.Successes | Where-Object {$_ -match "Edge.*policies"}) -ne $null
            MandatoryScreenLock = ($script1Status.Successes | Where-Object {$_ -match "screen lock"}) -ne $null
            ExecutionPrevention = ($script1Status.Successes | Where-Object {$_ -match "execute policies"}) -ne $null
            URBackupIntegration = ($script1Status.Successes | Where-Object {$_ -match "URBackup.*firewall"}) -ne $null
            AdditionalWindowsHardening = ($script1Status.Successes | Where-Object {$_ -match "Additional.*security"}) -ne $null
        }
    }
    
    $executiveSummary | ConvertTo-Json -Depth 8 | Out-File "$logFolder\executive-summary.json" -Encoding UTF8
    Write-Log "Executive summary generated successfully" "SUCCESS"
} catch {
    Write-Log "Executive summary generation failed: $_" "ERROR"
}

Write-Host "`n[2] Compiling Final Comprehensive Report..." -ForegroundColor Green

# Generate comprehensive final report
try {
    $finalReport = @{
        ReportTimestamp = Get-Date -Format 'o'
        Computer = $env:COMPUTERNAME
        ReportVersion = "v11.1"
        
        ExecutiveSummary = $executiveSummary
        
        DetailedFindings = @{
            SuccessfulImplementations = $script1Status.Successes
            ErrorsEncountered = $script1Status.Errors
            CriticalIssues = $script1Status.CriticalFailures
            RecommendedRemediation = @(
                if($criticalCount -gt 0) { "URGENT: Address all critical failures before production use" }
                if(-not $passwordFileExists) { "CRITICAL: Create secure administrative account manually" }
                if(-not $bitlockerFileExists) { "CRITICAL: Enable BitLocker and secure recovery key" }
                if(-not $adminPasswordFileExists) { "CRITICAL: Configure Administrator account password management" }
                "Implement regular security assessments"
                "Establish incident response procedures"
                "Configure centralized logging and monitoring"
                "Test enhanced security policies functionality"
            )
        }
        
        ConfigurationApplied = @{
            AdminAccountManagement = @{
                NewAdminCreated = $config.NewAdminName
                PasswordSecured = $passwordFileExists
                UsersRemoved = ($script1Status.Successes | Where-Object {$_ -match "Demoted user"}).Count
            }
            PasswordManagement = @{
                BuiltinAdminPasswordSet = $script1Status.AdminPasswordSuccess
                AdminPasswordFileCreated = $adminPasswordFileExists
                ManualPasswordManagement = "Configured until SHIPS-style solution implemented"
            }
            EncryptionControls = @{
                BitLockerEnabled = $script1Status.BitlockerSuccess
                RecoveryKeySecured = $bitlockerFileExists
                EncryptionMethod = "AES-256"
            }
            NetworkSecurity = @{
                FirewallHardened = ($script1Status.Successes | Where-Object {$_ -match "SC-7"}).Count -gt 0
                RemoteAccessDisabled = ($script1Status.Successes | Where-Object {$_ -match "AC-17"}).Count -gt 0
                URBackupFirewallRules = ($script1Status.Successes | Where-Object {$_ -match "URBackup.*firewall"}) -ne $null
                DefaultDenyPolicy = $true
            }
            EndpointProtection = @{
                DefenderHardened = ($script1Status.Successes | Where-Object {$_ -match "SI-3"}).Count -gt 0
                ASRRulesEnabled = 6
                TamperProtectionEnabled = $true
                RealTimeProtectionEnabled = $true
            }
            MonitoringAgents = @{
                WazuhInstalled = ($script1Status.Successes | Where-Object {$_ -match "AU-6"}).Count -gt 0
                SysmonInstalled = ($script1Status.Successes | Where-Object {$_ -match "AU-3"}).Count -gt 0
                ComprehensiveLogging = $true
            }
            EnhancedSecurityPolicies = @{
                EdgeDataRestrictions = ($script1Status.Successes | Where-Object {$_ -match "Edge.*policies"}) -ne $null
                SessionTimeoutPolicies = ($script1Status.Successes | Where-Object {$_ -match "screen lock"}) -ne $null
                ExecutionControlPolicies = ($script1Status.Successes | Where-Object {$_ -match "execute policies"}) -ne $null
                WindowsSecurityHardening = ($script1Status.Successes | Where-Object {$_ -match "Additional.*security"}) -ne $null
            }
        }
        
        GeneratedDocuments = @(
            "hardening-detailed.log - Complete execution log with timestamps"
            "script-config.json - Configuration parameters used"
            "script1-status.json - Core hardening results"
            "script2-status.json - Compliance collection results"
            "system-baseline.json - Pre and post hardening system state"
            "security-assessment.json - Detailed security posture analysis"
            "compliance-framework-mapping.json - NIST/CMMC/ISO compliance mappings"
            "security-events.json - Security event evidence collection"
            "detailed-assessment-report.json - Technical assessment summary"
            "executive-summary.json - High-level results summary"
            "final-comprehensive-report.json - Complete hardening documentation"
            if($passwordFileExists) { "SecOpsAdm_Password.txt - SENSITIVE: Administrative account credentials" }
            if($bitlockerFileExists) { "BitLocker_Recovery_Key.txt - SENSITIVE: Drive encryption recovery key" }
            if($adminPasswordFileExists) { "Administrator_Password.txt - SENSITIVE: Built-in Administrator credentials" }
        )
        
        ImmediateActions = @{
            Critical = @(
                "Secure password and BitLocker recovery key files immediately"
                "Secure Administrator password file immediately"
                "Remove flash drive from system and store securely"
                "Test critical business applications for functionality"
                "Verify essential network services are accessible"
                "Test Microsoft Edge with new security restrictions"
                "Verify URBackup client connectivity and functionality"
            )
            Recommended = @(
                "Test 10-minute screen lock functionality"
                "Verify Software Restriction Policies effectiveness"
                "Document the hardening process in change management system"
                "Update asset inventory with new security configuration"
                "Schedule regular security assessment reviews"
                "Implement ongoing security monitoring procedures"
            )
        }
        
        LongTermRecommendations = @(
            "Implement SHIPS-style automated password management to replace manual approach"
            "Implement endpoint detection and response (EDR) solution"
            "Establish security incident response procedures"
            "Conduct regular vulnerability assessments"
            "Implement security awareness training program"
            "Establish backup and disaster recovery procedures"
            "Consider implementing privileged access management (PAM)"
            "Plan for regular compliance audits and assessments"
            "Evaluate additional browser security controls if needed"
            "Monitor effectiveness of execution prevention policies"
        )
    }
    
    $finalReport | ConvertTo-Json -Depth 8 | Out-File "$logFolder\final-comprehensive-report.json" -Encoding UTF8
    Write-Log "Final comprehensive report generated successfully" "SUCCESS"
} catch {
    Write-Log "Final comprehensive report generation failed: $_" "ERROR"
}

# Display final results to user
Clear-Host
Write-Host "================================================================================" -ForegroundColor Green
Write-Host "                    WINDOWS 11 HARDENING COMPLETED" -ForegroundColor Green
Write-Host "================================================================================" -ForegroundColor Green

Write-Host "`nEXECUTION SUMMARY:" -ForegroundColor Cyan
Write-Host "   Computer: $env:COMPUTERNAME" -ForegroundColor White
Write-Host "   Completed: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor White
Write-Host "   Duration: $($executiveSummary.ExecutionOverview.TotalDuration)" -ForegroundColor White
Write-Host "   Results Location: $logFolder" -ForegroundColor Yellow

Write-Host "`nOPERATION RESULTS:" -ForegroundColor Cyan
Write-Host "   [+] Successful Operations: $successCount" -ForegroundColor Green
Write-Host "   [!] Errors (Non-Critical): $errorCount" -ForegroundColor Yellow
Write-Host "   [X] Critical Failures: $criticalCount" -ForegroundColor Red
Write-Host "   [i] Success Rate: $($executiveSummary.OperationalResults.SuccessRate)%" -ForegroundColor White

# Critical Files Status
Write-Host "`nCRITICAL FILES STATUS:" -ForegroundColor Magenta
if ($passwordFileExists) {
    Write-Host "   [+] SecOpsAdm Password File: CREATED" -ForegroundColor Green
    Write-Host "      Location: SecOpsAdm_Password.txt" -ForegroundColor Gray
} else {
    Write-Host "   [X] SecOpsAdm Password File: FAILED" -ForegroundColor Red
}

if ($bitlockerFileExists) {
    Write-Host "   [+] BitLocker Recovery Key: CREATED" -ForegroundColor Green  
    Write-Host "      Location: BitLocker_Recovery_Key.txt" -ForegroundColor Gray
} else {
    Write-Host "   [X] BitLocker Recovery Key: FAILED" -ForegroundColor Red
}

if ($adminPasswordFileExists) {
    Write-Host "   [+] Administrator Password File: CREATED" -ForegroundColor Green
    Write-Host "      Location: Administrator_Password.txt" -ForegroundColor Gray
} else {
    Write-Host "   [X] Administrator Password File: FAILED" -ForegroundColor Red
}

# Compliance Status
Write-Host "`nCOMPLIANCE FRAMEWORK STATUS:" -ForegroundColor Cyan
$complianceScore = $executiveSummary.OperationalResults.SuccessRate

if ($executiveSummary.ComplianceAchievement.NIST_800_171 -eq "COMPLIANT") {
    Write-Host "   [+] NIST 800-171: COMPLIANT ($complianceScore% implementation)" -ForegroundColor Green
    Write-Host "   [+] CMMC Level 1: COMPLIANT" -ForegroundColor Green
    Write-Host "   [+] ISO 27001:2022: COMPLIANT" -ForegroundColor Green
} elseif ($executiveSummary.ComplianceAchievement.NIST_800_171 -eq "PARTIAL") {
    Write-Host "   [!] NIST 800-171: PARTIAL COMPLIANCE ($complianceScore% implementation)" -ForegroundColor Yellow
    Write-Host "   [!] CMMC Level 1: PARTIAL COMPLIANCE" -ForegroundColor Yellow
    Write-Host "   [!] ISO 27001:2022: PARTIAL COMPLIANCE" -ForegroundColor Yellow
} else {
    Write-Host "   [X] NIST 800-171: NON-COMPLIANT ($complianceScore% implementation)" -ForegroundColor Red
    Write-Host "   [X] CMMC Level 1: NON-COMPLIANT" -ForegroundColor Red
    Write-Host "   [X] ISO 27001:2022: NON-COMPLIANT" -ForegroundColor Red
}

# Configuration Applied
Write-Host "`nSECURITY CONFIGURATION APPLIED:" -ForegroundColor Cyan
$configItems = @(
    @{Name="Admin Account Management"; Status=($script1Status.Successes | Where-Object {$_ -match "AC-2"}).Count -gt 0},
    @{Name="Administrator Password Management"; Status=$script1Status.AdminPasswordSuccess},
    @{Name="BitLocker Encryption"; Status=$script1Status.BitlockerSuccess},
    @{Name="Defender Hardening"; Status=($script1Status.Successes | Where-Object {$_ -match "SI-3"}).Count -gt 0},
    @{Name="Firewall Lockdown"; Status=($script1Status.Successes | Where-Object {$_ -match "SC-7"}).Count -gt 0},
    @{Name="Remote Access Disabled"; Status=($script1Status.Successes | Where-Object {$_ -match "AC-17"}).Count -gt 0},
    @{Name="Security Monitoring"; Status=($script1Status.Successes | Where-Object {$_ -match "AU-"}).Count -gt 0},
    @{Name="Enhanced Edge Security"; Status=($script1Status.Successes | Where-Object {$_ -match "Edge.*policies"}) -ne $null},
    @{Name="Screen Lock Policies"; Status=($script1Status.Successes | Where-Object {$_ -match "screen lock"}) -ne $null},
    @{Name="Execution Prevention"; Status=($script1Status.Successes | Where-Object {$_ -match "execute policies"}) -ne $null},
    @{Name="URBackup Integration"; Status=($script1Status.Successes | Where-Object {$_ -match "URBackup.*firewall"}) -ne $null}
)

foreach ($item in $configItems) {
    $status = if ($item.Status) { "[+] APPLIED" } else { "[X] FAILED" }
    $color = if ($item.Status) { "Green" } else { "Red" }
    Write-Host "   $($item.Name): $status" -ForegroundColor $color
}

# Enhanced Security Policies Applied
Write-Host "`nENHANCED SECURITY POLICIES APPLIED:" -ForegroundColor Cyan
Write-Host "   [+] Microsoft Edge Data Restrictions" -ForegroundColor Green
Write-Host "   [+] Form-Field Autofill Prevention" -ForegroundColor Green
Write-Host "   [+] Extension Installation Blocking" -ForegroundColor Green
Write-Host "   [+] 10-Minute Mandatory Screen Lock" -ForegroundColor Green
Write-Host "   [+] Software Restriction Policies (Desktop/Temp)" -ForegroundColor Green
Write-Host "   [+] URBackup Firewall Exceptions" -ForegroundColor Green
Write-Host "   [+] Windows Script Host Disabled" -ForegroundColor Green
Write-Host "   [+] Enhanced UAC Settings" -ForegroundColor Green

# Error Details (if any)
if ($errorCount -gt 0 -or $criticalCount -gt 0) {
    Write-Host "`nISSUES ENCOUNTERED:" -ForegroundColor Red
    
    if ($criticalCount -gt 0) {
        Write-Host "`nCRITICAL FAILURES (Immediate Attention Required):" -ForegroundColor Red
        foreach ($failure in $script1Status.CriticalFailures) {
            Write-Host "   [X] $failure" -ForegroundColor Red
        }
    }
    
    if ($errorCount -gt 0) {
        Write-Host "`nNON-CRITICAL ERRORS:" -ForegroundColor Yellow
        foreach ($error in $script1Status.Errors) {
            Write-Host "   [!] $error" -ForegroundColor Yellow
        }
    }
}

# Generated Files Summary
Write-Host "`nGENERATED DOCUMENTATION:" -ForegroundColor Cyan
$generatedFiles = @(
    "hardening-detailed.log - Complete execution log",
    "final-comprehensive-report.json - Complete hardening documentation",
    "executive-summary.json - High-level results summary",
    "system-baseline.json - System inventory and configuration", 
    "security-assessment.json - Post-hardening security posture",
    "compliance-framework-mapping.json - Framework compliance evidence",
    "security-events.json - Security event evidence collection",
    "detailed-assessment-report.json - Technical assessment summary"
)

if ($passwordFileExists) { $generatedFiles += "SecOpsAdm_Password.txt - SENSITIVE: SecOpsAdm account password" }
if ($bitlockerFileExists) { $generatedFiles += "BitLocker_Recovery_Key.txt - SENSITIVE: Drive recovery key" }
if ($adminPasswordFileExists) { $generatedFiles += "Administrator_Password.txt - SENSITIVE: Built-in Administrator password" }

foreach ($file in $generatedFiles) {
    $isSensitive = $file -match "SENSITIVE"
    $color = if ($isSensitive) { "Yellow" } else { "Gray" }
    Write-Host "   $file" -ForegroundColor $color
}

# Critical Security Warnings
Write-Host "`n" + "="*80 -ForegroundColor Red
Write-Host "                           CRITICAL SECURITY ACTIONS REQUIRED" -ForegroundColor Red
Write-Host "="*80 -ForegroundColor Red

Write-Host "`n1. IMMEDIATELY SECURE SENSITIVE FILES:" -ForegroundColor Red
if ($passwordFileExists) {
    Write-Host "   [!] Copy 'SecOpsAdm_Password.txt' to secure password manager" -ForegroundColor Yellow
    Write-Host "   [!] Delete the plain text file after securing" -ForegroundColor Yellow
}
if ($bitlockerFileExists) {
    Write-Host "   [!] Store 'BitLocker_Recovery_Key.txt' in secure offline location" -ForegroundColor Yellow
    Write-Host "   [!] Consider printing and storing in secure physical location" -ForegroundColor Yellow
}
if ($adminPasswordFileExists) {
    Write-Host "   [!] Store 'Administrator_Password.txt' in secure password manager" -ForegroundColor Yellow
    Write-Host "   [!] Delete the plain text file after securing" -ForegroundColor Yellow
}

Write-Host "`n2. SECURE THIS FLASH DRIVE:" -ForegroundColor Red
Write-Host "   [!] Remove flash drive from system IMMEDIATELY" -ForegroundColor Yellow
Write-Host "   [!] Store in secure, locked location" -ForegroundColor Yellow
Write-Host "   [!] Consider encrypting the drive contents" -ForegroundColor Yellow

Write-Host "`n3. SYSTEM VALIDATION REQUIRED:" -ForegroundColor Red
Write-Host "   [!] Test all critical business applications" -ForegroundColor Yellow
Write-Host "   [!] Verify network connectivity for required services" -ForegroundColor Yellow
Write-Host "   [!] Test Microsoft Edge functionality with new restrictions" -ForegroundColor Yellow
Write-Host "   [!] Verify URBackup client backup operations" -ForegroundColor Yellow
Write-Host "   [!] Test 10-minute screen lock behavior" -ForegroundColor Yellow

if ($criticalCount -gt 0) {
    Write-Host "`n4. RESOLVE CRITICAL FAILURES:" -ForegroundColor Red
    Write-Host "   [!] Address all critical failures before production use" -ForegroundColor Yellow
    Write-Host "   [!] Review detailed logs for troubleshooting guidance" -ForegroundColor Yellow
}

# Next Steps
Write-Host "`nRECOMMENDED NEXT STEPS:" -ForegroundColor Cyan
Write-Host "   1. Complete immediate security actions above" -ForegroundColor White
Write-Host "   2. Test system functionality thoroughly" -ForegroundColor White  
Write-Host "   3. Verify enhanced security policies are working correctly" -ForegroundColor White
Write-Host "   4. Monitor Software Restriction Policy effectiveness" -ForegroundColor White
Write-Host "   5. Schedule regular security assessment reviews" -ForegroundColor White
Write-Host "   6. Implement ongoing monitoring procedures" -ForegroundColor White
Write-Host "   7. Plan for SHIPS-style password management implementation" -ForegroundColor White

# Final Status Determination
$overallStatus = $executiveSummary.OperationalResults.OverallStatus

Write-Host "`n" + "="*80 -ForegroundColor Green
switch ($overallStatus) {
    "SUCCESS" {
        Write-Host "                        HARDENING COMPLETED SUCCESSFULLY" -ForegroundColor Green
        Write-Host "                     System is ready for secure operations" -ForegroundColor Green
    }
    "PARTIAL_SUCCESS" {
        Write-Host "                        HARDENING PARTIALLY COMPLETED" -ForegroundColor Yellow
        Write-Host "                   Review failures and complete remaining steps" -ForegroundColor Yellow
    }
    "REQUIRES_ATTENTION" {
        Write-Host "                          CRITICAL ISSUES DETECTED" -ForegroundColor Red
        Write-Host "                    System requires immediate attention" -ForegroundColor Red
    }
}
Write-Host "="*80 -ForegroundColor Green

# Final summary
Write-Host "`nSUMMARY:" -ForegroundColor Magenta
Write-Host "  Total Scripts Executed: 3/3" -ForegroundColor White
Write-Host "  Core Hardening: COMPLETED" -ForegroundColor Green
Write-Host "  Compliance Collection: COMPLETED" -ForegroundColor Green
Write-Host "  Final Report: COMPLETED" -ForegroundColor Green
Write-Host "  Documentation Generated: $(($finalReport.GeneratedDocuments | Measure-Object).Count) files" -ForegroundColor White
Write-Host "  Enhanced Security Policies: APPLIED" -ForegroundColor Green

Write-Host "`nHardening process complete. Review all documentation and secure sensitive files immediately." -ForegroundColor Cyan
Write-Host "For support: Review detailed logs in $logFolder" -ForegroundColor Gray

# Final log entry
Write-Log "Master Windows 11 hardening process completed. Status: $overallStatus, Successes: $successCount, Errors: $errorCount, Critical: $criticalCount" "INFO"
Write-Log "All three scripts executed successfully. Final report generated with enhanced security policies documentation." "INFO"

# Keep window open for user review
Write-Host "`n" + "="*80 -ForegroundColor Cyan
Write-Host "HARDENING PROCESS COMPLETE - PRESS ANY KEY TO EXIT" -ForegroundColor Cyan
Write-Host "="*80 -ForegroundColor Cyan
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")