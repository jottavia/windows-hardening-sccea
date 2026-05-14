<#
.SYNOPSIS
    Master GUI console for the Windows Hardening Toolkit. Launches the hardening
    script, the audit script, the undo script, and provides post-hardening
    toggles for RustDesk, Tailscale, RDP, Defender exclusions, and custom
    firewall rules.
.DESCRIPTION
    This console assumes the unified hardening script has been (or will be) run
    from the same USB drive. It locates the most recent
    PC-<COMPUTERNAME>-LOGS\HARDENING-<timestamp> folder, reads its
    hardening-state.json, and writes any post-hardening modifications back into
    that same state file under a 'PostHardening' section so Undo-PostHardening.ps1
    can reverse them.

    Uses Windows-built-in components only: System.Windows.Forms and System.Drawing.
.NOTES
    Version: 1.0.0
    Pairs with: Unified_PowerShell_Hardening_Script.ps1 v9.1
                undo-hardening.ps1
                collect-compliance-data.ps1
                Undo-PostHardening.ps1
#>
[CmdletBinding()]
param(
    [string]$UsbRoot = $null
)

#===========================================================================
# ADMIN ELEVATION
#===========================================================================
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "Administrator privileges are required."
    Start-Process powershell.exe -Verb RunAs -ArgumentList ('-NoProfile -ExecutionPolicy Bypass -File "{0}"' -f $MyInvocation.MyCommand.Path)
    exit
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

#===========================================================================
# CONFIGURATION
#===========================================================================
$script:Config = @{
    Version            = '1.0.0'
    LogRootPattern     = "PC-$env:COMPUTERNAME-LOGS"
    HardeningPattern   = "HARDENING-*"
    StateFileName      = "hardening-state.json"
    ConsoleLogName     = "post-hardening-log.txt"

    HardeningScript    = "Unified_PowerShell_Hardening_Script.ps1"
    AuditScript        = "collect-compliance-data.ps1"
    UndoScript         = "undo-hardening.ps1"

    RustDeskInstallerPattern = "rustdesk-*.exe"
    RustDeskMsiPattern       = "rustdesk-*.msi"
    RustDeskServerFile       = "rustdesk-server.txt"
    RustDeskKeyFile          = "rustdesk-key.txt"
    RustDeskInstallDir       = "C:\Program Files\RustDesk"

    TailscaleInstallerPattern = "tailscale-setup-*.exe"
    TailscaleMsiPattern       = "tailscale-*.msi"
    TailscaleInstallDir       = "C:\Program Files\Tailscale"
    TailscalePortUDP          = 41641

    # RustDesk client outbound ports for public relays
    RustDeskClientPorts = @(
        @{ Name = 'RustDesk-Out-TCP'; Protocol = 'TCP'; Port = '21115-21119' },
        @{ Name = 'RustDesk-Out-UDP'; Protocol = 'UDP'; Port = '21116' }
    )
}

# Resolve script root and USB root once
$script:ScriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
if (-not $UsbRoot) {
    $UsbRoot = Split-Path -Qualifier $script:ScriptRoot
    if ($UsbRoot -notmatch '\\$') { $UsbRoot = "$UsbRoot\" }
}
$script:UsbRoot = $UsbRoot

#===========================================================================
# STATE / LOG HELPERS
#===========================================================================
function Get-LatestHardeningFolder {
    $root = Join-Path $script:UsbRoot $script:Config.LogRootPattern
    if (-not (Test-Path $root)) { return $null }
    $latest = Get-ChildItem -Path $root -Directory -Filter $script:Config.HardeningPattern -ErrorAction SilentlyContinue |
              Sort-Object Name -Descending |
              Select-Object -First 1
    if ($latest) { return $latest.FullName }
    return $null
}

function Get-HardeningState {
    $folder = Get-LatestHardeningFolder
    if (-not $folder) { return $null }
    $stateFile = Join-Path $folder $script:Config.StateFileName
    if (-not (Test-Path $stateFile)) { return $null }
    try {
        $state = Get-Content -Path $stateFile -Raw -Encoding UTF8 | ConvertFrom-Json
        return [PSCustomObject]@{
            Folder    = $folder
            StateFile = $stateFile
            State     = $state
        }
    } catch {
        return $null
    }
}

function Save-HardeningState {
    param(
        [Parameter(Mandatory=$true)][string]$StateFile,
        [Parameter(Mandatory=$true)]$State
    )
    $State | ConvertTo-Json -Depth 10 | Out-File -FilePath $StateFile -Encoding UTF8 -Force
}

function Initialize-PostHardeningSection {
    param([Parameter(Mandatory=$true)]$State)
    if (-not ($State.PSObject.Properties.Name -contains 'PostHardening')) {
        $ph = [PSCustomObject]@{
            Version                 = 1
            RustDesk                = $null
            Tailscale               = $null
            RdpReenabled            = $false
            CustomFirewallRules     = @()
            DefenderExclusionsAdded = @()
        }
        $State | Add-Member -NotePropertyName PostHardening -NotePropertyValue $ph -Force
    }
    return $State
}

function Update-PostHardeningState {
    param([Parameter(Mandatory=$true)][scriptblock]$Mutate)
    $h = Get-HardeningState
    if (-not $h) { return $false }
    $state = Initialize-PostHardeningSection -State $h.State
    & $Mutate $state.PostHardening
    Save-HardeningState -StateFile $h.StateFile -State $state
    return $true
}

function Find-FileByPatterns {
    param([Parameter(Mandatory=$true)][string[]]$Patterns)
    foreach ($pat in $Patterns) {
        $hit = Get-ChildItem -Path $script:ScriptRoot -Filter $pat -ErrorAction SilentlyContinue |
               Select-Object -First 1
        if ($hit) { return $hit.FullName }
    }
    return $null
}

function Get-UninstallEntry {
    param([Parameter(Mandatory=$true)][string]$DisplayNamePattern)
    $hives = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    foreach ($hive in $hives) {
        $hit = Get-ItemProperty -Path $hive -ErrorAction SilentlyContinue |
               Where-Object { $_.DisplayName -like $DisplayNamePattern } |
               Select-Object -First 1
        if ($hit) { return $hit }
    }
    return $null
}

function Write-ConsoleLog {
    param([string]$Text, [string]$Level = 'INFO')
    $h = Get-HardeningState
    if (-not $h) { return }
    $logFile = Join-Path $h.Folder $script:Config.ConsoleLogName
    "$(Get-Date -f 'yyyy-MM-dd HH:mm:ss') [$Level] :: $Text" | Add-Content -Path $logFile -Encoding UTF8
}

#===========================================================================
# MSI / FIREWALL HELPERS
#===========================================================================
$script:MsiPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"

function Invoke-WithMsiAllowed {
    param([Parameter(Mandatory=$true)][scriptblock]$ScriptBlock)
    $had = $false
    $prev = $null
    try {
        if (Test-Path $script:MsiPolicyPath) {
            $had = $true
            $prev = (Get-ItemProperty -Path $script:MsiPolicyPath -Name "DisableMSI" -ErrorAction SilentlyContinue).DisableMSI
            Set-ItemProperty -Path $script:MsiPolicyPath -Name "DisableMSI" -Value 0 -Type DWord -Force
        }
        & $ScriptBlock
    } finally {
        if ($had -and $null -ne $prev) {
            Set-ItemProperty -Path $script:MsiPolicyPath -Name "DisableMSI" -Value $prev -Type DWord -Force
        }
    }
}

function Test-FirewallRuleExists {
    param([Parameter(Mandatory=$true)][string]$Name)
    return [bool](Get-NetFirewallRule -DisplayName $Name -ErrorAction SilentlyContinue)
}

function Add-OutboundAllowRule {
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][ValidateSet('TCP','UDP')][string]$Protocol,
        [Parameter(Mandatory=$true)][string]$RemotePort
    )
    if (Test-FirewallRuleExists -Name $Name) {
        Write-ConsoleLog "Firewall rule '$Name' already exists. Skipping."
        return
    }
    New-NetFirewallRule -DisplayName $Name -Direction Outbound -Action Allow `
        -Protocol $Protocol -RemotePort $RemotePort -Profile Any -Enabled True | Out-Null
    Write-ConsoleLog "Firewall rule added: $Name ($Protocol/$RemotePort outbound)"
}

function Remove-OutboundAllowRule {
    param([Parameter(Mandatory=$true)][string]$Name)
    if (Test-FirewallRuleExists -Name $Name) {
        Remove-NetFirewallRule -DisplayName $Name -ErrorAction SilentlyContinue
        Write-ConsoleLog "Firewall rule removed: $Name"
    }
}

# Poll for service appearance/disappearance after an installer/uninstaller call.
function Wait-ServicePresent {
    param(
        [Parameter(Mandatory=$true)][string]$ServicePattern,
        [int]$TimeoutSeconds = 60
    )
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        if (Get-Service -Name $ServicePattern -ErrorAction SilentlyContinue) { return $true }
        Start-Sleep -Seconds 2
    }
    return $false
}

function Wait-ServiceAbsent {
    param(
        [Parameter(Mandatory=$true)][string]$ServicePattern,
        [int]$TimeoutSeconds = 30
    )
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        if (-not (Get-Service -Name $ServicePattern -ErrorAction SilentlyContinue)) { return $true }
        Start-Sleep -Seconds 2
    }
    return $false
}

# Detect RustDesk install state from registry + filesystem + services.
# Returns a PSCustomObject with: Installed, InstallPath, ExePath, ServiceName, ServiceStatus.
function Get-RustDeskInstallInfo {
    $u = Get-UninstallEntry -DisplayNamePattern 'RustDesk*'
    $installPath = $null
    if ($u -and $u.InstallLocation) {
        $installPath = $u.InstallLocation.TrimEnd('\')
    } elseif (Test-Path $script:Config.RustDeskInstallDir) {
        $installPath = $script:Config.RustDeskInstallDir
    }

    $exePath = $null
    if ($installPath) {
        $candidate = Join-Path $installPath 'rustdesk.exe'
        if (Test-Path $candidate) { $exePath = $candidate }
    }

    $service = Get-Service -Name 'rustdesk*' -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $service) {
        $service = Get-Service -DisplayName 'RustDesk*' -ErrorAction SilentlyContinue | Select-Object -First 1
    }

    return [PSCustomObject]@{
        Installed     = [bool]($exePath -or $service)
        InstallPath   = $installPath
        ExePath       = $exePath
        ServiceName   = if ($service) { $service.Name } else { $null }
        ServiceStatus = if ($service) { $service.Status.ToString() } else { 'NotFound' }
    }
}

#===========================================================================
# =================== ACTIONS (extend below for new toggles) ================
#===========================================================================
# Each action returns @{ Ok = $true/$false; Message = '...' }. Actions update
# state via Get-HardeningState / Save-HardeningState and log via Write-ConsoleLog.
#===========================================================================

function Invoke-Action-RunHardening {
    param([string[]]$UsersToDemote = @(), [string]$WazuhManagerIP = '192.168.1.100')
    $script = Join-Path $script:ScriptRoot $script:Config.HardeningScript
    if (-not (Test-Path $script)) {
        return @{ Ok = $false; Message = "Hardening script not found: $script" }
    }
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$script`"")
    if ($UsersToDemote.Count -gt 0) {
        $argList += '-UsersToDemote'
        $argList += ($UsersToDemote -join ',')
    }
    if ($WazuhManagerIP) {
        $argList += '-WazuhManagerIP'
        $argList += $WazuhManagerIP
    }
    Start-Process powershell.exe -ArgumentList $argList -Verb RunAs -Wait
    return @{ Ok = $true; Message = "Hardening script execution returned." }
}

function Invoke-Action-RunAudit {
    $script = Join-Path $script:ScriptRoot $script:Config.AuditScript
    if (-not (Test-Path $script)) {
        return @{ Ok = $false; Message = "Audit script not found: $script" }
    }
    Start-Process powershell.exe -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$script`"") -Verb RunAs -Wait
    return @{ Ok = $true; Message = "Audit run returned." }
}

function Invoke-Action-RunUndo {
    $h = Get-HardeningState
    if (-not $h) { return @{ Ok = $false; Message = "No hardening log folder found." } }
    $script = Join-Path $script:ScriptRoot $script:Config.UndoScript
    if (-not (Test-Path $script)) {
        return @{ Ok = $false; Message = "Undo script not found: $script" }
    }
    Start-Process powershell.exe -ArgumentList @(
        '-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$script`"",
        '-LogFolderPath',"`"$($h.Folder)`""
    ) -Verb RunAs -Wait
    return @{ Ok = $true; Message = "Undo script execution returned." }
}

function Invoke-Action-RunUndoPostHardening {
    $h = Get-HardeningState
    if (-not $h) { return @{ Ok = $false; Message = "No hardening log folder found." } }
    $script = Join-Path $script:ScriptRoot "Undo-PostHardening.ps1"
    if (-not (Test-Path $script)) {
        return @{ Ok = $false; Message = "Undo-PostHardening.ps1 not found." }
    }
    Start-Process powershell.exe -ArgumentList @(
        '-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$script`"",
        '-LogFolderPath',"`"$($h.Folder)`"",
        '-All'
    ) -Verb RunAs -Wait
    return @{ Ok = $true; Message = "Post-hardening rollback returned." }
}

# ---------- RustDesk ----------
function Invoke-Action-InstallRustDesk {
    param(
        [ValidateSet('Public','SelfHosted')][string]$Mode = 'Public',
        [string]$Server = $null,
        [string]$Key = $null
    )
    if (-not (Get-HardeningState)) {
        return @{ Ok = $false; Message = "No hardening log folder; run hardening first." }
    }

    # Pre-flight: detect existing install
    $info = Get-RustDeskInstallInfo
    $skipInstall = $info.Installed
    $installer = $null
    if (-not $skipInstall) {
        $installer = Find-FileByPatterns -Patterns @($script:Config.RustDeskMsiPattern, $script:Config.RustDeskInstallerPattern)
        if (-not $installer) {
            return @{ Ok = $false; Message = "RustDesk installer not found on USB (looked for $($script:Config.RustDeskMsiPattern), $($script:Config.RustDeskInstallerPattern))." }
        }
    } else {
        Write-ConsoleLog "RustDesk already installed at $($info.InstallPath); refreshing config/firewall/exclusions"
    }

    # Self-hosted config resolution (server/key from form, then USB files)
    if ($Mode -eq 'SelfHosted') {
        if (-not $Server) {
            $serverFile = Join-Path $script:ScriptRoot $script:Config.RustDeskServerFile
            if (Test-Path $serverFile) { $Server = (Get-Content $serverFile -Raw -Encoding UTF8).Trim() }
        }
        if (-not $Key) {
            $keyFile = Join-Path $script:ScriptRoot $script:Config.RustDeskKeyFile
            if (Test-Path $keyFile) { $Key = (Get-Content $keyFile -Raw -Encoding UTF8).Trim() }
        }
        if (-not $Server) {
            return @{ Ok = $false; Message = "Self-hosted selected but no server address provided (expected $($script:Config.RustDeskServerFile) on USB or value in form)." }
        }
    }

    try {
        # ---- Run installer if needed ----
        if (-not $skipInstall) {
            Write-ConsoleLog "RustDesk install starting from $installer (mode=$Mode)"
            $ext = [System.IO.Path]::GetExtension($installer).ToLower()
            $proc = Invoke-WithMsiAllowed {
                if ($ext -eq '.msi') {
                    Start-Process msiexec -ArgumentList @('/i', "`"$installer`"", '/qn', '/norestart') -Wait -PassThru
                } else {
                    Start-Process -FilePath $installer -ArgumentList '--silent-install' -Wait -PassThru
                }
            }
            $code = if ($proc) { $proc.ExitCode } else { -1 }
            # 0 = success, 3010 = success + reboot pending (msiexec)
            if ($code -notin @(0, 3010)) {
                Write-ConsoleLog "[ERROR] RustDesk installer exit code $code" 'ERROR'
                return @{ Ok = $false; Message = "RustDesk installer exited with code $code. Install failed." }
            }

            # Wait for the rustdesk service to appear (up to 60s)
            if (-not (Wait-ServicePresent -ServicePattern 'rustdesk*' -TimeoutSeconds 60)) {
                Write-ConsoleLog "[ERROR] RustDesk service did not appear within 60 seconds after install" 'ERROR'
                return @{ Ok = $false; Message = "RustDesk installer returned $code but the service did not appear. Install incomplete." }
            }
            Start-Sleep -Seconds 2
            $info = Get-RustDeskInstallInfo
            if (-not $info.ExePath) {
                Write-ConsoleLog "[ERROR] RustDesk service is present but rustdesk.exe could not be located" 'ERROR'
                return @{ Ok = $false; Message = "RustDesk service is present but rustdesk.exe was not found in any known location." }
            }
            Write-ConsoleLog "RustDesk install verified. ExePath=$($info.ExePath) Service=$($info.ServiceName)/$($info.ServiceStatus)"
        }

        # ---- Self-hosted config (user + service config), then service restart, then verify ----
        $configVerified = $false
        if ($Mode -eq 'SelfHosted') {
            $rustdeskExe = $info.ExePath
            if (-not $rustdeskExe -or -not (Test-Path $rustdeskExe)) {
                return @{ Ok = $false; Message = "RustDesk binary not found; cannot apply self-hosted config." }
            }
            # Apply via the CLI option (writes user-mode config)
            Start-Process -FilePath $rustdeskExe -ArgumentList @('--option','custom-rendezvous-server',$Server) -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue
            if ($Key) {
                Start-Process -FilePath $rustdeskExe -ArgumentList @('--option','key',$Key) -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue
            }
            # Restart the RustDesk service so the service-side config also picks up
            if ($info.ServiceName) {
                Restart-Service -Name $info.ServiceName -Force -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 3
            }
            # Verify by reading the config back.
            # RustDesk has no --get-option; the single-arg form 'rustdesk --option <name>'
            # prints the current value via println!. The rustdesk binary is built for the
            # Windows subsystem (GUI) so stdout is not attached to the parent PowerShell
            # console; redirect it to a temp file via Start-Process -RedirectStandardOutput.
            try {
                $tmpOut = [System.IO.Path]::GetTempFileName()
                try {
                    Start-Process -FilePath $rustdeskExe `
                                  -ArgumentList @('--option','custom-rendezvous-server') `
                                  -Wait -WindowStyle Hidden `
                                  -RedirectStandardOutput $tmpOut `
                                  -ErrorAction SilentlyContinue | Out-Null
                    $reported = (Get-Content -Path $tmpOut -Raw -ErrorAction SilentlyContinue) -as [string]
                    if ($reported) { $reported = $reported.Trim() }
                } finally {
                    Remove-Item -Path $tmpOut -Force -ErrorAction SilentlyContinue
                }
                if ($reported -and $reported -eq $Server) {
                    $configVerified = $true
                    Write-ConsoleLog "RustDesk self-hosted config verified: $Server"
                } else {
                    Write-ConsoleLog "[WARN] RustDesk read-back returned '$reported'; expected '$Server'. The service-side config may need a custom-built installer from rustdesk.com." 'WARN'
                }
            } catch {
                Write-ConsoleLog "[WARN] Could not verify RustDesk config: $_" 'WARN'
            }
        }

        # ---- Firewall rules ----
        $ruleNames = @()
        foreach ($r in $script:Config.RustDeskClientPorts) {
            Add-OutboundAllowRule -Name $r.Name -Protocol $r.Protocol -RemotePort $r.Port
            $ruleNames += $r.Name
        }

        # ---- Defender exclusion ----
        $exclusionPath = if ($info.InstallPath) { $info.InstallPath } else { $script:Config.RustDeskInstallDir }
        $defAdded = $false
        if (Test-Path $exclusionPath) {
            Add-MpPreference -AttackSurfaceReductionOnlyExclusions $exclusionPath -ErrorAction SilentlyContinue
            $defAdded = $true
            Write-ConsoleLog "Defender ASR exclusion added: $exclusionPath"
        }

        # ---- Record verified state ----
        Update-PostHardeningState {
            param($ph)
            $ph.RustDesk = [PSCustomObject]@{
                Installed          = $true
                Mode               = $Mode
                Server             = $Server
                ConfigVerified     = $configVerified
                InstallerPath      = $installer
                InstallPath        = $info.InstallPath
                ExePath            = $info.ExePath
                ServiceName        = $info.ServiceName
                ServiceStatus      = $info.ServiceStatus
                FirewallRules      = $ruleNames
                DefenderExclusions = if ($defAdded) { @($exclusionPath) } else { @() }
                Timestamp          = (Get-Date -Format 'o')
            }
        } | Out-Null

        $note = ''
        if ($Mode -eq 'SelfHosted' -and -not $configVerified) {
            $note = ' WARNING: self-hosted config could not be read back; the service may still use public relays. Consider a custom-built installer from rustdesk.com for guaranteed service-side config.'
        }
        $svcText = if ($info.ServiceName) { "$($info.ServiceName)/$($info.ServiceStatus)" } else { 'no service detected' }
        return @{ Ok = $true; Message = "RustDesk installed ($Mode). Service: $svcText. Firewall + Defender exclusions applied.$note" }
    } catch {
        Write-ConsoleLog "[ERROR] RustDesk install failed: $_" 'ERROR'
        return @{ Ok = $false; Message = "RustDesk install failed: $($_.Exception.Message)" }
    }
}

function Invoke-Action-UninstallRustDesk {
    $h = Get-HardeningState
    if (-not $h) { return @{ Ok = $false; Message = "No hardening log folder found." } }

    try {
        $rdState = $h.State.PostHardening.RustDesk
        $info = Get-RustDeskInstallInfo

        $uninstalled = $false
        $exitCode = -1
        $msiExitOk = @(0, 1605, 3010)   # 0=ok, 1605=product not installed, 3010=reboot pending

        # 1. If we recorded an MSI installer path in state, try that (msiexec /x)
        if ($rdState -and $rdState.InstallerPath -and (Test-Path $rdState.InstallerPath) -and ($rdState.InstallerPath -like '*.msi')) {
            $proc = Invoke-WithMsiAllowed {
                Start-Process msiexec -ArgumentList @('/x', "`"$($rdState.InstallerPath)`"", '/qn', '/norestart') -Wait -PassThru
            }
            $exitCode = if ($proc) { $proc.ExitCode } else { -1 }
            $uninstalled = ($exitCode -in $msiExitOk)
        }
        # 2. RustDesk's official Windows uninstall path: 'rustdesk.exe --uninstall'.
        #    There is NO standalone uninstaller exe (no unins000.exe, no Uninstall.exe).
        #    The --uninstall switch runs an internal batch that removes the service,
        #    deletes files, and clears the registry. It is itself silent.
        if (-not $uninstalled -and $info.ExePath) {
            $proc = Start-Process -FilePath $info.ExePath -ArgumentList '--uninstall' -Wait -PassThru -WindowStyle Hidden
            $exitCode = if ($proc) { $proc.ExitCode } else { -1 }
            $uninstalled = ($exitCode -eq 0)
        }
        # 3. Last resort: registry's UninstallString (which is typically just
        #    "...rustdesk.exe" --uninstall but may differ on custom builds).
        if (-not $uninstalled) {
            $u = Get-UninstallEntry -DisplayNamePattern 'RustDesk*'
            if ($u -and ($u.QuietUninstallString -or $u.UninstallString)) {
                $cmdStr = if ($u.QuietUninstallString) { $u.QuietUninstallString } else { $u.UninstallString }
                if ($cmdStr -match 'msiexec' -and $cmdStr -match '({[A-F0-9-]+})') {
                    $guid = $Matches[1]
                    $proc = Invoke-WithMsiAllowed { Start-Process msiexec -ArgumentList @('/x',$guid,'/qn','/norestart') -Wait -PassThru }
                    $exitCode = if ($proc) { $proc.ExitCode } else { -1 }
                    $uninstalled = ($exitCode -in $msiExitOk)
                } else {
                    $proc = Start-Process cmd -ArgumentList @('/c', $cmdStr) -Wait -PassThru -WindowStyle Hidden
                    $exitCode = if ($proc) { $proc.ExitCode } else { -1 }
                    $uninstalled = ($exitCode -eq 0)
                }
            }
        }

        # Wait for the rustdesk service to disappear (up to 30s)
        $serviceGone = $true
        if ($info.ServiceName) {
            $serviceGone = Wait-ServiceAbsent -ServicePattern $info.ServiceName -TimeoutSeconds 30
            if (-not $serviceGone) {
                Write-ConsoleLog "[WARN] RustDesk uninstaller returned but '$($info.ServiceName)' service is still present after 30s" 'WARN'
            }
        }

        # Cleanup firewall + Defender exclusions regardless
        $names = if ($rdState -and $rdState.FirewallRules) { $rdState.FirewallRules } else { $script:Config.RustDeskClientPorts | ForEach-Object { $_.Name } }
        foreach ($n in $names) { Remove-OutboundAllowRule -Name $n }
        if ($rdState -and $rdState.DefenderExclusions) {
            foreach ($p in $rdState.DefenderExclusions) {
                Remove-MpPreference -AttackSurfaceReductionOnlyExclusions $p -ErrorAction SilentlyContinue
                Write-ConsoleLog "Defender ASR exclusion removed: $p"
            }
        }

        Update-PostHardeningState {
            param($ph)
            $ph.RustDesk = $null
        } | Out-Null

        if ($uninstalled -and $serviceGone) {
            return @{ Ok = $true; Message = "RustDesk uninstalled (exit $exitCode). Firewall + Defender exclusions cleared." }
        } elseif ($uninstalled) {
            return @{ Ok = $true; Message = "RustDesk uninstalled (exit $exitCode) but service is still present. May need a reboot. Firewall + Defender cleared." }
        } else {
            return @{ Ok = $false; Message = "RustDesk uninstall did not complete cleanly (exit $exitCode). Firewall + Defender cleaned anyway." }
        }
    } catch {
        return @{ Ok = $false; Message = "RustDesk uninstall failed: $($_.Exception.Message)" }
    }
}

# ---------- Tailscale ----------
function Invoke-Action-InstallTailscale {
    if (-not (Get-HardeningState)) {
        return @{ Ok = $false; Message = "No hardening log folder; run hardening first." }
    }
    $installer = Find-FileByPatterns -Patterns @($script:Config.TailscaleMsiPattern, $script:Config.TailscaleInstallerPattern)
    if (-not $installer) {
        return @{ Ok = $false; Message = "Tailscale installer not found on USB." }
    }
    try {
        Write-ConsoleLog "Tailscale install starting from $installer"
        $ext = [System.IO.Path]::GetExtension($installer).ToLower()
        $proc = Invoke-WithMsiAllowed {
            if ($ext -eq '.msi') {
                Start-Process msiexec -ArgumentList @('/i', "`"$installer`"", '/qn', '/norestart') -Wait -PassThru
            } else {
                Start-Process -FilePath $installer -ArgumentList '/S' -Wait -PassThru
            }
        }
        $code = if ($proc) { $proc.ExitCode } else { -1 }
        if ($code -notin @(0, 3010)) {
            Write-ConsoleLog "[ERROR] Tailscale installer exit code $code" 'ERROR'
            return @{ Ok = $false; Message = "Tailscale installer exited with code $code. Install failed." }
        }

        # Wait for the Tailscale service to appear
        if (-not (Wait-ServicePresent -ServicePattern 'Tailscale*' -TimeoutSeconds 60)) {
            return @{ Ok = $false; Message = "Tailscale installer returned $code but the service did not appear. Install incomplete." }
        }
        Start-Sleep -Seconds 2

        $exePath = Join-Path $script:Config.TailscaleInstallDir 'tailscale.exe'
        if (-not (Test-Path $exePath)) {
            return @{ Ok = $false; Message = "Tailscale service is present but tailscale.exe was not found at $exePath." }
        }
        $svc = Get-Service -Name 'Tailscale*' -ErrorAction SilentlyContinue | Select-Object -First 1
        Write-ConsoleLog "Tailscale install verified. ExePath=$exePath Service=$($svc.Name)/$($svc.Status)"

        # Firewall: outbound UDP 41641 for direct connections
        $ruleName = 'Tailscale-Direct-UDP'
        Add-OutboundAllowRule -Name $ruleName -Protocol UDP -RemotePort $script:Config.TailscalePortUDP

        # Defender exclusion
        $exclusionPath = $script:Config.TailscaleInstallDir
        $defAdded = $false
        if (Test-Path $exclusionPath) {
            Add-MpPreference -AttackSurfaceReductionOnlyExclusions $exclusionPath -ErrorAction SilentlyContinue
            $defAdded = $true
            Write-ConsoleLog "Defender ASR exclusion added: $exclusionPath"
        }

        Update-PostHardeningState {
            param($ph)
            $ph.Tailscale = [PSCustomObject]@{
                Installed          = $true
                InstallerPath      = $installer
                ExePath            = $exePath
                ServiceName        = if ($svc) { $svc.Name } else { $null }
                ServiceStatus      = if ($svc) { $svc.Status.ToString() } else { $null }
                FirewallRules      = @($ruleName)
                DefenderExclusions = if ($defAdded) { @($exclusionPath) } else { @() }
                Timestamp          = (Get-Date -Format 'o')
            }
        } | Out-Null

        return @{ Ok = $true; Message = "Tailscale installed. Service: $($svc.Name)/$($svc.Status). Click 'Login' to authenticate via browser." }
    } catch {
        Write-ConsoleLog "[ERROR] Tailscale install failed: $_" 'ERROR'
        return @{ Ok = $false; Message = "Tailscale install failed: $($_.Exception.Message)" }
    }
}

function Invoke-Action-LoginTailscale {
    $exe = Join-Path $script:Config.TailscaleInstallDir 'tailscale.exe'
    if (-not (Test-Path $exe)) {
        return @{ Ok = $false; Message = "Tailscale not installed (tailscale.exe not found)." }
    }
    # Open a visible console so the user sees the auth URL printed by 'tailscale up'
    Start-Process cmd -ArgumentList @('/k', "`"$exe`" up") -WindowStyle Normal
    Write-ConsoleLog "Tailscale login window launched"
    return @{ Ok = $true; Message = "Tailscale login window opened. Follow the URL in your browser." }
}

function Invoke-Action-UninstallTailscale {
    $h = Get-HardeningState
    if (-not $h) { return @{ Ok = $false; Message = "No hardening log folder found." } }

    try {
        $tsState = $h.State.PostHardening.Tailscale

        # Logout first if installed (best-effort)
        $exe = Join-Path $script:Config.TailscaleInstallDir 'tailscale.exe'
        if (Test-Path $exe) {
            Start-Process -FilePath $exe -ArgumentList 'logout' -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue
        }

        $uninstalled = $false
        if ($tsState -and $tsState.InstallerPath -and (Test-Path $tsState.InstallerPath) -and ($tsState.InstallerPath -like '*.msi')) {
            Invoke-WithMsiAllowed {
                Start-Process msiexec -ArgumentList @('/x', "`"$($tsState.InstallerPath)`"", '/qn', '/norestart') -Wait
            }
            $uninstalled = $true
        } else {
            $u = Get-UninstallEntry -DisplayNamePattern 'Tailscale*'
            if ($u) {
                if ($u.QuietUninstallString) {
                    Start-Process cmd -ArgumentList @('/c', $u.QuietUninstallString) -Wait
                    $uninstalled = $true
                } elseif ($u.UninstallString) {
                    $cmd = $u.UninstallString
                    if ($cmd -match 'msiexec' -and $cmd -match '({[A-F0-9-]+})') {
                        $guid = $Matches[1]
                        Invoke-WithMsiAllowed { Start-Process msiexec -ArgumentList @('/x',$guid,'/qn','/norestart') -Wait }
                    } else {
                        Start-Process cmd -ArgumentList @('/c', "$cmd /S") -Wait
                    }
                    $uninstalled = $true
                }
            }
        }

        # Remove firewall rules
        $names = if ($tsState -and $tsState.FirewallRules) { $tsState.FirewallRules } else { @('Tailscale-Direct-UDP') }
        foreach ($n in $names) { Remove-OutboundAllowRule -Name $n }

        # Remove Defender exclusions
        if ($tsState -and $tsState.DefenderExclusions) {
            foreach ($p in $tsState.DefenderExclusions) {
                Remove-MpPreference -AttackSurfaceReductionOnlyExclusions $p -ErrorAction SilentlyContinue
                Write-ConsoleLog "Defender ASR exclusion removed: $p"
            }
        }

        Update-PostHardeningState {
            param($ph)
            $ph.Tailscale = $null
        } | Out-Null

        if ($uninstalled) {
            return @{ Ok = $true; Message = "Tailscale uninstalled. Firewall + Defender exclusions cleared." }
        } else {
            return @{ Ok = $false; Message = "Tailscale uninstaller not found. Cleanup of firewall + Defender done." }
        }
    } catch {
        return @{ Ok = $false; Message = "Tailscale uninstall failed: $($_.Exception.Message)" }
    }
}

# ---------- RDP ----------
function Invoke-Action-EnableRdp {
    if (-not (Get-HardeningState)) {
        return @{ Ok = $false; Message = "No hardening log folder; run hardening first." }
    }
    try {
        Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0 -Type DWord -Force
        Set-Service -Name 'TermService' -StartupType Automatic -ErrorAction SilentlyContinue
        Start-Service -Name 'TermService' -ErrorAction SilentlyContinue
        Get-NetFirewallRule -DisplayName "*Remote Desktop*" -ErrorAction SilentlyContinue | Enable-NetFirewallRule -ErrorAction SilentlyContinue
        Write-ConsoleLog "RDP re-enabled (TermService started, firewall rules enabled)"

        Update-PostHardeningState {
            param($ph)
            $ph.RdpReenabled = $true
        } | Out-Null

        return @{ Ok = $true; Message = "RDP re-enabled. TermService running, firewall rules active." }
    } catch {
        return @{ Ok = $false; Message = "RDP enable failed: $($_.Exception.Message)" }
    }
}

function Invoke-Action-DisableRdp {
    try {
        Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1 -Type DWord -Force
        Stop-Service -Name 'TermService' -Force -ErrorAction SilentlyContinue
        Get-NetFirewallRule -DisplayName "*Remote Desktop*" -ErrorAction SilentlyContinue | Disable-NetFirewallRule -ErrorAction SilentlyContinue
        Write-ConsoleLog "RDP disabled (TermService stopped, firewall rules disabled)"

        Update-PostHardeningState {
            param($ph)
            $ph.RdpReenabled = $false
        } | Out-Null

        return @{ Ok = $true; Message = "RDP disabled. TermService stopped, firewall rules disabled." }
    } catch {
        return @{ Ok = $false; Message = "RDP disable failed: $($_.Exception.Message)" }
    }
}

# ---------- Defender Exclusions ----------
function Invoke-Action-AddDefenderExclusion {
    param([Parameter(Mandatory=$true)][string]$Path)
    if (-not (Get-HardeningState)) {
        return @{ Ok = $false; Message = "No hardening log folder; run hardening first." }
    }
    if (-not (Test-Path $Path)) {
        return @{ Ok = $false; Message = "Path does not exist: $Path" }
    }
    try {
        Add-MpPreference -AttackSurfaceReductionOnlyExclusions $Path -ErrorAction Stop
        $isExe = $Path -like '*.exe'
        if ($isExe) {
            Add-MpPreference -ControlledFolderAccessAllowedApplications $Path -ErrorAction Stop
        }
        Write-ConsoleLog "Defender exclusion ADDED: $Path (CFA=$isExe)"

        Update-PostHardeningState {
            param($ph)
            $entry = [PSCustomObject]@{
                Path      = $Path
                ASR       = $true
                CFA       = $isExe
                Timestamp = (Get-Date -Format 'o')
            }
            # Wrap pipeline in @() so $kept is always a real array (avoids $null leaking in)
            $kept = @($ph.DefenderExclusionsAdded | Where-Object { $_ -and $_.Path -ne $Path })
            $ph.DefenderExclusionsAdded = $kept + $entry
        } | Out-Null

        return @{ Ok = $true; Message = "Exclusion added: $Path" }
    } catch {
        return @{ Ok = $false; Message = "Add exclusion failed: $($_.Exception.Message)" }
    }
}

function Invoke-Action-RemoveDefenderExclusion {
    param([Parameter(Mandatory=$true)][string]$Path)
    try {
        Remove-MpPreference -AttackSurfaceReductionOnlyExclusions $Path -ErrorAction SilentlyContinue
        if ($Path -like '*.exe') {
            Remove-MpPreference -ControlledFolderAccessAllowedApplications $Path -ErrorAction SilentlyContinue
        }
        Write-ConsoleLog "Defender exclusion REMOVED: $Path"

        Update-PostHardeningState {
            param($ph)
            $ph.DefenderExclusionsAdded = @(@($ph.DefenderExclusionsAdded) | Where-Object { $_ -and $_.Path -ne $Path })
        } | Out-Null

        return @{ Ok = $true; Message = "Exclusion removed: $Path" }
    } catch {
        return @{ Ok = $false; Message = "Remove exclusion failed: $($_.Exception.Message)" }
    }
}

# ---------- Custom Firewall Rules ----------
function Invoke-Action-AddCustomFirewallRule {
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][ValidateSet('TCP','UDP')][string]$Protocol,
        [Parameter(Mandatory=$true)][string]$Port
    )
    if (-not (Get-HardeningState)) {
        return @{ Ok = $false; Message = "No hardening log folder; run hardening first." }
    }
    if (Test-FirewallRuleExists -Name $Name) {
        return @{ Ok = $false; Message = "A firewall rule named '$Name' already exists." }
    }
    try {
        Add-OutboundAllowRule -Name $Name -Protocol $Protocol -RemotePort $Port

        Update-PostHardeningState {
            param($ph)
            $entry = [PSCustomObject]@{
                Name      = $Name
                Protocol  = $Protocol
                Port      = $Port
                Timestamp = (Get-Date -Format 'o')
            }
            # Defensive: keep $kept guaranteed-array even if state somehow has $null
            $kept = @($ph.CustomFirewallRules | Where-Object { $_ -and $_.Name })
            $ph.CustomFirewallRules = $kept + $entry
        } | Out-Null

        return @{ Ok = $true; Message = "Firewall rule added: $Name ($Protocol/$Port outbound)" }
    } catch {
        return @{ Ok = $false; Message = "Add firewall rule failed: $($_.Exception.Message)" }
    }
}

function Invoke-Action-RemoveCustomFirewallRule {
    param([Parameter(Mandatory=$true)][string]$Name)
    try {
        Remove-OutboundAllowRule -Name $Name

        Update-PostHardeningState {
            param($ph)
            $ph.CustomFirewallRules = @(@($ph.CustomFirewallRules) | Where-Object { $_ -and $_.Name -ne $Name })
        } | Out-Null

        return @{ Ok = $true; Message = "Firewall rule removed: $Name" }
    } catch {
        return @{ Ok = $false; Message = "Remove firewall rule failed: $($_.Exception.Message)" }
    }
}

#===========================================================================
# =================== UI BUILDERS ===========================================
#===========================================================================

function New-StatusLabel {
    param([int]$X, [int]$Y, [int]$Width = 460)
    $lbl = New-Object System.Windows.Forms.Label
    $lbl.Location = New-Object System.Drawing.Point($X, $Y)
    $lbl.Size = New-Object System.Drawing.Size($Width, 40)
    $lbl.Text = "Status: Ready."
    $lbl.ForeColor = [System.Drawing.Color]::DimGray
    $lbl.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    return $lbl
}

function Set-StatusLabel {
    param(
        [System.Windows.Forms.Label]$Label,
        [string]$Text,
        [ValidateSet('Info','Working','Ok','Warn','Error')][string]$Tone = 'Info'
    )
    $Label.Text = "Status: $Text"
    switch ($Tone) {
        'Info'    { $Label.ForeColor = [System.Drawing.Color]::DimGray }
        'Working' { $Label.ForeColor = [System.Drawing.Color]::Blue }
        'Ok'      { $Label.ForeColor = [System.Drawing.Color]::DarkGreen }
        'Warn'    { $Label.ForeColor = [System.Drawing.Color]::DarkOrange }
        'Error'   { $Label.ForeColor = [System.Drawing.Color]::Red }
    }
}

function New-HardeningTab {
    $tab = New-Object System.Windows.Forms.TabPage
    $tab.Text = "Hardening"

    $info = New-Object System.Windows.Forms.Label
    $info.Location = New-Object System.Drawing.Point(15, 15)
    $info.Size = New-Object System.Drawing.Size(620, 40)
    $info.Text = "Run the unified hardening script, periodic audits, or the rollback. The console will operate on the most recent HARDENING-* folder found on this drive."
    $tab.Controls.Add($info)

    $btnRun = New-Object System.Windows.Forms.Button
    $btnRun.Location = New-Object System.Drawing.Point(15, 70)
    $btnRun.Size = New-Object System.Drawing.Size(305, 42)
    $btnRun.Text = "Run Hardening"
    $btnRun.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $btnRun.BackColor = [System.Drawing.Color]::LightSteelBlue
    $tab.Controls.Add($btnRun)

    $btnAudit = New-Object System.Windows.Forms.Button
    $btnAudit.Location = New-Object System.Drawing.Point(330, 70)
    $btnAudit.Size = New-Object System.Drawing.Size(305, 42)
    $btnAudit.Text = "Run Audit Only"
    $btnAudit.Font = New-Object System.Drawing.Font("Segoe UI", 10)
    $tab.Controls.Add($btnAudit)

    $btnUndoPost = New-Object System.Windows.Forms.Button
    $btnUndoPost.Location = New-Object System.Drawing.Point(15, 120)
    $btnUndoPost.Size = New-Object System.Drawing.Size(305, 42)
    $btnUndoPost.Text = "Undo Post-Hardening (RustDesk/TS/RDP/etc)"
    $btnUndoPost.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $btnUndoPost.BackColor = [System.Drawing.Color]::Wheat
    $tab.Controls.Add($btnUndoPost)

    $btnUndo = New-Object System.Windows.Forms.Button
    $btnUndo.Location = New-Object System.Drawing.Point(330, 120)
    $btnUndo.Size = New-Object System.Drawing.Size(305, 42)
    $btnUndo.Text = "Undo Hardening (base rollback)"
    $btnUndo.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $btnUndo.BackColor = [System.Drawing.Color]::MistyRose
    $tab.Controls.Add($btnUndo)

    $status = New-StatusLabel -X 15 -Y 180 -Width 620
    $tab.Controls.Add($status)

    $btnRun.Add_Click({
        Set-StatusLabel $status "Launching hardening script (elevated window opens)..." Working
        $form.Update()
        $r = Invoke-Action-RunHardening
        if ($r.Ok) { Set-StatusLabel $status $r.Message Ok } else { Set-StatusLabel $status $r.Message Error }
    }.GetNewClosure())

    $btnAudit.Add_Click({
        Set-StatusLabel $status "Launching audit script..." Working
        $form.Update()
        $r = Invoke-Action-RunAudit
        if ($r.Ok) { Set-StatusLabel $status $r.Message Ok } else { Set-StatusLabel $status $r.Message Error }
    }.GetNewClosure())

    $btnUndoPost.Add_Click({
        Set-StatusLabel $status "Rolling back post-hardening changes..." Working
        $form.Update()
        $r = Invoke-Action-RunUndoPostHardening
        if ($r.Ok) { Set-StatusLabel $status $r.Message Ok } else { Set-StatusLabel $status $r.Message Error }
    }.GetNewClosure())

    $btnUndo.Add_Click({
        Set-StatusLabel $status "Launching undo (base) script - interactive menu in new window..." Working
        $form.Update()
        $r = Invoke-Action-RunUndo
        if ($r.Ok) { Set-StatusLabel $status $r.Message Ok } else { Set-StatusLabel $status $r.Message Error }
    }.GetNewClosure())

    return $tab
}

function New-RemoteAccessTab {
    $tab = New-Object System.Windows.Forms.TabPage
    $tab.Text = "Remote Access"

    # ----- RustDesk groupbox -----
    $gbR = New-Object System.Windows.Forms.GroupBox
    $gbR.Location = New-Object System.Drawing.Point(10, 10)
    $gbR.Size = New-Object System.Drawing.Size(645, 155)
    $gbR.Text = "RustDesk"
    $tab.Controls.Add($gbR)

    $rdPublic = New-Object System.Windows.Forms.RadioButton
    $rdPublic.Location = New-Object System.Drawing.Point(15, 25)
    $rdPublic.Size = New-Object System.Drawing.Size(150, 22)
    $rdPublic.Text = "Public relays"
    $rdPublic.Checked = $true
    $gbR.Controls.Add($rdPublic)

    $rdSelf = New-Object System.Windows.Forms.RadioButton
    $rdSelf.Location = New-Object System.Drawing.Point(15, 50)
    $rdSelf.Size = New-Object System.Drawing.Size(150, 22)
    $rdSelf.Text = "Self-hosted server"
    $gbR.Controls.Add($rdSelf)

    $lblSrv = New-Object System.Windows.Forms.Label
    $lblSrv.Location = New-Object System.Drawing.Point(180, 28)
    $lblSrv.Size = New-Object System.Drawing.Size(140, 20)
    $lblSrv.Text = "Server (host:port):"
    $gbR.Controls.Add($lblSrv)

    $tbSrv = New-Object System.Windows.Forms.TextBox
    $tbSrv.Location = New-Object System.Drawing.Point(320, 25)
    $tbSrv.Size = New-Object System.Drawing.Size(310, 22)
    $tbSrv.Enabled = $false
    $gbR.Controls.Add($tbSrv)

    $lblKey = New-Object System.Windows.Forms.Label
    $lblKey.Location = New-Object System.Drawing.Point(180, 55)
    $lblKey.Size = New-Object System.Drawing.Size(140, 20)
    $lblKey.Text = "Key (optional):"
    $gbR.Controls.Add($lblKey)

    $tbKey = New-Object System.Windows.Forms.TextBox
    $tbKey.Location = New-Object System.Drawing.Point(320, 52)
    $tbKey.Size = New-Object System.Drawing.Size(310, 22)
    $tbKey.Enabled = $false
    $gbR.Controls.Add($tbKey)

    $rdPublic.Add_CheckedChanged({
        if ($rdPublic.Checked) { $tbSrv.Enabled = $false; $tbKey.Enabled = $false }
    }.GetNewClosure())
    $rdSelf.Add_CheckedChanged({
        if ($rdSelf.Checked) {
            $tbSrv.Enabled = $true
            $tbKey.Enabled = $true
            # Pre-fill from USB files if present
            $serverFile = Join-Path $script:ScriptRoot $script:Config.RustDeskServerFile
            $keyFile = Join-Path $script:ScriptRoot $script:Config.RustDeskKeyFile
            if ((Test-Path $serverFile) -and -not $tbSrv.Text) {
                $tbSrv.Text = (Get-Content $serverFile -Raw -Encoding UTF8).Trim()
            }
            if ((Test-Path $keyFile) -and -not $tbKey.Text) {
                $tbKey.Text = (Get-Content $keyFile -Raw -Encoding UTF8).Trim()
            }
        }
    }.GetNewClosure())

    $btnRInstall = New-Object System.Windows.Forms.Button
    $btnRInstall.Location = New-Object System.Drawing.Point(15, 85)
    $btnRInstall.Size = New-Object System.Drawing.Size(120, 28)
    $btnRInstall.Text = "Install RustDesk"
    $btnRInstall.BackColor = [System.Drawing.Color]::LightGreen
    $gbR.Controls.Add($btnRInstall)

    $btnRUninstall = New-Object System.Windows.Forms.Button
    $btnRUninstall.Location = New-Object System.Drawing.Point(145, 85)
    $btnRUninstall.Size = New-Object System.Drawing.Size(120, 28)
    $btnRUninstall.Text = "Uninstall"
    $btnRUninstall.BackColor = [System.Drawing.Color]::LightCoral
    $gbR.Controls.Add($btnRUninstall)

    $statusR = New-StatusLabel -X 15 -Y 120 -Width 620
    $gbR.Controls.Add($statusR)

    $btnRInstall.Add_Click({
        Set-StatusLabel $statusR "Installing RustDesk..." Working
        $form.Update()
        $mode = if ($rdSelf.Checked) { 'SelfHosted' } else { 'Public' }
        $r = Invoke-Action-InstallRustDesk -Mode $mode -Server $tbSrv.Text -Key $tbKey.Text
        if ($r.Ok) { Set-StatusLabel $statusR $r.Message Ok } else { Set-StatusLabel $statusR $r.Message Error }
    }.GetNewClosure())

    $btnRUninstall.Add_Click({
        Set-StatusLabel $statusR "Uninstalling RustDesk..." Working
        $form.Update()
        $r = Invoke-Action-UninstallRustDesk
        if ($r.Ok) { Set-StatusLabel $statusR $r.Message Ok } else { Set-StatusLabel $statusR $r.Message Error }
    }.GetNewClosure())

    # ----- Tailscale groupbox -----
    $gbT = New-Object System.Windows.Forms.GroupBox
    $gbT.Location = New-Object System.Drawing.Point(10, 175)
    $gbT.Size = New-Object System.Drawing.Size(645, 100)
    $gbT.Text = "Tailscale"
    $tab.Controls.Add($gbT)

    $btnTInstall = New-Object System.Windows.Forms.Button
    $btnTInstall.Location = New-Object System.Drawing.Point(15, 25)
    $btnTInstall.Size = New-Object System.Drawing.Size(120, 28)
    $btnTInstall.Text = "Install Tailscale"
    $btnTInstall.BackColor = [System.Drawing.Color]::LightGreen
    $gbT.Controls.Add($btnTInstall)

    $btnTLogin = New-Object System.Windows.Forms.Button
    $btnTLogin.Location = New-Object System.Drawing.Point(145, 25)
    $btnTLogin.Size = New-Object System.Drawing.Size(120, 28)
    $btnTLogin.Text = "Login (browser)"
    $gbT.Controls.Add($btnTLogin)

    $btnTUninstall = New-Object System.Windows.Forms.Button
    $btnTUninstall.Location = New-Object System.Drawing.Point(275, 25)
    $btnTUninstall.Size = New-Object System.Drawing.Size(120, 28)
    $btnTUninstall.Text = "Uninstall"
    $btnTUninstall.BackColor = [System.Drawing.Color]::LightCoral
    $gbT.Controls.Add($btnTUninstall)

    $statusT = New-StatusLabel -X 15 -Y 60 -Width 620
    $gbT.Controls.Add($statusT)

    $btnTInstall.Add_Click({
        Set-StatusLabel $statusT "Installing Tailscale..." Working
        $form.Update()
        $r = Invoke-Action-InstallTailscale
        if ($r.Ok) { Set-StatusLabel $statusT $r.Message Ok } else { Set-StatusLabel $statusT $r.Message Error }
    }.GetNewClosure())

    $btnTLogin.Add_Click({
        Set-StatusLabel $statusT "Launching Tailscale login..." Working
        $form.Update()
        $r = Invoke-Action-LoginTailscale
        if ($r.Ok) { Set-StatusLabel $statusT $r.Message Ok } else { Set-StatusLabel $statusT $r.Message Error }
    }.GetNewClosure())

    $btnTUninstall.Add_Click({
        Set-StatusLabel $statusT "Uninstalling Tailscale..." Working
        $form.Update()
        $r = Invoke-Action-UninstallTailscale
        if ($r.Ok) { Set-StatusLabel $statusT $r.Message Ok } else { Set-StatusLabel $statusT $r.Message Error }
    }.GetNewClosure())

    # ----- RDP groupbox -----
    $gbD = New-Object System.Windows.Forms.GroupBox
    $gbD.Location = New-Object System.Drawing.Point(10, 285)
    $gbD.Size = New-Object System.Drawing.Size(645, 100)
    $gbD.Text = "Remote Desktop (RDP)"
    $tab.Controls.Add($gbD)

    $lblWarn = New-Object System.Windows.Forms.Label
    $lblWarn.Location = New-Object System.Drawing.Point(15, 22)
    $lblWarn.Size = New-Object System.Drawing.Size(620, 18)
    $lblWarn.Text = "Re-enabling RDP reduces the hardened posture. Use only when required."
    $lblWarn.ForeColor = [System.Drawing.Color]::DarkRed
    $gbD.Controls.Add($lblWarn)

    $btnRdpOn = New-Object System.Windows.Forms.Button
    $btnRdpOn.Location = New-Object System.Drawing.Point(15, 45)
    $btnRdpOn.Size = New-Object System.Drawing.Size(120, 28)
    $btnRdpOn.Text = "Enable RDP"
    $gbD.Controls.Add($btnRdpOn)

    $btnRdpOff = New-Object System.Windows.Forms.Button
    $btnRdpOff.Location = New-Object System.Drawing.Point(145, 45)
    $btnRdpOff.Size = New-Object System.Drawing.Size(120, 28)
    $btnRdpOff.Text = "Disable RDP"
    $gbD.Controls.Add($btnRdpOff)

    $statusD = New-StatusLabel -X 15 -Y 75 -Width 620
    $gbD.Controls.Add($statusD)

    $btnRdpOn.Add_Click({
        Set-StatusLabel $statusD "Enabling RDP..." Working
        $form.Update()
        $r = Invoke-Action-EnableRdp
        if ($r.Ok) { Set-StatusLabel $statusD $r.Message Ok } else { Set-StatusLabel $statusD $r.Message Error }
    }.GetNewClosure())

    $btnRdpOff.Add_Click({
        Set-StatusLabel $statusD "Disabling RDP..." Working
        $form.Update()
        $r = Invoke-Action-DisableRdp
        if ($r.Ok) { Set-StatusLabel $statusD $r.Message Ok } else { Set-StatusLabel $statusD $r.Message Error }
    }.GetNewClosure())

    return $tab
}

function New-DefenderTab {
    $tab = New-Object System.Windows.Forms.TabPage
    $tab.Text = "Defender Exclusions"

    $info = New-Object System.Windows.Forms.Label
    $info.Location = New-Object System.Drawing.Point(10, 10)
    $info.Size = New-Object System.Drawing.Size(640, 30)
    $info.Text = "Add or remove an .exe / folder from Defender ASR and Controlled Folder Access exclusion lists."
    $tab.Controls.Add($info)

    $tb = New-Object System.Windows.Forms.TextBox
    $tb.Location = New-Object System.Drawing.Point(10, 45)
    $tb.Size = New-Object System.Drawing.Size(420, 22)
    $tb.ReadOnly = $true
    $tab.Controls.Add($tb)

    $btnFile = New-Object System.Windows.Forms.Button
    $btnFile.Location = New-Object System.Drawing.Point(440, 43)
    $btnFile.Size = New-Object System.Drawing.Size(100, 26)
    $btnFile.Text = "Browse File..."
    $tab.Controls.Add($btnFile)

    $btnFolder = New-Object System.Windows.Forms.Button
    $btnFolder.Location = New-Object System.Drawing.Point(545, 43)
    $btnFolder.Size = New-Object System.Drawing.Size(100, 26)
    $btnFolder.Text = "Browse Folder..."
    $tab.Controls.Add($btnFolder)

    $btnAdd = New-Object System.Windows.Forms.Button
    $btnAdd.Location = New-Object System.Drawing.Point(10, 80)
    $btnAdd.Size = New-Object System.Drawing.Size(315, 32)
    $btnAdd.Text = "ADD TO WHITELIST"
    $btnAdd.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $btnAdd.BackColor = [System.Drawing.Color]::LightGreen
    $btnAdd.Enabled = $false
    $tab.Controls.Add($btnAdd)

    $btnRem = New-Object System.Windows.Forms.Button
    $btnRem.Location = New-Object System.Drawing.Point(330, 80)
    $btnRem.Size = New-Object System.Drawing.Size(315, 32)
    $btnRem.Text = "REMOVE FROM WHITELIST"
    $btnRem.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $btnRem.BackColor = [System.Drawing.Color]::LightCoral
    $btnRem.Enabled = $false
    $tab.Controls.Add($btnRem)

    $lblList = New-Object System.Windows.Forms.Label
    $lblList.Location = New-Object System.Drawing.Point(10, 125)
    $lblList.Size = New-Object System.Drawing.Size(420, 18)
    $lblList.Text = "Exclusions added via this console:"
    $tab.Controls.Add($lblList)

    $list = New-Object System.Windows.Forms.ListBox
    $list.Location = New-Object System.Drawing.Point(10, 145)
    $list.Size = New-Object System.Drawing.Size(635, 180)
    $list.Font = New-Object System.Drawing.Font("Consolas", 9)
    $tab.Controls.Add($list)

    $btnRefresh = New-Object System.Windows.Forms.Button
    $btnRefresh.Location = New-Object System.Drawing.Point(10, 335)
    $btnRefresh.Size = New-Object System.Drawing.Size(100, 26)
    $btnRefresh.Text = "Refresh"
    $tab.Controls.Add($btnRefresh)

    $status = New-StatusLabel -X 10 -Y 365 -Width 635
    $tab.Controls.Add($status)

    $refreshList = {
        $list.Items.Clear()
        $h = Get-HardeningState
        if ($h -and $h.State.PSObject.Properties.Name -contains 'PostHardening' -and $h.State.PostHardening.DefenderExclusionsAdded) {
            foreach ($e in @($h.State.PostHardening.DefenderExclusionsAdded)) {
                if ($e -and $e.Path) {
                    $cfa = if ($e.CFA) { 'CFA' } else { '   ' }
                    $list.Items.Add(("[ASR][{0}] {1}" -f $cfa, $e.Path)) | Out-Null
                }
            }
        }
    }

    $onPick = {
        $btnAdd.Enabled = -not [string]::IsNullOrWhiteSpace($tb.Text)
        $btnRem.Enabled = -not [string]::IsNullOrWhiteSpace($tb.Text)
        Set-StatusLabel $status "Path selected." Info
    }

    $btnFile.Add_Click({
        $d = New-Object System.Windows.Forms.OpenFileDialog
        $d.Filter = "Executable Files (*.exe)|*.exe|All files (*.*)|*.*"
        $d.Title = "Select an application"
        if ($d.ShowDialog() -eq 'OK') { $tb.Text = $d.FileName; & $onPick }
    }.GetNewClosure())

    $btnFolder.Add_Click({
        $d = New-Object System.Windows.Forms.FolderBrowserDialog
        $d.Description = "Select a folder"
        if ($d.ShowDialog() -eq 'OK') { $tb.Text = $d.SelectedPath; & $onPick }
    }.GetNewClosure())

    $btnAdd.Add_Click({
        Set-StatusLabel $status "Adding exclusion..." Working
        $form.Update()
        $r = Invoke-Action-AddDefenderExclusion -Path $tb.Text
        if ($r.Ok) { Set-StatusLabel $status $r.Message Ok } else { Set-StatusLabel $status $r.Message Error }
        & $refreshList
    }.GetNewClosure())

    $btnRem.Add_Click({
        Set-StatusLabel $status "Removing exclusion..." Working
        $form.Update()
        $r = Invoke-Action-RemoveDefenderExclusion -Path $tb.Text
        if ($r.Ok) { Set-StatusLabel $status $r.Message Ok } else { Set-StatusLabel $status $r.Message Error }
        & $refreshList
    }.GetNewClosure())

    $btnRefresh.Add_Click($refreshList.GetNewClosure())
    $tab.Add_Enter($refreshList.GetNewClosure())

    return $tab
}

function New-FirewallTab {
    $tab = New-Object System.Windows.Forms.TabPage
    $tab.Text = "Firewall"

    $info = New-Object System.Windows.Forms.Label
    $info.Location = New-Object System.Drawing.Point(10, 10)
    $info.Size = New-Object System.Drawing.Size(640, 30)
    $info.Text = "Add outbound allow rules for applications you need to reach the network."
    $tab.Controls.Add($info)

    $lblName = New-Object System.Windows.Forms.Label
    $lblName.Location = New-Object System.Drawing.Point(10, 50)
    $lblName.Size = New-Object System.Drawing.Size(60, 22)
    $lblName.Text = "Name:"
    $tab.Controls.Add($lblName)

    $tbName = New-Object System.Windows.Forms.TextBox
    $tbName.Location = New-Object System.Drawing.Point(70, 47)
    $tbName.Size = New-Object System.Drawing.Size(200, 22)
    $tab.Controls.Add($tbName)

    $lblProto = New-Object System.Windows.Forms.Label
    $lblProto.Location = New-Object System.Drawing.Point(285, 50)
    $lblProto.Size = New-Object System.Drawing.Size(60, 22)
    $lblProto.Text = "Protocol:"
    $tab.Controls.Add($lblProto)

    $cbProto = New-Object System.Windows.Forms.ComboBox
    $cbProto.Location = New-Object System.Drawing.Point(345, 47)
    $cbProto.Size = New-Object System.Drawing.Size(70, 22)
    $cbProto.DropDownStyle = 'DropDownList'
    [void]$cbProto.Items.Add('TCP')
    [void]$cbProto.Items.Add('UDP')
    $cbProto.SelectedIndex = 0
    $tab.Controls.Add($cbProto)

    $lblPort = New-Object System.Windows.Forms.Label
    $lblPort.Location = New-Object System.Drawing.Point(425, 50)
    $lblPort.Size = New-Object System.Drawing.Size(40, 22)
    $lblPort.Text = "Port:"
    $tab.Controls.Add($lblPort)

    $tbPort = New-Object System.Windows.Forms.TextBox
    $tbPort.Location = New-Object System.Drawing.Point(465, 47)
    $tbPort.Size = New-Object System.Drawing.Size(80, 22)
    $tab.Controls.Add($tbPort)

    $btnAdd = New-Object System.Windows.Forms.Button
    $btnAdd.Location = New-Object System.Drawing.Point(555, 45)
    $btnAdd.Size = New-Object System.Drawing.Size(90, 26)
    $btnAdd.Text = "Add"
    $btnAdd.BackColor = [System.Drawing.Color]::LightGreen
    $tab.Controls.Add($btnAdd)

    $lblList = New-Object System.Windows.Forms.Label
    $lblList.Location = New-Object System.Drawing.Point(10, 85)
    $lblList.Size = New-Object System.Drawing.Size(400, 18)
    $lblList.Text = "Custom rules added via this console:"
    $tab.Controls.Add($lblList)

    $list = New-Object System.Windows.Forms.ListBox
    $list.Location = New-Object System.Drawing.Point(10, 105)
    $list.Size = New-Object System.Drawing.Size(635, 220)
    $list.Font = New-Object System.Drawing.Font("Consolas", 9)
    $tab.Controls.Add($list)

    $btnRemove = New-Object System.Windows.Forms.Button
    $btnRemove.Location = New-Object System.Drawing.Point(10, 335)
    $btnRemove.Size = New-Object System.Drawing.Size(150, 26)
    $btnRemove.Text = "Remove selected"
    $btnRemove.BackColor = [System.Drawing.Color]::LightCoral
    $tab.Controls.Add($btnRemove)

    $btnRefresh = New-Object System.Windows.Forms.Button
    $btnRefresh.Location = New-Object System.Drawing.Point(170, 335)
    $btnRefresh.Size = New-Object System.Drawing.Size(100, 26)
    $btnRefresh.Text = "Refresh"
    $tab.Controls.Add($btnRefresh)

    $status = New-StatusLabel -X 10 -Y 365 -Width 635
    $tab.Controls.Add($status)

    $refreshList = {
        $list.Items.Clear()
        $h = Get-HardeningState
        if ($h -and $h.State.PSObject.Properties.Name -contains 'PostHardening' -and $h.State.PostHardening.CustomFirewallRules) {
            foreach ($r in @($h.State.PostHardening.CustomFirewallRules)) {
                if ($r -and $r.Name) {
                    $list.Items.Add(("{0,-28} {1,-4} {2}" -f $r.Name, $r.Protocol, $r.Port)) | Out-Null
                }
            }
        }
    }

    $btnAdd.Add_Click({
        $name = $tbName.Text.Trim()
        $proto = $cbProto.SelectedItem
        $port = $tbPort.Text.Trim()
        if (-not $name -or -not $port) {
            Set-StatusLabel $status "Name and Port are required." Warn
            return
        }
        Set-StatusLabel $status "Adding rule..." Working
        $form.Update()
        $r = Invoke-Action-AddCustomFirewallRule -Name $name -Protocol $proto -Port $port
        if ($r.Ok) {
            Set-StatusLabel $status $r.Message Ok
            $tbName.Clear(); $tbPort.Clear()
        } else { Set-StatusLabel $status $r.Message Error }
        & $refreshList
    }.GetNewClosure())

    $btnRemove.Add_Click({
        if ($list.SelectedIndex -lt 0) {
            Set-StatusLabel $status "Select a rule to remove." Warn
            return
        }
        $line = $list.SelectedItem.ToString()
        $ruleName = ($line -split '\s+', 2)[0]
        Set-StatusLabel $status "Removing rule..." Working
        $form.Update()
        $r = Invoke-Action-RemoveCustomFirewallRule -Name $ruleName
        if ($r.Ok) { Set-StatusLabel $status $r.Message Ok } else { Set-StatusLabel $status $r.Message Error }
        & $refreshList
    }.GetNewClosure())

    $btnRefresh.Add_Click($refreshList.GetNewClosure())
    $tab.Add_Enter($refreshList.GetNewClosure())

    return $tab
}

function New-StateTab {
    $tab = New-Object System.Windows.Forms.TabPage
    $tab.Text = "System State"

    $lbl = New-Object System.Windows.Forms.Label
    $lbl.Location = New-Object System.Drawing.Point(15, 15)
    $lbl.Size = New-Object System.Drawing.Size(620, 20)
    $lbl.Text = "Latest hardening-state.json (read-only view):"
    $tab.Controls.Add($lbl)

    $tb = New-Object System.Windows.Forms.TextBox
    $tb.Location = New-Object System.Drawing.Point(15, 40)
    $tb.Size = New-Object System.Drawing.Size(620, 320)
    $tb.Multiline = $true
    $tb.ReadOnly = $true
    $tb.ScrollBars = 'Vertical'
    $tb.Font = New-Object System.Drawing.Font("Consolas", 9)
    $tab.Controls.Add($tb)

    $btn = New-Object System.Windows.Forms.Button
    $btn.Location = New-Object System.Drawing.Point(15, 370)
    $btn.Size = New-Object System.Drawing.Size(120, 28)
    $btn.Text = "Refresh"
    $tab.Controls.Add($btn)

    $refresh = {
        $h = Get-HardeningState
        if (-not $h) {
            $tb.Text = "(no hardening log folder found; run hardening first)"
            return
        }
        $tb.Text = "Folder: $($h.Folder)`r`n`r`n" + ($h.State | ConvertTo-Json -Depth 10)
    }

    $btn.Add_Click($refresh.GetNewClosure())
    $tab.Add_Enter($refresh.GetNewClosure())

    return $tab
}

function New-AboutTab {
    $tab = New-Object System.Windows.Forms.TabPage
    $tab.Text = "About"

    $lbl = New-Object System.Windows.Forms.Label
    $lbl.Location = New-Object System.Drawing.Point(15, 15)
    $lbl.Size = New-Object System.Drawing.Size(620, 200)
    $lbl.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $lbl.Text = @"
Windows Hardening Toolkit - Post-Hardening Console
Version $($script:Config.Version)

USB root:    $script:UsbRoot
Script root: $script:ScriptRoot
Computer:    $env:COMPUTERNAME

This console wraps the unified hardening pipeline and provides post-hardening
toggles. All modifications are recorded under PostHardening in the most recent
hardening-state.json so that Undo-PostHardening.ps1 can reverse them.

WARNING: Generated admin passwords and BitLocker recovery keys are stored in
plaintext on this drive. Remove the drive after use and store it securely.
"@
    $tab.Controls.Add($lbl)

    $btnOpenLog = New-Object System.Windows.Forms.Button
    $btnOpenLog.Location = New-Object System.Drawing.Point(15, 230)
    $btnOpenLog.Size = New-Object System.Drawing.Size(200, 30)
    $btnOpenLog.Text = "Open log folder in Explorer"
    $tab.Controls.Add($btnOpenLog)

    $btnOpenLog.Add_Click({
        $h = Get-HardeningState
        if ($h) { Start-Process explorer.exe -ArgumentList "`"$($h.Folder)`"" }
        else    { [System.Windows.Forms.MessageBox]::Show("No hardening log folder found.", "Info", "OK", "Information") | Out-Null }
    }.GetNewClosure())

    return $tab
}

#===========================================================================
# MAIN
#===========================================================================
$form = New-Object System.Windows.Forms.Form
$form.Text = "Windows Hardening Toolkit - Post-Hardening Console v$($script:Config.Version)"
$form.Size = New-Object System.Drawing.Size(700, 500)
$form.StartPosition = "CenterScreen"
$form.FormBorderStyle = 'FixedDialog'
$form.MaximizeBox = $false

$tabs = New-Object System.Windows.Forms.TabControl
$tabs.Location = New-Object System.Drawing.Point(5, 5)
$tabs.Size = New-Object System.Drawing.Size(675, 450)
$form.Controls.Add($tabs)

# Add tabs - extend by appending New-XxxTab calls
$tabs.TabPages.Add((New-HardeningTab))
$tabs.TabPages.Add((New-RemoteAccessTab))
$tabs.TabPages.Add((New-DefenderTab))
$tabs.TabPages.Add((New-FirewallTab))
$tabs.TabPages.Add((New-StateTab))
$tabs.TabPages.Add((New-AboutTab))

$form.ShowDialog() | Out-Null
