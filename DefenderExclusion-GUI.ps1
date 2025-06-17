<#
.SYNOPSIS
    Provides a GUI to add or remove a file/folder from Microsoft Defender exclusion lists
    for Controlled Folder Access (CFA) and Attack Surface Reduction (ASR).
.DESCRIPTION
    This script launches a simple user interface to help administrators whitelist or remove
    exclusions for trusted applications or folders. It requires administrative privileges
    and logs all actions.
#>

# --- Initial Setup and Admin Check ---
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    [System.Windows.Forms.MessageBox]::Show("This script requires administrative privileges. Please re-run from an elevated PowerShell prompt.", "Error", "OK", "Error")
    exit 1
}

# --- Standalone Logging Function ---
function Write-ExclusionLog {
    param([string]$Text)
    $logFile = Join-Path $PSScriptRoot "defender-exclusions.log"
    $logEntry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') :: $Text"
    try {
        Add-Content -Path $logFile -Value $logEntry -ErrorAction Stop
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show("Could not write to log file '$logFile'.", "Logging Error", "OK", "Warning")
    }
}

# --- GUI FORM DEFINITION ---
$form = New-Object System.Windows.Forms.Form
$form.Text = "Defender Whitelist Tool"
$form.Size = New-Object System.Drawing.Size(500, 310)
$form.StartPosition = "CenterScreen"
$form.FormBorderStyle = 'FixedDialog'
$form.MaximizeBox = $false

# --- GUI CONTROLS ---
$label = New-Object System.Windows.Forms.Label
$label.Location = New-Object System.Drawing.Point(10, 10)
$label.Size = New-Object System.Drawing.Size(460, 30)
$label.Text = "Browse for a file (.exe) or a folder to add to or remove from the Defender exclusion lists."
$form.Controls.Add($label)

$textBox = New-Object System.Windows.Forms.TextBox
$textBox.Location = New-Object System.Drawing.Point(10, 45)
$textBox.Size = New-Object System.Drawing.Size(350, 20)
$textBox.ReadOnly = $true
$form.Controls.Add($textBox)

$browseFileButton = New-Object System.Windows.Forms.Button
$browseFileButton.Location = New-Object System.Drawing.Point(370, 43)
$browseFileButton.Size = New-Object System.Drawing.Size(100, 25)
$browseFileButton.Text = "Browse File..."
$form.Controls.Add($browseFileButton)

$browseFolderButton = New-Object System.Windows.Forms.Button
$browseFolderButton.Location = New-Object System.Drawing.Point(370, 73)
$browseFolderButton.Size = New-Object System.Drawing.Size(100, 25)
$browseFolderButton.Text = "Browse Folder..."
$form.Controls.Add($browseFolderButton)

$addButton = New-Object System.Windows.Forms.Button
$addButton.Location = New-Object System.Drawing.Point(10, 110)
$addButton.Size = New-Object System.Drawing.Size(460, 40)
$addButton.Text = "ADD TO WHITELIST"
$addButton.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$addButton.BackColor = [System.Drawing.Color]::LightGreen
$addButton.Enabled = $false
$form.Controls.Add($addButton)

$removeButton = New-Object System.Windows.Forms.Button
$removeButton.Location = New-Object System.Drawing.Point(10, 155)
$removeButton.Size = New-Object System.Drawing.Size(460, 40)
$removeButton.Text = "REMOVE FROM WHITELIST"
$removeButton.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$removeButton.BackColor = [System.Drawing.Color]::LightCoral
$removeButton.Enabled = $false
$form.Controls.Add($removeButton)

$statusLabel = New-Object System.Windows.Forms.Label
$statusLabel.Location = New-Object System.Drawing.Point(10, 205)
$statusLabel.Size = New-Object System.Drawing.Size(460, 50)
$statusLabel.Text = "Status: Waiting for selection..."
$statusLabel.ForeColor = [System.Drawing.Color]::DimGray
$statusLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$form.Controls.Add($statusLabel)

# --- EVENT HANDLERS ---
$onPathSelected = {
    $textBox.Text = $path
    $addButton.Enabled = $true
    $removeButton.Enabled = $true
    $statusLabel.Text = "Status: Path selected. Ready to add or remove."
    $statusLabel.ForeColor = [System.Drawing.Color]::Blue
}

$browseFileButton.Add_Click({
    $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openFileDialog.Filter = "Executable Files (*.exe)|*.exe|All files (*.*)|*.*"
    $openFileDialog.Title = "Select an Application"
    if ($openFileDialog.ShowDialog() -eq "OK") { $script:path = $openFileDialog.FileName; . $onPathSelected }
})

$browseFolderButton.Add_Click({
    $folderBrowserDialog = New-Object System.Windows.Forms.FolderBrowserDialog
    $folderBrowserDialog.Description = "Select a Folder"
    if ($folderBrowserDialog.ShowDialog() -eq "OK") { $script:path = $folderBrowserDialog.SelectedPath; . $onPathSelected }
})

$addButton.Add_Click({
    $path = $textBox.Text; if ([string]::IsNullOrWhiteSpace($path)) { return }
    $statusLabel.Text = "Status: Processing ADD request..."; $statusLabel.ForeColor = [System.Drawing.Color]::Blue; $form.Update()
    try {
        Add-MpPreference -AttackSurfaceReductionOnlyExclusions $path -ErrorAction Stop
        Write-ExclusionLog -Text "ASR exclusion ADDED for path: $path"
        if ($path -like "*.exe") {
            Add-MpPreference -ControlledFolderAccessAllowedApplications $path -ErrorAction Stop
            Write-ExclusionLog -Text "CFA exclusion ADDED for application: $path"
        }
        $statusLabel.Text = "Status: Successfully ADDED exclusion for '$path'."; $statusLabel.ForeColor = [System.Drawing.Color]::Green
        [System.Windows.Forms.MessageBox]::Show("The exclusion was successfully added.", "Success", "OK", "Information")
    } catch {
        $errorMessage = "An error occurred while ADDING the exclusion: $($_.Exception.Message)"
        $statusLabel.Text = "Status: $errorMessage"; $statusLabel.ForeColor = [System.Drawing.Color]::Red
        Write-ExclusionLog -Text "[ERROR] Failed to ADD exclusion for '$path'. Details: $_"
        [System.Windows.Forms.MessageBox]::Show($errorMessage, "Error", "OK", "Error")
    }
})

$removeButton.Add_Click({
    $path = $textBox.Text; if ([string]::IsNullOrWhiteSpace($path)) { return }
    $statusLabel.Text = "Status: Processing REMOVE request..."; $statusLabel.ForeColor = [System.Drawing.Color]::Blue; $form.Update()
    try {
        Remove-MpPreference -AttackSurfaceReductionOnlyExclusions $path -ErrorAction Stop
        Write-ExclusionLog -Text "ASR exclusion REMOVED for path: $path"
        if ($path -like "*.exe") {
            Remove-MpPreference -ControlledFolderAccessAllowedApplications $path -ErrorAction Stop
            Write-ExclusionLog -Text "CFA exclusion REMOVED for application: $path"
        }
        $statusLabel.Text = "Status: Successfully REMOVED exclusion for '$path'."; $statusLabel.ForeColor = [System.Drawing.Color]::DarkGreen
        [System.Windows.Forms.MessageBox]::Show("The exclusion was successfully removed.", "Success", "OK", "Information")
    } catch {
        $errorMessage = "An error occurred while REMOVING the exclusion: $($_.Exception.Message)"
        $statusLabel.Text = "Status: $errorMessage"; $statusLabel.ForeColor = [System.Drawing.Color]::Red
        Write-ExclusionLog -Text "[ERROR] Failed to REMOVE exclusion for '$path'. Details: $_"
        [System.Windows.Forms.MessageBox]::Show($errorMessage, "Error", "OK", "Error")
    }
})

# --- Display Form ---
$form.ShowDialog() | Out-Null
