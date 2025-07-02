# PowerShell Syntax Reference Guide - Proven Patterns

This guide contains verified PowerShell syntax patterns that are known to work correctly. Use this as a reference to avoid common syntax errors and ensure proper PowerShell script construction.

## Basic Script Structure

### Script Header (Always Use This Format)
```powershell
<#
.SYNOPSIS
    Brief description
.DESCRIPTION
    Detailed description
.NOTES
    Version and notes
#>
[CmdletBinding()]
param(
    [string[]]$ArrayParameter = @(),
    [string]$StringParameter = 'DefaultValue'
)
```

### Admin Check Pattern (Proven Working)
```powershell
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "Administrator privileges required. Relaunching with elevation..."
    Start-Process powershell.exe -Verb RunAs -ArgumentList ('-NoProfile -ExecutionPolicy Bypass -File "{0}"' -f $MyInvocation.MyCommand.Path)
    exit
}
```

## Variables and Data Types

### Variable Declaration (Correct Syntax)
```powershell
# Simple variables
$stringVar = "text"
$numberVar = 123
$boolVar = $true
$nullVar = $null

# Arrays (Use @ syntax)
$simpleArray = @("item1", "item2", "item3")
$emptyArray = @()
$typedArray = [System.Collections.ArrayList]@()

# Hash tables (Use @ syntax)
$hashTable = @{
    Key1 = "Value1"
    Key2 = 123
    Key3 = $true
}

# Nested structures
$complexData = @{
    StringValue = "text"
    NumberValue = 456
    NestedHash = @{
        SubKey = "SubValue"
    }
    NestedArray = @("a", "b", "c")
}
```

### Variable Expansion in Strings
```powershell
# Correct double-quote expansion
$message = "Hello $userName, today is $(Get-Date)"

# Correct subexpression syntax
$text = "Result: $($variable.Property)"

# Avoid expansion (use single quotes)
$literal = 'This $variable will not expand'
```

## Conditional Statements

### If-Else Syntax (Proven Pattern)
```powershell
if ($condition -eq $true) {
    # Action when true
} elseif ($anotherCondition) {
    # Action for another condition
} else {
    # Default action
}

# Complex conditions
if (($var1 -eq "value") -and ($var2 -gt 10)) {
    # Multiple conditions
}

# File/path checks
if (Test-Path $filePath) {
    # File exists
}

if (-not (Test-Path $folderPath)) {
    # Folder does not exist
}
```

### Comparison Operators (Use These)
```powershell
# Equality
$a -eq $b          # Equal
$a -ne $b          # Not equal
$a -gt $b          # Greater than
$a -lt $b          # Less than
$a -ge $b          # Greater or equal
$a -le $b          # Less or equal

# String comparisons
$string -like "*pattern*"      # Wildcard match
$string -match "regex"         # Regex match
$string -contains "substring"  # Contains

# Collection operations
$array -contains $item         # Array contains item
$item -in $array              # Item in array
```

## Loops (Correct Syntax)

### ForEach Loop Patterns
```powershell
# ForEach with collections
foreach ($item in $collection) {
    # Process each item
    Write-Host "Processing: $item"
}

# ForEach with hash table
foreach ($key in $hashTable.Keys) {
    $value = $hashTable[$key]
    Write-Host "$key = $value"
}

# ForEach with pipeline
$collection | ForEach-Object {
    # Process each item in pipeline
    Write-Host "Item: $_"
}
```

### For Loop Pattern
```powershell
for ($i = 0; $i -lt $array.Count; $i++) {
    $item = $array[$i]
    Write-Host "Index $i: $item"
}
```

### While Loop Pattern
```powershell
while ($condition -eq $true) {
    # Loop while condition is true
    # Make sure to modify condition to avoid infinite loop
}
```

## Functions (Proven Working Syntax)

### Function Declaration
```powershell
function Verb-Noun {
    param(
        [Parameter(Mandatory=$true)]
        [string]$RequiredParam,
        
        [Parameter(Mandatory=$false)]
        [int]$OptionalParam = 10,
        
        [switch]$SwitchParam
    )
    
    # Function body
    try {
        # Main logic
        return $result
    } catch {
        Write-Error "Function failed: $_"
        throw
    }
}
```

### Function Calls
```powershell
# Call with parameters
$result = Verb-Noun -RequiredParam "value" -OptionalParam 20

# Call with switch
$result = Verb-Noun -RequiredParam "value" -SwitchParam

# Call with splatting
$params = @{
    RequiredParam = "value"
    OptionalParam = 30
}
$result = Verb-Noun @params
```

## Error Handling (Critical Syntax)

### Try-Catch Pattern (Always Use This Structure)
```powershell
try {
    # Code that might fail
    $result = Some-Command -ErrorAction Stop
    
} catch {
    # Handle the error
    Write-Error "Operation failed: $_"
    # or
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
}
```

### Try-Catch with Finally
```powershell
try {
    # Main code
} catch {
    # Error handling
} finally {
    # Cleanup code (always runs)
}
```

### Multiple Catch Blocks
```powershell
try {
    # Code here
} catch [System.IO.FileNotFoundException] {
    # Handle file not found
} catch [System.UnauthorizedAccessException] {
    # Handle access denied
} catch {
    # Handle any other error
}
```

## File and Path Operations

### Path Operations (Use These Patterns)
```powershell
# Path joining (cross-platform safe)
$fullPath = Join-Path $basePath $fileName

# Get script directory
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# File/folder existence
if (Test-Path $path) {
    # Exists
}

# Create directories safely
if (-not (Test-Path $folderPath)) {
    New-Item -ItemType Directory -Path $folderPath -Force | Out-Null
}
```

### File Operations
```powershell
# Read file content
$content = Get-Content $filePath -Encoding UTF8

# Write file content
$content | Out-File -FilePath $outputPath -Encoding UTF8 -Force

# JSON operations
$data | ConvertTo-Json -Depth 4 | Out-File $jsonPath -Encoding UTF8
$jsonData = Get-Content $jsonPath | ConvertFrom-Json

# Copy files
Copy-Item -Path $sourcePath -Destination $destPath -Force

# Remove files/folders
Remove-Item -Path $path -Recurse -Force
```

## Registry Operations (Proven Syntax)

### Registry Access Pattern
```powershell
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion"

# Check if key exists
if (Test-Path $regPath) {
    # Key exists
}

# Create registry key
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Set registry value
Set-ItemProperty -Path $regPath -Name "ValueName" -Value "ValueData" -Type String

# Get registry value
$value = Get-ItemProperty -Path $regPath -Name "ValueName" -ErrorAction SilentlyContinue

# Registry value types
Set-ItemProperty -Path $regPath -Name "StringValue" -Value "text" -Type String
Set-ItemProperty -Path $regPath -Name "DWordValue" -Value 1 -Type DWord
Set-ItemProperty -Path $regPath -Name "BinaryValue" -Value ([byte[]](1,2,3,4)) -Type Binary
Set-ItemProperty -Path $regPath -Name "MultiStringValue" -Value @("string1", "string2") -Type MultiString
```

## Service Operations

### Service Management Pattern
```powershell
# Get service
$service = Get-Service -Name "ServiceName" -ErrorAction SilentlyContinue

# Check service status
if ($service) {
    if ($service.Status -eq 'Running') {
        # Service is running
    }
}

# Start/Stop services
Start-Service -Name "ServiceName" -ErrorAction SilentlyContinue
Stop-Service -Name "ServiceName" -Force -ErrorAction SilentlyContinue

# Set service startup type
Set-Service -Name "ServiceName" -StartupType Disabled
```

## Process Operations

### Process Management
```powershell
# Start process and wait
$process = Start-Process -FilePath "program.exe" -ArgumentList "/silent" -Wait -PassThru

# Check exit code
if ($process.ExitCode -eq 0) {
    # Success
}

# Get running processes
$processes = Get-Process -Name "ProcessName" -ErrorAction SilentlyContinue

# Stop process
Stop-Process -Name "ProcessName" -Force -ErrorAction SilentlyContinue
```

## String Operations (Common Patterns)

### String Manipulation
```powershell
# String formatting
$formatted = "Value: {0}, Count: {1}" -f $value, $count

# String replacement
$newString = $originalString -replace "oldtext", "newtext"

# String splitting
$parts = $string -split ","
$parts = $string.Split(",")

# String joining
$joined = $array -join ","
$joined = [string]::Join(",", $array)

# String trimming
$trimmed = $string.Trim()
$trimmed = $string.Trim(" ", "\t")

# Case conversion
$upper = $string.ToUpper()
$lower = $string.ToLower()
```

## Object and Collection Operations

### Working with Objects
```powershell
# Select specific properties
$filtered = $objects | Select-Object Name, Value, Status

# Where-Object filtering
$filtered = $collection | Where-Object { $_.Property -eq "value" }
$filtered = $collection | Where-Object Property -eq "value"

# Sort objects
$sorted = $collection | Sort-Object PropertyName
$sorted = $collection | Sort-Object PropertyName -Descending

# Group objects
$grouped = $collection | Group-Object PropertyName

# Measure objects
$count = ($collection | Measure-Object).Count
$sum = ($collection | Measure-Object -Property NumberProperty -Sum).Sum
```

### Array Operations (Safe Patterns)
```powershell
# Add to ArrayList (preferred for dynamic arrays)
$arrayList = [System.Collections.ArrayList]@()
$arrayList.Add("item") | Out-Null

# Add to regular array (creates new array)
$array += "newitem"

# Array indexing
$firstItem = $array[0]
$lastItem = $array[-1]

# Array slicing
$subset = $array[1..3]

# Check if array contains item
if ($array -contains "item") {
    # Item exists
}
```

## Date and Time Operations

### Date Formatting (Standard Patterns)
```powershell
# Current date/time
$now = Get-Date

# Formatted dates
$timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
$fileStamp = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
$isoDate = Get-Date -Format 'o'

# Date arithmetic
$tomorrow = (Get-Date).AddDays(1)
$lastWeek = (Get-Date).AddDays(-7)
```

## Output and Display (Console)

### Write-Host vs Write-Output
```powershell
# Console output with colors (not captured by pipeline)
Write-Host "Message" -ForegroundColor Green
Write-Host "Error message" -ForegroundColor Red

# Pipeline output (can be captured)
Write-Output "Data for pipeline"

# Error streams
Write-Error "Error message"
Write-Warning "Warning message"
Write-Verbose "Verbose message"
```

### String Formatting for Output
```powershell
# Backtick for newlines in strings
Write-Host "`nSection Header:" -ForegroundColor Cyan

# Here-strings for multi-line content
$content = @"
Line 1
Line 2
Variable: $variable
"@
```

## Common Mistakes to Avoid

### Syntax Errors to Prevent
```powershell
# WRONG: Missing @ for arrays
$array = ("item1", "item2")  # Don't do this

# CORRECT: Proper array syntax
$array = @("item1", "item2")

# WRONG: Missing @ for hashtables
$hash = { Key = "Value" }  # Don't do this

# CORRECT: Proper hashtable syntax
$hash = @{ Key = "Value" }

# WRONG: Incorrect if statement
if $condition { }  # Don't do this

# CORRECT: Proper if syntax
if ($condition) { }

# WRONG: String concatenation in expansion
$text = "$variable + more text"  # Don't do this

# CORRECT: Proper string expansion
$text = "$variable more text"
# or
$text = "${variable} more text"
```

### Parameter and Argument Patterns
```powershell
# Command with parameters (use hyphens)
Get-Process -Name "notepad"
Get-ChildItem -Path "C:\" -Recurse

# Splatting for multiple parameters
$params = @{
    Path = "C:\"
    Filter = "*.txt"
    Recurse = $true
}
Get-ChildItem @params
```

## Pipeline Operations (Proven Patterns)

### Pipeline Syntax
```powershell
# Basic pipeline
Get-Process | Where-Object Name -like "*notepad*" | Select-Object Name, Id

# Complex pipeline with multiple stages
Get-ChildItem -Path "C:\Logs" |
    Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-30) } |
    Remove-Item -Force

# Pipeline with ForEach-Object
$files | ForEach-Object {
    Write-Host "Processing: $($_.Name)"
    # Process each file
}
```

This syntax reference contains proven PowerShell patterns that work correctly. Always refer to these patterns to avoid syntax errors and ensure your PowerShell scripts execute properly.