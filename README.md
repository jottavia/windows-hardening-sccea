# **PowerShell Windows Hardening & Management Toolkit**

This document is the complete guide for the PowerShell Hardening Toolkit, a collection of scripts designed to rapidly secure a Windows 10/11 machine, revert those changes, and manage security exceptions.

## **CRITICAL SECURITY WARNING**

This toolkit is powerful and handles sensitive information. You **MUST** understand and agree to the following before use:

1. **Secret Storage:** The hardening script creates a log file (hardening-log.txt) containing a newly generated administrator password and the BitLocker recovery key in **plain text**.  
2. **Physical Security:** The USB drive containing these scripts and the generated logs **must be removed** from the computer immediately after use and stored in a physically secure location (e.g., a safe).  
3. **Risk:** Leaving this drive connected to a computer completely undermines the security changes and exposes critical recovery information.

**By using these scripts, you accept full responsibility for the security of the generated secrets.**

## **Toolkit Components**

This toolkit contains three main scripts:

1. Unified-Hardening.ps1: The main script that applies a wide range of security configurations to lock down a system.  
2. Undo-Hardening.ps1: A rollback script that reads a state file to revert the changes made by the hardening script.  
3. Add-DefenderExclusion-GUI.ps1: A user-friendly graphical tool to add or remove exceptions from Microsoft Defender's security policies.

### **Part 1: The Hardening Script (Unified-Hardening.ps1)**

This is the core script for applying security settings.

#### **Features**

* **Administrator Management:** Creates a new secure admin (SecOpsAdm) and demotes specified users.  
* **Microsoft Defender Hardening:** Enables Tamper Protection, Controlled Folder Access (CFA), and strong Attack Surface Reduction (ASR) rules.  
* **Disk Encryption:** Enables BitLocker on the system drive.  
* **LAPS Configuration:** Configures the Windows Local Administrator Password Solution (LAPS).  
* **Verification:** Checks that each configuration was applied successfully.  
* **Rollback File:** Generates a hardening-state.json file to enable the undo script.

#### **Usage**

1. **Prerequisites:** Place the script on a USB drive. Optionally, add installers for Wazuh (wazuh-agent\*.msi) or Sysmon (Sysmon64.exe, sysmon.xml) to the same drive.  
2. **Launch:** Open PowerShell **as an Administrator**, navigate to the USB drive (e.g., cd E:), and run the script.  
3. **Example Execution:**  
   \# Standard run  
   .\\Unified-Hardening.ps1

   \# Run while demoting existing local admins  
   .\\Unified-Hardening.ps1 \-UsersToDemote "OldAdmin", "TempUser"

4. **Completion:** Once the script finishes, it will have created a folder named PC-\<ComputerName\>-LOGS on your drive. Eject and secure the drive immediately.

### **Part 2: The Rollback Script (Undo-Hardening.ps1)**

Use this script to safely revert the system to its pre-hardened state.

#### **Features**

* **State-Based Reversal:** Reads the hardening-state.json file to know exactly what to undo.  
* **Interactive Menu:** Allows you to undo all changes at once or select specific configurations to revert.  
* **High-Risk Warnings:** Provides explicit warnings for irreversible or risky actions like disabling BitLocker.

#### **Usage**

1. **Prerequisites:** You must have the PC-\<ComputerName\>-LOGS folder that was created by the hardening script on the same USB drive.  
2. **Launch:** Open PowerShell **as an Administrator**, navigate to the USB drive, and run the script, pointing it to the correct log folder.  
3. **Example Execution:**  
   .\\Undo-Hardening.ps1 \-LogFolderPath "E:\\PC-WORKSTATION-01-LOGS"

4. **Follow the Menu:** Use the on-screen menu to select the changes you wish to revert.

### **Part 3: The Exclusion Management GUI (Add-DefenderExclusion-GUI.ps1)**

After hardening, a legitimate application may be blocked. Use this tool to create exceptions.

#### **Features**

* **User-Friendly GUI:** No command-line knowledge needed.  
* **Add & Remove:** Easily add or remove items from the Defender exclusion lists.  
* **Browse for Files/Folders:** Prevents typos by letting you browse for the exact item.  
* **Automatic Logging:** Creates a separate defender-exclusions.log file for auditing.

#### **Usage**

1. **Launch:** Right-click the Add-DefenderExclusion-GUI.ps1 script and select **"Run with PowerShell"**. Approve the admin (UAC) prompt.  
2. **Select Path:** In the tool, click **"Browse File..."** for applications or **"Browse Folder..."** for folders.  
3. **Apply Action:** Once a path is selected, click **"ADD TO WHITELIST"** or **"REMOVE FROM WHITELIST"**.  
4. **Confirm:** A message box will confirm if the action was successful.

## **Disclaimer**

This toolkit makes significant changes to a system's security configuration. Always test in a non-production environment first. The author(s) are not responsible for any data loss or system instability that may result from the use of these scripts. **Use at your own risk.**