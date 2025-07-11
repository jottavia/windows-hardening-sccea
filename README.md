# **PowerShell Windows Hardening & Management Toolkit**

This document is the complete guide for the PowerShell Hardening Toolkit, a collection of scripts designed to rapidly secure a Windows 10/11 machine, revert those changes, and manage security exceptions in a way that supports formal compliance and auditing.

## **Table of Contents**

1. [CRITICAL SECURITY WARNING](#bookmark=id.71iwglvwxqcg)  
2. [Toolkit Components & File Manifest](#bookmark=id.qb07bu8fv8fl)  
3. [Framework Compliance Support](#bookmark=id.otlzdrsluw7q)  
4. [The Compliance Evidence Package](#bookmark=id.s1fpot8rrjwo)  
5. [Typical Deployment Environment](#bookmark=id.ed88nk38illy)  
6. [Part 1: The Hardening Script (Unified-Hardening.ps1)](#bookmark=id.28pu9svjtohr)  
7. [Part 2: The Rollback Script (Undo-Hardening.ps1)](#bookmark=id.k9ftjjc8hl4x)  
8. [Part 3: The Exclusion Management GUI (Add-DefenderExclusion-GUI.ps1)](#bookmark=id.7f3ds9bc9ln)  
9. [Part 4: The Standalone Audit Script (Collect-ComplianceData.ps1)](#bookmark=id.n227cqiymgqb)  
10. [Troubleshooting](#bookmark=id.9t922whwhe5f)  
11. [Disclaimer](#bookmark=id.immmob1kpsz4)

## **CRITICAL SECURITY WARNING**

This toolkit is powerful and handles sensitive information. You **MUST** understand and agree to the following before use:

1. **Secret Storage:** The hardening script creates a log file (hardening-log.txt) containing a newly generated administrator password and the BitLocker recovery key in **plain text**.  
2. **Physical Security:** The USB drive containing these scripts and the generated logs **must be removed** from the computer immediately after use and stored in a physically secure location (e.g., a safe).  
3. **Risk:** Leaving this drive connected to a computer completely undermines the security changes and exposes critical recovery information.

**By using these scripts, you accept full responsibility for the security of the generated secrets.**

## **Toolkit Components & File Manifest**

Your toolkit should contain the following files:

* Unified-Hardening.ps1: The core script that applies security settings and collects initial compliance data.  
* Undo-Hardening.ps1: An interactive script to revert changes made by the hardening script.  
* Add-DefenderExclusion-GUI.ps1: A graphical tool for managing Defender ASR/CFA exceptions.  
* Collect-ComplianceData.ps1: A standalone, read-only script for periodic compliance auditing.  
* README.md: This documentation file.

## **Framework Compliance Support**

This toolkit is designed to help organizations meet the technical requirements of various cybersecurity frameworks. The automated hardening and data collection directly support controls found in:

* **NIST SP 800-171 & NIST SP 800-53:** Implements controls across numerous families including Access Control (AC), Audit and Accountability (AU), Configuration Management (CM), System and Communications Protection (SC), and System and Information Integrity (SI).  
* **CMMC (Cybersecurity Maturity Model Certification):** The script's actions align with practices required for CMMC Level 1 and provide a technical foundation for many Level 2 practices.  
* **ISO/IEC 27001:** Helps implement technical controls listed in Annex A, such as A.9 (Access Control), A.12 (Operations Security), and A.14 (System Acquisition, Development, and Maintenance).

The script doesn't just apply settings; it collects verifiable evidence that these settings are in place.

## **The Compliance Evidence Package**

A key feature of the hardening script is the automatic generation of a **Compliance Evidence Package**. When the script runs, it creates multiple detailed JSON files that serve as a point-in-time snapshot of the system's security state, providing machine-readable evidence for auditors and compliance officers.

* system-baseline.json: A comprehensive inventory of the system's hardware, OS, network configuration, user accounts, and installed software.  
* compliance-verification.json: A structured report that directly maps system settings to common security control families. This file is designed to answer auditor questions about how specific compliance requirements are met.  
* security-events.json: A collection of recent, security-relevant events from Windows Event Logs, providing data on logins, policy changes, and Defender actions.  
* backup-integrity-test.json: Records the result of a test to ensure backup systems are functioning as expected.

These files bridge the gap between technical implementation and formal compliance documentation. They provide the raw data needed to prove that controls are operating effectively.

#### **Example compliance-verification.json Snippet:**

{  
  "AccessControl": {  
    "UniqueUserIDs": 5,  
    "AdminAccounts": 2,  
    "DisabledAccounts": 1,  
    "AccountLockoutPolicy": null,  
    "PasswordPolicy": {  
      "MinPasswordLength": 8,  
      "MaxPasswordAge": 42  
    }  
  }  
}

## **Typical Deployment Environment**

This toolkit is optimized for securing standalone or workgroup Windows machines that may not be part of a centrally managed Active Directory domain. The typical use case includes:

* **Endpoint Hardening:** Securing individual workstations or servers in small offices, remote locations, or specialized environments.  
* **Removable Media Deployment:** All scripts are designed to be run from a USB drive, making it a portable solution for IT technicians and security professionals.  
* **Integration:** The script anticipates common small business tools, such as including a default firewall rule for URBackup (TCP/55415), demonstrating its adaptability to specific environments.

## **Part 1: The Hardening Script (Unified-Hardening.ps1)**

This script applies the security configurations and collects the initial compliance data.

### **Usage**

1. **Prerequisites:** Place the script on a USB drive. Optionally, add installers for Wazuh (wazuh-agent\*.msi) or Sysmon (Sysmon64.exe, sysmon.xml) to the same drive.  
2. **Launch:** Open PowerShell **as an Administrator**. To do this, click the Start Menu, type PowerShell, right-click on "Windows PowerShell", and select "Run as administrator".  
3. **Navigate:** In the PowerShell window, navigate to your USB drive by typing its letter followed by a colon (e.g., E:).  
4. **Execute:** Run the script using one of the following command formats.  
   * **Standard Execution:**  
     .\\Unified-Hardening.ps1

   * **To Demote Specific Admins:**  
     .\\Unified-Hardening.ps1 \-UsersToDemote "OldAdmin", "TempUser"

5. **Completion:** Once finished, the script will have created a folder named PC-\<ComputerName\>-LOGS on your drive. Eject and securely store the USB drive immediately.

## **Part 2: The Rollback Script (Undo-Hardening.ps1)**

Use this script to safely revert the system to its pre-hardened state.

### **Usage**

1. **Prerequisites:** You must have the PC-\<ComputerName\>-LOGS folder that was created by the hardening script on the same USB drive.  
2. **Launch:** Open PowerShell **as an Administrator** and navigate to the USB drive.  
3. **Execute:** Run the script, pointing it to the correct log folder for the machine you are on.  
   .\\Undo-Hardening.ps1 \-LogFolderPath "E:\\PC-WORKSTATION-01-LOGS"

4. **Follow the Menu:** The interactive menu will prompt you to undo specific changes, such as 'Admin Account Changes', 'Defender Hardening', 'BitLocker Encryption', and 'Remote Access Disabling'. You can also choose the 'UNDO ALL' option to revert all applied settings in sequence. Be aware of high-risk actions that may require a reboot.

## **Part 3: The Exclusion Management GUI (Add-DefenderExclusion-GUI.ps1)**

After hardening, use this graphical tool to manage exceptions for trusted applications.

### **Usage**

1. **Launch:** In File Explorer, navigate to the script. Right-click the Add-DefenderExclusion-GUI.ps1 file and select **"Run with PowerShell"**. Approve the admin (UAC) prompt.  
2. **Select Path:** In the tool, click **"Browse File..."** for applications or **"Browse Folder..."** for folders.  
3. **Apply Action:** Once a path is selected, click **"ADD TO WHITELIST"** or **"REMOVE FROM WHITELIST"**.  
4. **Confirm:** A message box will confirm if the action was successful.

## **Part 4: The Standalone Audit Script (Collect-ComplianceData.ps1)**

Use this script to perform periodic compliance checks *after* the initial hardening.

### **Features**

* **Read-Only:** Gathers all the same data as the hardening script but makes no changes to the system.  
* **Timestamped Folders:** Each run saves the JSON evidence package into a new folder named AUDIT-\<timestamp\>, allowing you to track compliance over time.

### **Usage**

1. **Launch:** Open PowerShell **as an Administrator**, navigate to the USB drive, and run the script.  
2. **Example Execution:**  
   .\\Collect-ComplianceData.ps1

3. **Completion:** A new timestamped audit folder will be created inside the PC-\<ComputerName\>-AUDITS directory on your drive.

## **Troubleshooting**

* **Issue:** A script fails with an error message containing "Access is denied."  
  * **Solution:** You must run PowerShell as an Administrator. Close the current window, find PowerShell in the Start Menu, right-click it, and select "Run as administrator".  
* **Issue:** A script will not run and shows a red error message about "running scripts is disabled on this system."  
  * **Solution:** You may need to temporarily change the PowerShell execution policy for the current session. In your administrative PowerShell window, run the following command and then re-run the script:  
    Set-ExecutionPolicy \-ExecutionPolicy RemoteSigned \-Scope Process

## **Disclaimer**

This toolkit makes significant changes to a system's security configuration. Always test in a non-production environment first. The author(s) are not responsible for any data loss or system instability that may result from the use of these scripts. **Use at your own risk.**