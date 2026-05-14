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
10. [Part 5: The Post-Hardening Console GUI (Post-Hardening-Console.ps1)](#part-5-the-post-hardening-console-gui-post-hardening-consoleps1)  
11. [Part 6: The Post-Hardening Rollback Script (Undo-PostHardening.ps1)](#part-6-the-post-hardening-rollback-script-undo-posthardeningps1)  
12. [Troubleshooting](#bookmark=id.9t922whwhe5f)  
13. [Disclaimer](#bookmark=id.immmob1kpsz4)

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
* Post-Hardening-Console.ps1: A WinForms GUI that launches the hardening pipeline and provides post-hardening one-click toggles (RustDesk, Tailscale, RDP, Defender exclusions, custom firewall rules).  
* Undo-PostHardening.ps1: Reverses every change made via the Post-Hardening Console. Run before Undo-Hardening.ps1 if a full rollback is needed.  
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

   * **To pre-stage LAPS on a non-domain-joined machine** (LAPS cannot *function* without AD, but you may want the policy pre-configured for a future domain join):  
     .\\Unified-Hardening.ps1 \-ForceLAPS

5. **Completion:** Once finished, the script will have created a folder named PC-\<ComputerName\>-LOGS on your drive. Eject and securely store the USB drive immediately.

### **LAPS and domain join**

LAPS (Local Administrator Password Solution) cannot rotate passwords on machines that are not joined to Active Directory. As of v9.2 the hardening script auto-detects domain membership via `(Get-CimInstance Win32_ComputerSystem).PartOfDomain`:

| Scenario | Default behavior |
|:--|:--|
| Domain-joined (modern LAPS cmdlet present) | Configure modern LAPS, enable built-in Administrator. |
| Domain-joined (legacy LAPS MSI on USB) | Install + configure legacy LAPS, enable built-in Administrator. |
| **Not** domain-joined, `-ForceLAPS` not specified | **Skip LAPS**, disable the built-in Administrator account as a compensating control. |
| Not domain-joined, `-ForceLAPS` specified | Configure LAPS anyway (will only become functional after the machine joins a domain). |

## **Part 2: The Rollback Script (Undo-Hardening.ps1)**

Use this script to safely revert the **non-account** portions of the hardened baseline.

### **Account changes are intentionally NOT reversed**

As of v9.2, this script does **not** reverse:

* Creation of the `SecOpsAdm` administrator account.
* Demotion of users named via `-UsersToDemote`.
* Enable/disable state of the built-in `Administrator`.

Once a machine has been hardened those accounts form the live security posture. Reversing them would lock out the operator (who is now signed in as `SecOpsAdm`) and silently re-grant privileges that were intentionally removed. Manage account state directly if needed.

### **Usage**

1. **Prerequisites:** You must have the PC-\<ComputerName\>-LOGS folder that was created by the hardening script on the same USB drive.  
2. **Launch:** Open PowerShell **as an Administrator** and navigate to the USB drive.  
3. **Execute:** Run the script, pointing it to the correct log folder for the machine you are on.  
   .\\Undo-Hardening.ps1 \-LogFolderPath "E:\\PC-WORKSTATION-01-LOGS"

4. **Follow the Menu:** The interactive menu will prompt you to undo specific non-account changes: LAPS policy, Defender hardening, BitLocker encryption, agent installs, WDAC policy, firewall hardening, and remote-access disabling. You can also choose 'UNDO ALL' to revert every non-account setting in sequence. Be aware of high-risk actions that may require a reboot.

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

## **Part 5: The Post-Hardening Console GUI (Post-Hardening-Console.ps1)**

A WinForms console that wraps the entire pipeline (run hardening, run audit, run undo) and provides post-hardening one-click toggles. Built with the Windows-shipped System.Windows.Forms and System.Drawing assemblies only - no third-party dependencies.

### **Tabs**

1. **Hardening** - Buttons to run the unified hardening script, the periodic audit script, the post-hardening rollback (Undo-PostHardening.ps1), and the base hardening rollback (undo-hardening.ps1). All four launch as elevated child processes.
2. **Remote Access** - One-click install / uninstall for **RustDesk** (with a Public-relays-vs-Self-hosted radio; self-hosted reads server/key from rustdesk-server.txt and rustdesk-key.txt next to the console if present) and **Tailscale** (install, then a separate Login button that opens a console where 'tailscale up' prints the browser auth URL). Includes Re-enable RDP / Disable RDP buttons.
3. **Defender Exclusions** - Browse File / Browse Folder + Add / Remove against Defender ASR and Controlled Folder Access. Subsumes the standalone Add-DefenderExclusion-GUI.ps1.
4. **Firewall** - Add custom outbound allow rules (TCP/UDP) and remove them. Useful for apps that need network reach after the default-deny outbound lockdown.
5. **System State** - Read-only viewer for the latest hardening-state.json.
6. **About** - Version info, log folder path, button to open the log folder in Explorer.

### **State Contract**

The console adds a new top-level "PostHardening" object inside the existing hardening-state.json:

```json
{
  "PostHardening": {
    "Version": 1,
    "RustDesk":  { "Installed": true,  "Mode": "SelfHosted", "Server": "rdsk.example.com:21116", "InstallerPath": "...", "FirewallRules": ["RustDesk-Out-TCP","RustDesk-Out-UDP"], "DefenderExclusions": ["C:\\Program Files\\RustDesk"], "Timestamp": "..." },
    "Tailscale": { "Installed": true,  "InstallerPath": "...", "FirewallRules": ["Tailscale-Direct-UDP"], "DefenderExclusions": ["C:\\Program Files\\Tailscale"], "Timestamp": "..." },
    "RdpReenabled": false,
    "CustomFirewallRules":     [ { "Name": "MyApp-Out", "Protocol": "TCP", "Port": "8080", "Timestamp": "..." } ],
    "DefenderExclusionsAdded": [ { "Path": "C:\\Apps\\X.exe", "ASR": true, "CFA": true, "Timestamp": "..." } ]
  }
}
```

Every console action either creates or updates entries here. The companion Undo-PostHardening.ps1 reads this object to reverse the actions.

### **Optional configuration files (next to the console on the USB)**

| File | Purpose |
|:--|:--|
| rustdesk-\*.msi or rustdesk-\*.exe | RustDesk installer (auto-discovered). |
| rustdesk-server.txt | Pre-fills the self-hosted server field (one line, e.g. `rdsk.example.com:21116`). |
| rustdesk-key.txt | Pre-fills the self-hosted key field. |
| tailscale-setup-\*.exe or tailscale-\*.msi | Tailscale installer (auto-discovered). |

### **Usage**

1. **Prerequisites:** Run the unified hardening script at least once on this machine - the console operates on the latest PC-\<ComputerName\>-LOGS\HARDENING-\<timestamp\> folder it finds on the same drive.
2. **Launch:** In File Explorer on the USB drive, right-click Post-Hardening-Console.ps1 and select **"Run with PowerShell"**. Approve the UAC prompt.
3. **Work:** Use the tabs in sequence as needed - typically Hardening first (to confirm or run the lockdown), then Remote Access / Defender / Firewall to apply post-hardening exceptions.
4. **Log:** Every action is appended to `post-hardening-log.txt` inside the hardening folder for that run.

## **Part 6: The Post-Hardening Rollback Script (Undo-PostHardening.ps1)**

Reverses every change made via the Post-Hardening Console. Run this **before** Undo-Hardening.ps1 if you want a full rollback to factory state.

### **Usage**

1. **Launch:** Open PowerShell **as an Administrator**, navigate to the USB drive.
2. **Interactive menu:**

   ```
   .\Undo-PostHardening.ps1 -LogFolderPath "E:\PC-WORKSTATION-01-LOGS\HARDENING-2026-05-14_09-22-31"
   ```

3. **Non-interactive (everything at once):**

   ```
   .\Undo-PostHardening.ps1 -LogFolderPath "E:\PC-WORKSTATION-01-LOGS\HARDENING-2026-05-14_09-22-31" -All
   ```

The script also runs from the GUI's "Undo Post-Hardening" button on the Hardening tab.

## **Troubleshooting**

* **Issue:** A script fails with an error message containing "Access is denied."  
  * **Solution:** You must run PowerShell as an Administrator. Close the current window, find PowerShell in the Start Menu, right-click it, and select "Run as administrator".  
* **Issue:** A script will not run and shows a red error message about "running scripts is disabled on this system."  
  * **Solution:** You may need to temporarily change the PowerShell execution policy for the current session. In your administrative PowerShell window, run the following command and then re-run the script:  
    Set-ExecutionPolicy \-ExecutionPolicy RemoteSigned \-Scope Process

## **Disclaimer**

This toolkit makes significant changes to a system's security configuration. Always test in a non-production environment first. The author(s) are not responsible for any data loss or system instability that may result from the use of these scripts. **Use at your own risk.**