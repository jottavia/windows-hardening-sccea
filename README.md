# PowerShell Windows Hardening & Management Toolkit

This document is the complete guide for the PowerShell Hardening Toolkit, a collection of scripts designed to rapidly secure a Windows 10/11 machine, revert those changes, and manage security exceptions in a way that supports formal compliance and auditing.

---

## **CRITICAL SECURITY WARNING**

This toolkit is powerful and handles sensitive information. You **MUST** understand and agree to the following before use:

1.  **Secret Storage:** The hardening script creates a log file (`hardening-log.txt`) containing a newly generated administrator password and the BitLocker recovery key in **plain text**.
2.  **Physical Security:** The USB drive containing these scripts and the generated logs **must be removed** from the computer immediately after use and stored in a physically secure location (e.g., a safe).
3.  **Risk:** Leaving this drive connected to a computer completely undermines the security changes and exposes critical recovery information.

**By using these scripts, you accept full responsibility for the security of the generated secrets.**

---

## **Toolkit Components**

* `Unified-Hardening.ps1`: Applies security configurations and collects compliance data.
* `Undo-Hardening.ps1`: Reverts the changes made by the hardening script.
* `Add-DefenderExclusion-GUI.ps1`: A graphical tool for managing Defender exclusions.
* `Collect-ComplianceData.ps1`: A standalone script to perform periodic compliance data collection *without* re-hardening the system.

---

## **Framework Compliance Support**

This toolkit is designed to help organizations meet the technical requirements of various cybersecurity frameworks. The automated hardening and data collection directly support controls found in:

* **NIST SP 800-171 & NIST SP 800-53:** Implements controls across numerous families including Access Control (AC), Audit and Accountability (AU), Configuration Management (CM), System and Communications Protection (SC), and System and Information Integrity (SI).
* **CMMC (Cybersecurity Maturity Model Certification):** The script's actions align with practices required for CMMC Level 1 and provide a technical foundation for many Level 2 practices.
* **ISO/IEC 27001:** Helps implement technical controls listed in Annex A, such as A.9 (Access Control), A.12 (Operations Security), and A.14 (System Acquisition, Development, and Maintenance).

The script doesn't just apply settings; it collects verifiable evidence that these settings are in place.

---

## **The Compliance Evidence Package**

A key feature of the hardening script is the automatic generation of a **Compliance Evidence Package**. When the script runs, it creates multiple detailed JSON files that serve as a point-in-time snapshot of the system's security state, providing machine-readable evidence for auditors and compliance officers.

* `system-baseline.json`: A comprehensive inventory of the system's hardware, OS, network configuration, user accounts, and installed software.
* `compliance-verification.json`: A structured report that directly maps system settings to common security control families (Access Control, Auditing, Change Management, Backup Verification, etc.). This file is designed to answer auditor questions about how specific compliance requirements are met.
* `security-events.json`: A collection of recent, security-relevant events from Windows Event Logs, providing data on logins, policy changes, and Defender actions.
* `backup-integrity-test.json`: Records the result of a test to ensure backup systems are functioning as expected.

These files bridge the gap between technical implementation and formal compliance documentation. They provide the raw data needed to prove that controls are operating effectively.

---

## **Typical Deployment Environment**

This toolkit is optimized for securing standalone or workgroup Windows machines that may not be part of a centrally managed Active Directory domain. The typical use case includes:

* **Endpoint Hardening:** Securing individual workstations or servers in small offices, remote locations, or specialized environments.
* **Removable Media Deployment:** All scripts are designed to be run from a USB drive, making it a portable solution for IT technicians and security professionals.
* **Integration:** The script anticipates common small business tools, such as including a default firewall rule for URBackup (`TCP/55415`), demonstrating its adaptability to specific environments.

---

## **Part 1: The Hardening Script (`Unified-Hardening.ps1`)**

*(Usage instructions for running the script, demoting users, etc., would follow here as in the previous README.)*

## **Part 2: The Rollback Script (`Undo-Hardening.ps1`)**

*(Usage instructions for the undo script would follow here.)*

## **Part 3: The Exclusion Management GUI (`Add-DefenderExclusion-GUI.ps1`)**

*(Usage instructions for the GUI tool would follow here.)*

## **Part 4: The Standalone Audit Script (`Collect-ComplianceData.ps1`)**

Use this script to perform periodic compliance checks *after* the initial hardening.

### **Features**
* **Read-Only:** Gathers all the same data as the hardening script but makes no changes to the system.
* **Timestamped Folders:** Each run saves the JSON evidence package into a new folder named `AUDIT-<timestamp>`, allowing you to track compliance over time.

### **Usage**
1.  **Launch:** Open PowerShell **as an Administrator**, navigate to the USB drive, and run the script.
2.  **Example Execution:**
    ```powershell
    .\Collect-ComplianceData.ps1
    ```
3.  **Completion:** A new timestamped audit folder will be created inside the `PC-<ComputerName>-AUDITS` directory on your drive.

---

## **Disclaimer**

This toolkit makes significant changes to a system's security configuration. Always test in a non-production environment first. The author(s) are not responsible for any data loss or system instability that may result from the use of these scripts. **Use at your own risk.**
