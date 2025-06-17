# **User Guide: Unified Hardening Script**

This guide provides detailed instructions for using the Unified-Hardening.ps1 script and outlines the manual steps to take if any part of the automated process fails.

### **Part 1: Prerequisites & Setup**

Before you begin, ensure you have the following:

1. **A USB Flash Drive:** This is where the scripts and logs will be stored.  
2. **The Unified-Hardening.ps1 Script:** Located on the root of the USB drive.  
3. **Administrator Access:** You must be able to run PowerShell as an Administrator on the target machine.  
4. **(Optional) Installers:** If you want to install Wazuh or Sysmon, place their respective installers (wazuh-agent\*.msi, Sysmon64.exe, sysmon.xml) on the root of the USB drive.

### **Part 2: Running the Automated Script**

Follow these steps to execute the automated hardening process. The script is designed to be verbose, providing \[VERIFIED\] or \[FAILED\] status for each major task.

1. **Insert the USB Drive:** Plug the prepared USB drive into the target computer.  
2. **Open PowerShell as Administrator:**  
   * Click the Start Menu.  
   * Type PowerShell.  
   * Right-click on "Windows PowerShell" and select **"Run as administrator"**.  
3. **Navigate to the USB Drive:** In the PowerShell window, type the drive letter followed by a colon and press Enter. For example:  
   E:

4. **Execute the Script:** Run the script using one of the following methods.  
   * **Standard Execution:**  
     .\\Unified-Hardening.ps1

   * **To Demote Specific Admins:** List the usernames of the local admin accounts you wish to remove from the Administrators group.  
     .\\Unified-Hardening.ps1 \-UsersToDemote "OldAdmin", "TempUser"

5. **Review the Output:** Pay close attention to the console output. If any step shows \[FAILED\], refer to Part 3 of this guide to perform that step manually.  
6. **SECURE THE DRIVE:** Eject the USB drive immediately and store it in a physically secure location. It now contains the administrator password and BitLocker recovery key.

### **Part 3: Manual Fallback & Verification Guide**

If a step in the script fails or requires manual verification, use the detailed instructions below.

#### **1\. Administrator Accounts**

* **Goal:** Create a new admin SecOpsAdm and demote others.  
* **Manual GUI Steps:**  
  1. Press Win \+ R, type lusrmgr.msc, and press Enter.  
  2. **To create a user:** Right-click on the "Users" folder \> "New User...". Fill in SecOpsAdm as the username, provide a strong password, uncheck "User must change password...", check "Password never expires", and click "Create".  
  3. **To make a user an admin:** Go to the "Groups" folder, double-click "Administrators". Click "Add...", type SecOpsAdm, click "Check Names", and then "OK".  
  4. **To demote a user:** In the same "Administrators" properties window, select the user you want to demote and click "Remove".

#### **2\. Microsoft Defender Hardening**

* **Goal:** Enable Tamper Protection, Controlled Folder Access (CFA), and Attack Surface Reduction (ASR).  
* **Manual GUI Steps:**  
  1. Go to **Settings \> Update & Security \> Windows Security \> Virus & threat protection**.  
  2. Under "Virus & threat protection settings", click "Manage settings".  
  3. **Tamper Protection:** Ensure the toggle is **On**.  
  4. **Controlled Folder Access:** Scroll down, click "Manage Controlled folder access", and ensure the toggle is **On**.  
  5. **ASR:** This cannot be fully configured from the GUI. You must use PowerShell for verification.  
* **Manual PowerShell Command (run as admin):**  
  \# To apply the settings  
  Set-MpPreference \-EnableTamperProtection 1 \-EnableControlledFolderAccess Enabled  
  $asrRuleIds \= @("56a863a9-875e-4185-98a7-b882c64b5ce5", "3b576869-a4ec-4529-8536-b80a7769e899") \# Add all other IDs  
  Set-MpPreference \-AttackSurfaceReductionRules\_Ids $asrRuleIds \-AttackSurfaceReductionRules\_Actions Enabled

  \# To verify  
  Get-MpPreference | Select-Object EnableTamperProtection, EnableControlledFolderAccess

#### **3\. BitLocker Encryption**

* **Goal:** Encrypt the C: drive.  
* **Manual GUI Steps:**  
  1. Go to **Control Panel \> System and Security \> BitLocker Drive Encryption**.  
  2. Find your C: drive and click "**Turn on BitLocker**".  
  3. Follow the wizard to save your recovery key (save it to the USB drive) and start encryption.  
* **Manual Command Prompt Command (run as admin):**  
  rem To turn on  
  manage-bde \-on C: \-skiphardwaretest

  rem To check status  
  manage-bde \-status C:

#### **4\. LAPS Configuration**

* **Goal:** Enable LAPS to manage the local Administrator password.  
* **Manual GUI Steps:** LAPS is primarily managed via Group Policy or Intune. For a standalone machine, PowerShell is the most direct method.  
* **Manual PowerShell Command (run as admin):**  
  \# To apply the policy  
  Set-LapsPolicy \-Enable 1 \-AdminAccountName "Administrator" \-PasswordComplexity 4 \-PasswordLength 15 \-PasswordAgeDays 30

  \# To verify  
  Get-LapsPolicy

#### **5\. Remote Access Services**

* **Goal:** Disable WinRM and Remote Desktop Protocol (RDP).  
* **Manual GUI Steps:**  
  1. **RDP:** Press Win \+ R, type SystemPropertiesRemote, press Enter. Select "Don't allow remote connections to this computer" and click "OK".  
  2. **WinRM:** Press Win \+ R, type services.msc, press Enter. Find "Windows Remote Management (WS-Management)", double-click it, set "Startup type" to **Disabled**, and click the "Stop" button.  
* **Manual PowerShell Command (run as admin):**  
  \# Disable RDP  
  Set-ItemProperty \-Path "HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server" \-Name "fDenyTSConnections" \-Value 1  
  Stop-Service \-Name 'TermService' \-Force

  \# Disable WinRM  
  Set-Service \-Name 'WinRM' \-StartupType Disabled  
  Stop-Service \-Name 'WinRM' \-Force

#### **6\. Firewall Hardening**

* **Goal:** Set the firewall to block all outbound connections by default and add specific exceptions.  
* **Manual GUI Steps:**  
  1. Press Win \+ R, type wf.msc, and press Enter.  
  2. In the main pane, click on "**Windows Defender Firewall Properties**".  
  3. For each tab (**Domain Profile**, **Private Profile**, **Public Profile**):  
     * Set "Outbound connections" to **Block**.  
     * Click "OK".  
  4. **To add an allow rule:** Right-click "Outbound Rules" \> "New Rule...". Follow the wizard to create an "Allow" rule for a specific program or port (e.g., TCP Port 443 for HTTPS).  
* **Manual Command Prompt Command (run as admin):**  
  :: Set all profiles to block outbound traffic  
  netsh advfirewall set allprofiles firewallpolicy blockoutbound,allowinbound

  :: Add an allow rule for HTTPS (repeat for other needed ports)  
  netsh advfirewall firewall add rule name="Allow HTTPS-Out" dir=out action=allow protocol=TCP remoteport=443  
