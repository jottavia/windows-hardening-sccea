## **User Guide: PowerShell Windows Hardening Toolkit**

This guide provides detailed instructions for using the Unified-Hardening.ps1 script, understanding its output, and manually performing its tasks if a step fails or requires verification.

### **Part 1: Prerequisites & Setup**

Before you begin, ensure you have the following:

1. **A USB Flash Drive:** This is where the scripts and logs will be stored.  
2. **The Script Files:** Unified-Hardening.ps1 and Undo-Hardening.ps1 on the root of the USB drive.  
3. **Administrator Access:** You must be ableto run PowerShell as an Administrator on the target machine.  
4. **(Optional) Installers:** If you want to install Wazuh or Sysmon, place their respective installers (wazuh-agent\*.msi, Sysmon64.exe, sysmon.xml) on the root of the USB drive.

### **Part 2: Running the Hardening Script**

Follow these steps to execute the automated hardening process.

1. **Insert the USB Drive:** Plug the prepared USB drive into the target computer.  
2. **Open PowerShell as Administrator:**  
   * Click the Start Menu.  
   * Type PowerShell.  
   * Right-click on "Windows PowerShell" and select **"Run as administrator"**.  
3. **Navigate to the USB Drive:** In the PowerShell window, type the drive letter followed by a colon and press Enter. For example:  
   E:

4. **Execute the Script:** Run the script using one of the following methods. The script will display its progress, including \[VERIFIED\] or \[FAILED\] for each step.  
   * **Standard Execution:**  
     .\\Unified-Hardening.ps1

   * **To Demote Specific Admins:** List the usernames of the local admin accounts you wish to demote.  
     .\\Unified-Hardening.ps1 \-UsersToDemote "OldAdmin", "TempUser"

5. **Review the Output:** Once the script finishes, review the on-screen summary.  
6. **SECURE THE DRIVE:** Eject the USB drive immediately and store it in a physically secure location. It now contains the administrator password and BitLocker recovery key.

### **Part 3: Manual Fallback & Verification Guide**

If a step in the script shows \[FAILED\] or you wish to apply a setting manually, use the instructions below.

#### **1\. Administrator Accounts**

* **Goal:** Create a new admin SecOpsAdm and demote others.  
* **Manual GUI Steps:**  
  1. Press Win \+ R, type lusrmgr.msc, and press Enter.  
  2. **To create user:** Right-click on "Users" \> "New User...". Fill in SecOpsAdm as the username, provide a password, uncheck "User must change password...", check "Password never expires", and click "Create".  
  3. **To make user admin:** Go to "Groups", double-click "Administrators". Click "Add...", type SecOpsAdm, and click "OK".  
  4. **To demote a user:** In the same "Administrators" properties window, select the user you want to demote and click "Remove".

#### **2\. Microsoft Defender Hardening**

* **Goal:** Enable Tamper Protection, Controlled Folder Access (CFA), and Attack Surface Reduction (ASR).  
* **Manual GUI Steps:**  
  1. Go to **Settings \> Update & Security \> Windows Security \> Virus & threat protection**.  
  2. Under "Virus & threat protection settings", click "Manage settings".  
  3. **Tamper Protection:** Ensure the toggle is **On**.  
  4. **Controlled Folder Access:** Scroll down and click "Manage Controlled folder access". Ensure the toggle is **On**.  
  5. **ASR:** This cannot be fully configured from the GUI. You must use PowerShell.  
* **Manual PowerShell Command (run as admin):**  
  \# Enable Tamper Protection and CFA  
  Set-MpPreference \-EnableTamperProtection 1 \-EnableControlledFolderAccess Enabled

  \# Apply the ASR Rules  
  $asrRuleIds \= @("56a863a9-875e-4185-98a7-b882c64b5ce5", "3b576869-a4ec-4529-8536-b80a7769e899", "d4f940ab-401b-4efc-aadc-ad5f3c50688a", "9e6c285a-c97e-4ad4-a890-1ce04d5e0674", "c1db55ab-c21a-4637-bb3f-a12568109d35", "92e97fa1-2edf-4476-bdd6-9dd38f7c9c35")  
  Set-MpPreference \-AttackSurfaceReductionRules\_Ids $asrRuleIds \-AttackSurfaceReductionRules\_Actions Enabled

#### **3\. BitLocker Encryption**

* **Goal:** Encrypt the C: drive.  
* **Manual GUI Steps:**  
  1. Go to **Control Panel \> System and Security \> BitLocker Drive Encryption**.  
  2. Find your C: drive and click "**Turn on BitLocker**".  
  3. Follow the wizard to save your recovery key (save it to the USB drive) and start encryption.  
* **Manual Command Prompt Command (run as admin):**  
  manage-bde \-on C: \-skiphardwaretest

#### **4\. LAPS Configuration**

* **Goal:** Enable LAPS to manage the local Administrator password.  
* **Manual GUI Steps:** LAPS is primarily managed via Group Policy or Intune. For a standalone machine, PowerShell is the most direct method.  
* **Manual PowerShell Command (run as admin):**  
  \# Enable LAPS with recommended settings  
  Set-LapsPolicy \-Enable 1 \-AdminAccountName "Administrator" \-PasswordComplexity 4 \-PasswordLength 15 \-PasswordAgeDays 30

#### **5\. WDAC Policy**

* **Goal:** Apply a Code Integrity policy to restrict which applications can run.  
* **Manual GUI Steps:** This is an advanced feature with no simple GUI for application. PowerShell is the required method.  
* **Manual PowerShell Command (run as admin):**  
  1. Ensure WDAC\_Policy.xml is on your USB drive (e.g., E:\\).  
  2. Run the conversion and copy command:

\# Define paths  
$xmlPath \= "E:\\WDAC\_Policy.xml"  
$binaryPath \= "$env:SystemRoot\\System32\\CodeIntegrity\\SIPolicy.p7b"

\# Convert the XML policy to a binary file  
ConvertFrom-CIPolicy \-XmlFilePath $xmlPath \-BinaryFilePath $binaryPath

\# A reboot is required for the policy to take effect.

#### **6\. Firewall Hardening**

* **Goal:** Set the firewall to block all outbound connections by default and add specific exceptions.  
* **Manual GUI Steps:**  
  1. Press Win \+ R, type wf.msc, and press Enter.  
  2. In the main pane, click on "**Windows Defender Firewall Properties**".  
  3. For each tab (**Domain Profile**, **Private Profile**, **Public Profile**):  
     * Set "Outbound connections" to **Block**.  
     * Click "OK".  
  4. **To add rules:** Right-click "Outbound Rules" \> "New Rule...". Follow the wizard to create "Allow" rules for specific programs or ports (e.g., TCP Port 443 for HTTPS).  
* **Manual Command Prompt Command (run as admin):**  
  :: Set all profiles to block outbound traffic  
  netsh advfirewall set allprofiles firewallpolicy blockoutbound,allowinbound

  :: Add an allow rule for HTTPS (repeat for other needed ports)  
  netsh advfirewall firewall add rule name="Allow HTTPS-Out" dir=out action=allow protocol=TCP remoteport=443  
