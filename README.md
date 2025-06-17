PowerShell Windows Hardening Toolkit

This toolkit contains a set of PowerShell scripts designed to rapidly increase the security posture of a Windows 10/11 machine. It is intended to be run from a removable USB drive. The toolkit includes a main hardening script and a corresponding undo script to revert the changes.
CRITICAL SECURITY WARNING

This toolkit is powerful and handles sensitive information. You MUST understand and agree to the following before use:

    Secret Storage: The hardening script creates a log file (hardening-log.txt) containing a newly generated administrator password and the BitLocker recovery key in plain text.

    Physical Security: The USB drive containing these scripts and the generated logs must be removed from the computer immediately after use and stored in a physically secure location (e.g., a safe).

    Risk: Leaving this drive connected to a computer completely undermines the security changes and exposes critical recovery information.

By using these scripts, you accept full responsibility for the security of the generated secrets.
Features

The Unified-Hardening.ps1 script performs the following actions:

    Administrator Management: Creates a new, secure local administrator account (SecOpsAdm) and provides an option to demote existing non-essential admins.

    Microsoft Defender Hardening: Enables Tamper Protection, Controlled Folder Access (CFA), and a strong set of Attack Surface Reduction (ASR) rules to block common malware techniques.

    Disk Encryption: Enables BitLocker on the system drive (C:) using the TPM.

    LAPS Configuration: Configures the Windows Local Administrator Password Solution (LAPS) to manage the built-in Administrator account's password.

    Agent Installation (Optional): Automatically installs and configures the Wazuh agent and Sysmon if their installers (wazuh-agent*.msi, Sysmon64.exe, sysmon.xml) are present on the drive.

    Application Control (Optional): Deploys a default-allow Windows Defender Application Control (WDAC) policy if a WDAC_Policy.xml file is present.

    Firewall Lockdown: Switches the Windows Firewall to a "block outbound by default" policy, only allowing rules for essential traffic like DNS, HTTPS, and Windows Update.

    Rollback Capability: Generates a hardening-state.json file that logs all actions taken, enabling the Undo-Hardening.ps1 script to revert the changes.

Directory Structure

After running the hardening script on a machine named WORKSTATION-01, the following folder will be created on your USB drive:

\---PC-WORKSTATION-01-LOGS
    |   hardening-log.txt       (Log of actions and secrets)
    |   hardening-state.json    (State file for the undo script)

Usage Instructions
Prerequisites

    A USB flash drive.

    The script files (Unified-Hardening.ps1, Undo-Hardening.ps1).

    (Optional) The installers for any agents you wish to deploy (e.g., wazuh-agent-4.x.x-win64.msi, Sysmon64.exe, sysmon.xml).

    (Optional) A WDAC_Policy.xml file if you intend to use Application Control.

    Administrative privileges on the target machine.

1. Running the Hardening Script

This script applies the security configurations.

    Plug the USB drive into the target Windows machine.

    Open PowerShell as an Administrator.

    Navigate to your USB drive (e.g., cd E:).

    Run the script. Use the -UsersToDemote parameter to specify any current local admins you want to remove from the Administrators group.

Basic Example:

.\Unified-Hardening.ps1

Example with Demoting Users:
This command will demote the local users currentAdmin and testUser.

.\Unified-Hardening.ps1 -UsersToDemote "currentAdmin", "testUser"

Example with Custom Wazuh IP:

.\Unified-Hardening.ps1 -WazuhManagerIP "10.10.20.5"

    Follow the on-screen prompts. Once complete, the script will remind you to remove the drive.

    Eject and securely store the USB drive.

2. Running the Undo Script (Rollback)

This script reverts the changes made by the hardening script. It is interactive and requires the log folder that was created.

    Plug the same USB drive into the machine you wish to revert.

    Open PowerShell as an Administrator.

    Navigate to your USB drive (e.g., cd E:).

    Run the Undo-Hardening.ps1 script, pointing it to the log folder for that machine using the -LogFolderPath parameter.

Example:

.\Undo-Hardening.ps1 -LogFolderPath "E:\PC-WORKSTATION-01-LOGS"

    The script will display a menu of changes that were applied. You can choose to undo specific items one by one, or select option 8 to undo all changes automatically.

    Some actions, like disabling BitLocker or removing a WDAC policy, are high-risk and may require additional confirmation or a system reboot.

Disclaimer

This toolkit makes significant changes to a system's security configuration. Always test in a non-production environment first. The author(s) are not responsible for any data loss or system instability that may result from the use of these scripts. Use at your own risk.
