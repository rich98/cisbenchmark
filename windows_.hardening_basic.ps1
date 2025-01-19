# Windows 11 CIS Benchmark Hardening Script
# Author: [Your Name]
# Description: This script applies various CIS Benchmark recommendations for Windows 11.
# DISCLAIMER: Test thoroughly before using in production environments.

# Ensure script is run with administrative privileges
# This section ensures the script is executed with Administrator rights.
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script must be run as an Administrator. Exiting."
    exit 1
}

# Disable Guest Account
# Disabling the Guest account enhances security by preventing unauthorized access.
Write-Host "Disabling Guest Account..."
Set-LocalUser -Name Guest -Enabled $false

# Enforce Password Policies
# Configures password complexity, length, age, and history to meet security standards.
Write-Host "Configuring password policies..."
secedit /export /cfg C:\Windows\Temp\secpol.cfg
(Get-Content C:\Windows\Temp\secpol.cfg).replace("PasswordComplexity = 0", "PasswordComplexity = 1") |
    Set-Content C:\Windows\Temp\secpol.cfg
(Get-Content C:\Windows\Temp\secpol.cfg).replace("MinimumPasswordLength = 0", "MinimumPasswordLength = 14") |
    Set-Content C:\Windows\Temp\secpol.cfg
(Get-Content C:\Windows\Temp\secpol.cfg).replace("MinimumPasswordAge = 0", "MinimumPasswordAge = 1") |
    Set-Content C:\Windows\Temp\secpol.cfg
(Get-Content C:\Windows\Temp\secpol.cfg).replace("PasswordHistorySize = 0", "PasswordHistorySize = 24") |
    Set-Content C:\Windows\Temp\secpol.cfg
secedit /configure /db C:\Windows\Security\Database\secedit.sdb /cfg C:\Windows\Temp\secpol.cfg /areas SECURITYPOLICY

# Disable SMBv1
# Disabling SMBv1 protects against vulnerabilities inherent in this outdated protocol.
Write-Host "Disabling SMBv1..."
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart

# Enable Windows Firewall
# Ensures the Windows Firewall is active for all profiles to enhance network security.
Write-Host "Enabling Windows Firewall..."
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

# Configure Windows Defender Antivirus
# Configures Windows Defender to enable real-time monitoring, reporting, and PUA protection.
Write-Host "Configuring Windows Defender Antivirus..."
Set-MpPreference -DisableRealtimeMonitoring $false
Set-MpPreference -MAPSReporting Advanced
Set-MpPreference -SubmitSamplesConsent SendSafeSamples
Set-MpPreference -PUAProtection Enabled

# Enable BitLocker (if applicable)
# Enables BitLocker to encrypt the system drive using AES-256 encryption.
Write-Host "Enabling BitLocker..."
Enable-BitLocker -MountPoint C: -EncryptionMethod XtsAes256 -UsedSpaceOnly -SkipHardwareTest

# Disable Unnecessary Services
# Stops and disables services that are not essential and may pose security risks.
Write-Host "Disabling unnecessary services..."
Get-Service -Name "XboxGipSvc", "DiagTrack", "WMPNetworkSvc" | ForEach-Object {
    Stop-Service $_.Name -Force
    Set-Service $_.Name -StartupType Disabled
}

# Audit Policies
# Configures audit policies to log successful and failed events for all categories.
Write-Host "Configuring audit policies..."
audtpol /set /category:* /subcategory:* /success:enable /failure:enable

# Add Login Auditing
# Enables auditing for user logon and logoff events.
Write-Host "Enabling login auditing..."
AuditPol /Set /Subcategory:"Logon" /Success:Enable /Failure:Enable
AuditPol /Set /Subcategory:"Account Logon" /Success:Enable /Failure:Enable

# Set Account Lockout Policy
# Configures the account lockout policy to lock accounts after 3 failed attempts, requiring admin to unlock.
Write-Host "Setting account lockout policy..."
net accounts /lockoutthreshold:3 /lockoutduration:0 /lockoutwindow:30
Write-Host "Account lockout policy configured to require admin intervention for unlock."

# Enforce Account Complexity Requirements
# Enforces the use of complex passwords.
Write-Host "Enforcing account complexity requirements..."
secedit /export /cfg C:\Windows\Temp\complexity.cfg
(Get-Content C:\Windows\Temp\complexity.cfg).replace("PasswordComplexity = 0", "PasswordComplexity = 1") |
    Set-Content C:\Windows\Temp\complexity.cfg
secedit /configure /db C:\Windows\Security\Database\secedit.sdb /cfg C:\Windows\Temp\complexity.cfg /areas SECURITYPOLICY

# Disable Automatic Login
# Removes any automatic login credentials to prevent unauthorized access.
Write-Host "Disabling automatic login..."
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultUserName" -ErrorAction SilentlyContinue
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultPassword" -ErrorAction SilentlyContinue

# Disable Remote Desktop (if not needed)
# Disables Remote Desktop to reduce exposure to external attacks.
Write-Host "Disabling Remote Desktop..."
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1

# Disable Autorun
# Disables Autorun for all drives to prevent automatic execution of potentially malicious files.
Write-Host "Disabling Autorun..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255

# Harden Disk Access
# Configures disk access permissions to restrict unauthorized changes and access.
Write-Host "Hardening disk access..."
# Disable write access to removable drives not protected by BitLocker
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "DenyWriteAccess" -Value 1
# Restrict access to USB storage devices
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR" -Name "Start" -Value 4
Write-Host "Disk access hardened to restrict unauthorized modifications."

# Disable Unnecessary Scheduled Tasks
# Disables scheduled tasks that are not required and could be used for attacks.
Write-Host "Disabling unnecessary scheduled tasks..."
$tasks = @("\Microsoft\Windows\Customer Experience Improvement Program\Consolidator", 
           "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
           "\Microsoft\Windows\Defrag\ScheduledDefrag")
foreach ($task in $tasks) {
    Disable-ScheduledTask -TaskPath ($task -replace "\\[^\\]+$", "\\") -TaskName ($task -replace ".*\\", "")
}
Write-Host "Unnecessary scheduled tasks disabled."

# Enable Secure Boot
# Ensures Secure Boot is enabled to prevent unauthorized software from loading during boot.
Write-Host "Ensuring Secure Boot is enabled..."
if ((Confirm-SecureBootUEFI) -eq $false) {
    Write-Warning "Secure Boot is not enabled. Please enable it in the UEFI firmware settings."
} else {
    Write-Host "Secure Boot is enabled."
}

# Enable Tamper Protection for Windows Security
# Prevents unauthorized changes to security settings.
Write-Host "Enabling Tamper Protection..."
Set-MpPreference -DisableTamperProtection $false
Write-Host "Tamper Protection enabled."

# Enable Credential Guard
# Protects credentials by isolating them in a secure environment.
Write-Host "Enabling Credential Guard..."
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "LsaCfgFlags" /t REG_DWORD /d 1 /f
Write-Host "Credential Guard enabled."

# Finalizing
# Completion message and reminder to reboot the system.
Write-Host "CIS Benchmark hardening complete. Please reboot the system to apply all changes."
