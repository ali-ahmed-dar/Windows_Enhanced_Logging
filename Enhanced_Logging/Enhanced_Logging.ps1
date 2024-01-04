echo "### Updating log file sizes ###"
wevtutil sl Security /ms:540100100
wevtutil sl Application /ms:256000100
wevtutil sl Setup /ms:256000100
wevtutil sl System /ms:256000100
wevtutil sl "Windows Powershell" /ms:256000100

echo "### Task Scheduler ###"
wevtutil sl Microsoft-Windows-TaskScheduler/Operational /e:true

echo "### Task Scheduler and Removable Storage ###"
Auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable
Auditpol /set /subcategory:"Removable Storage" /success:enable /failure:enable

echo "### Logon, Logoff, Lockout, Special Logon ###"
Auditpol /set /subcategory:"Logon" /success:enable /failure:enable
Auditpol /set /subcategory:"Logoff" /success:enable /failure:enable
Auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable
Auditpol /set /subcategory:"Special Logon" /success:enable /failure:enable

echo "### RDP ###"
wevtutil sl /q Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Admin /e:true
wevtutil sl /q Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Debug /e:true
wevtutil sl /q Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational /e:true


echo "### Terminal Services ###"
wevtutil sl /q Microsoft-Windows-TerminalServices-LocalSessionManager/Operational /e:true
wevtutil sl /q Microsoft-Windows-TerminalServices-LocalSessionManager/Admin /e:true
wevtutil sl /q Microsoft-Windows-TerminalServices-RemoteConnectionManager/Admin /e:true
wevtutil sl /q Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational /e:true
wevtutil sl /q Microsoft-Windows-TerminalServices-RDPClient/Operational /e:true

echo "### User account/Group management ###"
Auditpol /set /subcategory:"Computer Account Management" /success:enable /failure:enable
Auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
Auditpol /set /subcategory:"Distribution Group Management" /success:enable /failure:enable
Auditpol /set /subcategory:"Application Group Management" /success:enable /failure:enable
Auditpol /set /subcategory:"Other Account Management Events" /success:enable /failure:enable
Auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable

echo "### Endpoint Firewall rules & management ###"
Auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable
Auditpol /set /subcategory:"Authentication Policy Change" /success:enable /failure:enable
Auditpol /set /subcategory:"Filtering Platform Policy Change" /success:enable /failure:enable
Auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /success:enable /failure:enable
Auditpol /set /subcategory:"Security State Change" /success:enable /failure:enable

echo "### Process command-line logging (Process Creation, Process Termination, PNP Activity) ###"
Auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
Auditpol /set /subcategory:"Process Termination" /success:enable /failure:enable
Auditpol /set /subcategory:"Plug and Play Events" /success:enable /failure:enable
reg add "hklm\software\microsoft\windows\currentversion\policies\system\audit" /f /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1

echo "###  Force Advanced Audit ###"
reg add "hklm\System\CurrentControlSet\Control\Lsa" /v SCENoApplyLegacyAuditPolicy /t REG_DWORD /d 1 /f

echo "### Applocker ###"
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\SrpV2\Dll" /f /v EnforcementMode /t REG_DWORD /d 0
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\SrpV2\Exe" /f /v EnforcementMode /t REG_DWORD /d 0
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\SrpV2\Msi" /f /v EnforcementMode /t REG_DWORD /d 0
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\SrpV2\Script" /f /v EnforcementMode /t REG_DWORD /d 0

echo "### Powershell ###"
powershell Set-ExecutionPolicy RemoteSigned
copy-item .\profile.ps1 c:\windows\system32\WindowsPowerShell\v1.0\profile.ps1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell" /f /v ExecutionPolicy /t REG_SZ /d "RemoteSigned"
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /f /v EnableModuleLogging /t REG_DWORD /d 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /f /v EnableScriptBlockLogging /t REG_DWORD /d 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /f /v EnableInvocationHeader /t REG_DWORD /d 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /f /v EnableTranscripting /t REG_DWORD /d 1
mkdir C:\temp
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /f /v OutputDirectory /t REG_SZ /d "C:\temp"

echo "### Configure the Application Identity service ###"
sc.exe config appidsvc start= auto
Set-AppLockerPolicy -XmlPolicy .\rules.xml