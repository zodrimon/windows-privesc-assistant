<#
.SYNOPSIS
Sets up a vulnerable Windows environment for end-to-end testing of privesc-assistant-win.

.DESCRIPTION
This script intentionally weakens permissions and creates misconfigurations to validate that
the privesc-assistant-win scanner can successfully detect them.

WARNING: ONLY RUN THIS ON A DISPOSABLE VIRTUAL MACHINE. IT MAKES THE SYSTEM INSECURE.

.EXAMPLE
.\setup_vulnerable_vm.ps1
#>

# 1. AlwaysInstallElevated
Write-Host "[+] Setting AlwaysInstallElevated policy..."
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\Installer" -Force | Out-Null
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -Value 1 -PropertyType DWord -Force | Out-Null
New-Item -Path "HKCU:\Software\Policies\Microsoft\Windows\Installer" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -Value 1 -PropertyType DWord -Force | Out-Null

# 2. Unquoted Service Path
Write-Host "[+] Creating Unquoted Service Path..."
$unquotedPath = "C:\Program Files\Vulnerable App\service.exe"
New-Item -Path "C:\Program Files\Vulnerable App" -ItemType Directory -Force | Out-Null
New-Item -Path $unquotedPath -ItemType File -Force | Out-Null
New-Service -Name "VulnUnquotedService" -BinaryPathName $unquotedPath -DisplayName "Vulnerable Unquoted Service" -StartupType Manual | Out-Null

# 3. Writable Autorun
Write-Host "[+] Creating writable AutoRun binary..."
$autorunPath = "C:\Temp\VulnAutorun.exe"
New-Item -Path "C:\Temp" -ItemType Directory -Force | Out-Null
New-Item -Path $autorunPath -ItemType File -Force | Out-Null
$acl = Get-Acl $autorunPath
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Users", "FullControl", "Allow")
$acl.AddAccessRule($rule)
Set-Acl $autorunPath $acl
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "VulnAutorun" -Value $autorunPath -PropertyType String -Force | Out-Null

# 4. Writable Scheduled Task
Write-Host "[+] Creating writable Scheduled Task..."
$taskPath = "C:\Temp\VulnTask.bat"
New-Item -Path $taskPath -ItemType File -Force | Out-Null
$acl = Get-Acl $taskPath
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Users", "FullControl", "Allow")
$acl.AddAccessRule($rule)
Set-Acl $taskPath $acl
$action = New-ScheduledTaskAction -Execute $taskPath
$trigger = New-ScheduledTaskTrigger -Daily -At 9am
Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "VulnScheduledTask" -Description "Vulnerable Task" -User "SYSTEM" -Force | Out-Null

Write-Host "Done! You can now run `privesc-assistant-win scan` to verify these findings."
