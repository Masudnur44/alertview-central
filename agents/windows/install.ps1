<#
  Installs the FINPAY SOC Windows agent. Run in an elevated PowerShell:
    powershell -ExecutionPolicy Bypass -File .\install.ps1 -Url https://soc.finpaytech.com -Key soc_xxxxxxxx
#>
param(
  [Parameter(Mandatory = $true)][string]$Url,
  [Parameter(Mandatory = $true)][string]$Key
)
$ErrorActionPreference = "Stop"
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw "Run this script as Administrator."
}

$Dir = "$env:ProgramData\FinpaySocAgent"
New-Item -ItemType Directory -Force -Path $Dir | Out-Null
Copy-Item -Force "$PSScriptRoot\finpay-soc-agent.ps1" "$Dir\finpay-soc-agent.ps1"
@{ url = $Url; key = $Key } | ConvertTo-Json | Set-Content "$Dir\config.json"

# Only SYSTEM and Administrators may read the folder (it holds the ingest key).
$acl = New-Object Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true, $false)
foreach ($id in @("NT AUTHORITY\SYSTEM", "BUILTIN\Administrators")) {
  $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($id, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")))
}
Set-Acl -Path $Dir -AclObject $acl

if (-not [Diagnostics.EventLog]::SourceExists("FinpaySocAgent")) { New-EventLog -LogName Application -Source "FinpaySocAgent" }

# Process-creation auditing with command lines (needed for process detections).
auditpol /set /subcategory:"Process Creation" /success:enable | Out-Null
$auditKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
if (-not (Test-Path $auditKey)) { New-Item -Path $auditKey -Force | Out-Null }
New-ItemProperty -Path $auditKey -Name ProcessCreationIncludeCmdLine_Enabled -Value 1 -PropertyType DWord -Force | Out-Null
auditpol /set /subcategory:"Logon" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"User Account Management" /success:enable | Out-Null
auditpol /set /subcategory:"Security Group Management" /success:enable | Out-Null

$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$Dir\finpay-soc-agent.ps1`""
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 1)
$settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 5) -StartWhenAvailable
Register-ScheduledTask -TaskName "FINPAY SOC Agent" -Action $action -Trigger $trigger -Settings $settings -User "SYSTEM" -RunLevel Highest -Force | Out-Null

# Connectivity test
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$body = @{ event_type = "agent.test"; host = $env:COMPUTERNAME; outcome = "success"; message = "finpay-soc-agent (windows) installed" } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri ($Url.TrimEnd("/") + "/api/public/ingest") -Body $body -ContentType "application/json" -Headers @{ "x-soc-key" = $Key } -UseBasicParsing | Out-Null
Write-Host "FINPAY SOC agent installed. It runs every minute as SYSTEM (Task Scheduler: 'FINPAY SOC Agent')."
