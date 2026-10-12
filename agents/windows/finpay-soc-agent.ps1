<#
  FINPAY SOC Windows agent. Runs every minute as SYSTEM (scheduled task created by install.ps1).

  Forwards security-relevant Windows events to the SOC intake endpoint:
    4624 / 4625  logon success / failure            -> auth.login
    4720         user account created                -> account.created
    4728/4732/4756 member added to security group    -> group.member_added
    1102         security log cleared                -> log.cleared
    7045         service installed (System log)      -> service.installed
    4688         process creation (filtered)         -> process.start
  plus a heartbeat every run.

  Only events newer than the last forwarded record are read (bookmark per log).
  Events that cannot be delivered are kept in a spool file and retried next run.
#>
$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$Dir = "$env:ProgramData\FinpaySocAgent"
$Config = Get-Content "$Dir\config.json" -Raw | ConvertFrom-Json
$StatePath = "$Dir\state.json"
$SpoolPath = "$Dir\spool.jsonl"
$HostName = $env:COMPUTERNAME
$Version = "1.0.0"

$state = @{ Security = 0; System = 0 }
if (Test-Path $StatePath) {
  $saved = Get-Content $StatePath -Raw | ConvertFrom-Json
  foreach ($k in @("Security", "System")) { if ($saved.$k) { $state[$k] = [int64]$saved.$k } }
}

function Get-Data($evt) {
  $h = @{}
  foreach ($d in ([xml]$evt.ToXml()).Event.EventData.Data) { $h[$d.Name] = [string]$d.'#text' }
  return $h
}

function New-SocEvent($type, $evt, $user, $ip, $outcome, $message, $raw) {
  $e = [ordered]@{
    event_type  = $type
    host        = $HostName
    username    = $user
    outcome     = $outcome
    message     = if ($message.Length -gt 3900) { $message.Substring(0, 3900) } else { $message }
    occurred_at = $evt.TimeCreated.ToUniversalTime().ToString("o")
    raw         = $raw
  }
  if ($ip -and $ip -ne "-" -and $ip -ne "::1" -and $ip -ne "127.0.0.1") { $e.src_ip = $ip }
  return $e
}

$Suspicious = '(?i)\\(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|msbuild|installutil)\.exe$'
$OfficeOrBrowser = '(?i)\\(winword|excel|powerpnt|outlook|onenote|msaccess|acrord32|chrome|msedge|firefox)\.exe$'
$Interactive = @("2", "7", "10", "11")

function Read-Log($logName, $ids, $max = 2000) {
  $last = $state[$logName]
  $idFilter = ($ids | ForEach-Object { "EventID=$_" }) -join " or "
  $xpath = "*[System[($idFilter) and EventRecordID > $last]]"
  try {
    $events = Get-WinEvent -LogName $logName -FilterXPath $xpath -MaxEvents $max -ErrorAction Stop | Sort-Object RecordId
  } catch {
    if ($_.Exception.Message -match "No events were found") { return @() }
    throw
  }
  if ($events) { $state[$logName] = [int64]($events | Select-Object -Last 1).RecordId }
  return $events
}

$out = New-Object System.Collections.ArrayList

# First run: start from "now" rather than replaying the whole log.
if ($state.Security -eq 0) {
  foreach ($ln in @("Security", "System")) {
    $latest = Get-WinEvent -LogName $ln -MaxEvents 1 -ErrorAction SilentlyContinue
    if ($latest) { $state[$ln] = [int64]$latest.RecordId }
  }
} else {
  foreach ($evt in (Read-Log "Security" @(4624, 4625, 4720, 4728, 4732, 4756, 1102, 4688))) {
    $d = Get-Data $evt
    switch ($evt.Id) {
      4624 {
        if ($Interactive -contains $d.LogonType -or ($d.LogonType -eq "3" -and $d.IpAddress -and $d.IpAddress -ne "-")) {
          if ($d.TargetUserName -notmatch '\$$' -and $d.TargetUserName -ne "ANONYMOUS LOGON") {
            [void]$out.Add((New-SocEvent "auth.login" $evt $d.TargetUserName $d.IpAddress "success" "Logon type $($d.LogonType) by $($d.TargetDomainName)\$($d.TargetUserName)" @{ logon_type = $d.LogonType; workstation = $d.WorkstationName }))
          }
        }
      }
      4625 { [void]$out.Add((New-SocEvent "auth.login" $evt $d.TargetUserName $d.IpAddress "failure" "Failed logon (type $($d.LogonType), status $($d.Status)/$($d.SubStatus))" @{ logon_type = $d.LogonType; workstation = $d.WorkstationName })) }
      4720 { [void]$out.Add((New-SocEvent "account.created" $evt $d.TargetUserName $null "success" "Account $($d.TargetUserName) created by $($d.SubjectUserName)" @{ created_by = $d.SubjectUserName })) }
      { $_ -in 4728, 4732, 4756 } {
        $member = if ($d.MemberName -and $d.MemberName -ne "-") { $d.MemberName } else { $d.MemberSid }
        [void]$out.Add((New-SocEvent "group.member_added" $evt $member $null "success" "Added to group $($d.TargetUserName) by $($d.SubjectUserName)" @{ group = $d.TargetUserName; changed_by = $d.SubjectUserName }))
      }
      1102 { [void]$out.Add((New-SocEvent "log.cleared" $evt $null $null "success" "Security event log cleared" @{})) }
      4688 {
        $proc = $d.NewProcessName; $parent = $d.ParentProcessName
        if ($proc -match $Suspicious -or $parent -match $OfficeOrBrowser) {
          [void]$out.Add((New-SocEvent "process.start" $evt $d.SubjectUserName $null "success" "$parent -> $proc $($d.CommandLine)" @{ image = $proc; parent_image = $parent; command_line = $d.CommandLine }))
        }
      }
    }
  }
  foreach ($evt in (Read-Log "System" @(7045))) {
    $d = Get-Data $evt
    [void]$out.Add((New-SocEvent "service.installed" $evt $d.AccountName $null "success" "Service '$($d.ServiceName)' installed: $($d.ImagePath)" @{ service = $d.ServiceName; image = $d.ImagePath; start_type = $d.StartType }))
  }
}

[void]$out.Add([ordered]@{ event_type = "agent.heartbeat"; host = $HostName; outcome = "success"; message = "finpay-soc-agent (windows) $Version alive"; occurred_at = (Get-Date).ToUniversalTime().ToString("o") })

function Send-Batch($events) {
  $body = @{ events = @($events) } | ConvertTo-Json -Depth 6 -Compress
  Invoke-RestMethod -Method Post -Uri ($Config.url.TrimEnd("/") + "/api/public/ingest") -Body ([Text.Encoding]::UTF8.GetBytes($body)) `
    -ContentType "application/json" -Headers @{ "x-soc-key" = $Config.key } -TimeoutSec 30 -UseBasicParsing | Out-Null
}

# Retry anything spooled from earlier failures first, then this run's events.
$pending = New-Object System.Collections.ArrayList
if (Test-Path $SpoolPath) {
  Get-Content $SpoolPath | Where-Object { $_ } | ForEach-Object { [void]$pending.Add(($_ | ConvertFrom-Json)) }
  Remove-Item $SpoolPath -Force
}
$pending.AddRange($out)

try {
  for ($i = 0; $i -lt $pending.Count; $i += 400) {
    $chunk = $pending[$i..([Math]::Min($i + 399, $pending.Count - 1))]
    Send-Batch $chunk
  }
} catch {
  Write-EventLog -LogName Application -Source "FinpaySocAgent" -EventId 1001 -EntryType Warning -Message "SOC delivery failed: $($_.Exception.Message)" -ErrorAction SilentlyContinue
  $remaining = $pending[$i..($pending.Count - 1)]
  if ((Test-Path $SpoolPath) -and (Get-Item $SpoolPath).Length -gt 50MB) { $remaining = @() }
  $remaining | ForEach-Object { $_ | ConvertTo-Json -Depth 6 -Compress | Add-Content -Path $SpoolPath }
}

$state | ConvertTo-Json | Set-Content $StatePath
