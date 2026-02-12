<#
.SYNOPSIS
  SecOps AI Alert Triage Automation (Simulated)
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $PSScriptRoot
$dataPath  = Join-Path $RepoRoot "data\sentinel_export_simulated_2026-02-02.jsonl"
$rulesPath = Join-Path $PSScriptRoot "rules.json"

$outCsv = Join-Path $RepoRoot "outputs\prioritized_alerts_2026-02-02.csv"
$outTxt = Join-Path $RepoRoot "outputs\executive_brief_2026-02-02.txt"
$outMd  = Join-Path $RepoRoot "outputs\incident_timeline_2026-02-02.md"

Write-Host "== SecOps AI Alert Triage ==" -ForegroundColor Cyan
Write-Host "Input:  $dataPath"
Write-Host "Rules:  $rulesPath"
Write-Host "Output: $outCsv"
Write-Host "Brief:  $outTxt"
Write-Host "Timeline:$outMd"

if (!(Test-Path $dataPath)) { throw "Missing data file: $dataPath" }
if (!(Test-Path $rulesPath)) { throw "Missing rules file: $rulesPath" }

$rules = Get-Content -Raw -Path $rulesPath | ConvertFrom-Json
$events = Get-Content -Path $dataPath | ForEach-Object { $_ | ConvertFrom-Json }

function Get-GeoDistanceMiles {
  param([string]$LocA, [string]$LocB)
  $map = @{
    "Boston, MA, US" = @{Lat=42.3601; Lon=-71.0589}
    "Frankfurt, DE"  = @{Lat=50.1109; Lon=8.6821}
    "Ashburn, VA, US"= @{Lat=39.0438; Lon=-77.4874}
  }
  if (!$map.ContainsKey($LocA) -or !$map.ContainsKey($LocB)) { return 0 }
  $a = $map[$LocA]; $b = $map[$LocB]
  $R = 3958.8
  $lat1 = [Math]::PI/180*$a.Lat; $lat2=[Math]::PI/180*$b.Lat
  $dlat = $lat2-$lat1
  $dlon = [Math]::PI/180*($b.Lon-$a.Lon)
  $h = [Math]::Sin($dlat/2)*[Math]::Sin($dlat/2) + [Math]::Cos($lat1)*[Math]::Cos($lat2)*[Math]::Sin($dlon/2)*[Math]::Sin($dlon/2)
  $c = 2*[Math]::Atan2([Math]::Sqrt($h), [Math]::Sqrt(1-$h))
  return [Math]::Round($R*$c,0)
}

function New-Enrichment {
  param([string]$RuleName)
  switch ($RuleName) {
    "Impossible Travel Sign-in" { return "User authenticated from distant locations within a short time window; validate travel and enforce session controls." }
    "Brute Force Then Success" { return "Multiple authentication failures followed by success from the same source; possible credential stuffing or password spray." }
    "Suspicious PowerShell from Office App" { return "Office process spawned encoded PowerShell with stealth flags; possible phishing-to-execution chain." }
    "Shadow Copy Deletion" { return "Shadow copies deleted—common ransomware precursor; treat as high-confidence destructive behavior." }
    default { return "Alert requires analyst review and validation." }
  }
}

$alerts = New-Object System.Collections.Generic.List[object]

# SOP-001 Impossible travel
$signin = $events | Where-Object { $_.EventType -eq "Signin" -and $_.ResultType -eq "0" } |
  Select-Object UserPrincipalName, Location, IPAddress, @{N="Time";E={[datetime]$_.TimeGenerated}}

$signinByUser = $signin | Group-Object UserPrincipalName
foreach ($g in $signinByUser) {
  $rows = $g.Group | Sort-Object Time
  for ($i=0; $i -lt $rows.Count; $i++) {
    for ($j=$i+1; $j -lt $rows.Count; $j++) {
      $mins = ($rows[$j].Time - $rows[$i].Time).TotalMinutes
      if ($mins -le 60 -and $mins -ge 0) {
        $dist = Get-GeoDistanceMiles -LocA $rows[$i].Location -LocB $rows[$j].Location
        if ($dist -ge 1000) {
          $alerts.Add([PSCustomObject]@{
            AlertId="ALERT-20260202-001"; RuleId="SOP-001"; AlertName="Impossible Travel Sign-in"; Severity="High";
            TimeGenerated=$rows[$j].Time.ToString("yyyy-MM-ddTHH:mm:ssZ"); Entity=$g.Name; Asset="AzureAD";
            Evidence="LoginA=$($rows[$i].Location) $($rows[$i].IPAddress); LoginB=$($rows[$j].Location) $($rows[$j].IPAddress); DistanceMi=$dist; WindowMin=$([Math]::Round($mins,0))";
            Mitre="TA0001|T1078"; Response="Reset password; Revoke sessions; Review MFA";
            Rationale="Two successful sign-ins from distant geos within 60 minutes."; Enrichment=(New-Enrichment "Impossible Travel Sign-in");
            PriorityScore=85
          })
        }
      }
    }
  }
}

# SOP-002 brute force then success
$signinAll = $events | Where-Object { $_.EventType -eq "Signin" } |
  Select-Object UserPrincipalName, ResultType, IPAddress, @{N="Time";E={[datetime]$_.TimeGenerated}}
$groups = $signinAll | Group-Object UserPrincipalName, IPAddress
foreach ($g in $groups) {
  $rows = $g.Group | Sort-Object Time
  for ($i=0; $i -lt $rows.Count; $i++) {
    $window = $rows | Where-Object { $_.Time -ge $rows[$i].Time -and $_.Time -le $rows[$i].Time.AddMinutes(10) }
    $fails = @($window | Where-Object { $_.ResultType -ne "0" }).Count
    $succ  = @($window | Where-Object { $_.ResultType -eq "0" }).Count
    if ($fails -ge 2 -and $succ -ge 1) {
      $alerts.Add([PSCustomObject]@{
        AlertId="ALERT-20260202-002"; RuleId="SOP-002"; AlertName="Brute Force Then Success"; Severity="High";
        TimeGenerated=($window | Where-Object { $_.ResultType -eq "0" } | Select-Object -First 1).Time.ToString("yyyy-MM-ddTHH:mm:ssZ");
        Entity=($window | Select-Object -First 1).UserPrincipalName; Asset="AzureAD";
        Evidence="IP=$($g.Name.Split(',')[1].Trim()); Failures=$fails; Successes=$succ; Window=10m";
        Mitre="TA0006|T1110"; Response="Block IP; Force MFA; Investigate account activity";
        Rationale="Multiple failures then a success from the same source."; Enrichment=(New-Enrichment "Brute Force Then Success"); PriorityScore=80
      })
      break
    }
  }
}

# SOP-003 suspicious powershell
$proc = $events | Where-Object { $_.EventType -eq "Process" }
foreach ($p in $proc) {
  if ($p.ProcessName -eq "powershell.exe" -and $p.ParentProcess -eq "winword.exe") {
    if ($p.CommandLine -match "-enc" -or $p.CommandLine -match "-w hidden" -or $p.CommandLine -match "-nop") {
      $alerts.Add([PSCustomObject]@{
        AlertId="ALERT-20260202-003"; RuleId="SOP-003"; AlertName="Suspicious PowerShell from Office App"; Severity="High";
        TimeGenerated=$p.TimeGenerated; Entity=$p.Account; Asset=$p.Hostname;
        Evidence="Parent=$($p.ParentProcess); CmdLine=$($p.CommandLine)";
        Mitre="TA0002|T1059.001"; Response="Isolate host; Collect triage package; Hunt similar activity";
        Rationale="Office spawned PowerShell with stealth flags/encoded content."; Enrichment=(New-Enrichment "Suspicious PowerShell from Office App"); PriorityScore=90
      })
    }
  }
}

# SOP-004 shadow copy deletion
foreach ($p in $proc) {
  if ($p.ProcessName -eq "vssadmin.exe" -and $p.CommandLine -match "delete shadows") {
    $alerts.Add([PSCustomObject]@{
      AlertId="ALERT-20260202-004"; RuleId="SOP-004"; AlertName="Shadow Copy Deletion"; Severity="Critical";
      TimeGenerated=$p.TimeGenerated; Entity=$p.Account; Asset=$p.Hostname;
      Evidence="CmdLine=$($p.CommandLine); Parent=$($p.ParentProcess)";
      Mitre="TA0040|T1490"; Response="Isolate host; Contain ransomware; Start IR process";
      Rationale="Shadow copy deletion is a high-confidence ransomware indicator."; Enrichment=(New-Enrichment "Shadow Copy Deletion"); PriorityScore=98
    })
  }
}

$alerts = $alerts | Sort-Object PriorityScore -Descending | Select-Object -Unique AlertName, Asset, TimeGenerated, *

$alerts | Select-Object AlertId, RuleId, AlertName, Severity, TimeGenerated, Entity, Asset, PriorityScore, Mitre, Response, Evidence, Rationale, Enrichment |
  Export-Csv -NoTypeInformation -Path $outCsv

$timeline = New-Object System.Collections.Generic.List[string]
$timeline.Add("# Incident Timeline (Simulated) – 2026-02-02")
$timeline.Add("")
$timeline.Add("| Time (UTC) | Signal | Summary |")
$timeline.Add("|---|---|---|")
foreach ($a in ($alerts | Sort-Object TimeGenerated)) {
  $timeline.Add("| $($a.TimeGenerated) | $($a.AlertName) | $($a.Rationale) |")
}
$timeline | Out-File -FilePath $outMd -Encoding UTF8

$total = @($alerts).Count
$crit = @($alerts | Where-Object { $_.Severity -eq "Critical" }).Count
$high = @($alerts | Where-Object { $_.Severity -eq "High" }).Count

$brief = New-Object System.Collections.Generic.List[string]
$brief.Add("SECOPS EXECUTIVE BRIEF – ALERT TRIAGE AUTOMATION")
$brief.Add("Date: 2026-02-02")
$brief.Add("Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
$brief.Add("")
$brief.Add("1) Executive Summary")
$brief.Add("This brief summarizes prioritized security signals detected from simulated Sentinel telemetry. The objective is to demonstrate an automation-driven triage workflow that reduces manual review and accelerates response decisions.")
$brief.Add("")
$brief.Add("2) Exposure Snapshot")
$brief.Add(" - Total Alerts: $total")
$brief.Add(" - Critical: $crit | High: $high")
$brief.Add("")
$brief.Add("3) Top Alerts (Highest Priority)")
foreach ($t in ($alerts | Sort-Object PriorityScore -Descending | Select-Object -First 3)) {
  $brief.Add(" - [$($t.Severity)] $($t.AlertName) on $($t.Asset) | Entity=$($t.Entity) | Score=$($t.PriorityScore)")
  $brief.Add("   Evidence: $($t.Evidence)")
  $brief.Add("   MITRE: $($t.Mitre)")
  $brief.Add("   Recommendation: $($t.Response)")
  $brief.Add("   Analyst Notes: $($t.Enrichment)")
}
$brief.Add("")
$brief.Add("4) Recommended Actions (Next 24 Hours)")
$brief.Add(" - Contain FIN-WS-014 immediately if shadow copy deletion confirmed; initiate incident response.")
$brief.Add(" - Validate suspicious PowerShell execution chain; hunt across endpoints for similar parent-child process patterns.")
$brief.Add(" - Investigate svc-backup sign-in sequence; enforce MFA and block suspicious IP where applicable.")
$brief.Add(" - Validate user travel for impossible travel alert; revoke sessions if unconfirmed.")
$brief.Add("")
$brief.Add("5) Notes")
$brief.Add("This project uses deterministic enrichment and simulated data for demonstration. Extend by connecting to Sentinel API, MDE Advanced Hunting, and automated ticketing.")
$brief.Add("")
$brief.Add("End of Brief")

$brief | Out-File -FilePath $outTxt -Encoding UTF8

Write-Host "Done." -ForegroundColor Green
Write-Host "Alerts CSV: $outCsv"
Write-Host "Brief:      $outTxt"
Write-Host "Timeline:   $outMd"
