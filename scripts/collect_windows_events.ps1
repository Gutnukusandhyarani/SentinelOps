param(
  [string]$OutputPath = ".\data\windows-security.jsonl",
  [int]$MaxEvents = 500
)
$ErrorActionPreference = "Stop"
$ids = @(4624,4625,4688,4720,4728,4732,4756,1102,7045,4697)
$fullPath = [System.IO.Path]::GetFullPath($OutputPath)
$target = Split-Path -Parent $fullPath
if ($target -and !(Test-Path $target)) { New-Item -ItemType Directory -Path $target | Out-Null }
$events = Get-WinEvent -FilterHashtable @{LogName=@("Security","System"); Id=$ids} -MaxEvents $MaxEvents -ErrorAction Stop
$writer = [System.IO.StreamWriter]::new($fullPath, $false, [System.Text.UTF8Encoding]::new($false))
try {
  foreach ($event in $events) {
    $data = @{}
    try {
      [xml]$xml = $event.ToXml()
      foreach ($item in $xml.Event.EventData.Data) {
        if ($item.Name) { $data[[string]$item.Name] = [string]$item.'#text' }
      }
    } catch { }
    $record = [ordered]@{
      TimeCreated = $event.TimeCreated.ToString("o")
      EventID = [string]$event.Id
      Computer = [string]$event.MachineName
      Provider = [string]$event.ProviderName
      Channel = [string]$event.LogName
      Message = [string]$event.Message
      EventData = $data
    }
    $writer.WriteLine(($record | ConvertTo-Json -Depth 7 -Compress))
  }
} finally { $writer.Dispose() }
Write-Host "Exported $($events.Count) records to $OutputPath"
Write-Host "Read-only export: no event log or endpoint settings were changed."
