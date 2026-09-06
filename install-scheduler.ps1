# Registers a Windows Task Scheduler job that runs run-refresh.ps1 every Monday at 07:30 (local time).
# Run once from an elevated or normal PowerShell:  pwsh -File install-scheduler.ps1
$script = Join-Path $PSScriptRoot "run-refresh.ps1"
$action  = New-ScheduledTaskAction -Execute "pwsh.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$script`"" -WorkingDirectory $PSScriptRoot
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 07:30
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -RunOnlyIfNetworkAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 2)
Register-ScheduledTask -TaskName "Zero Project weekly refresh" -Action $action -Trigger $trigger -Settings $settings -Description "Pulls KEV, Anthropic ledger, Epoch, MSRC, Oracle, GitHub advisories; rebuilds zero.peries.ca data; pushes to GitHub." -Force | Out-Null
Write-Host "Registered 'Zero Project weekly refresh' (Mondays 07:30). Check with: Get-ScheduledTask -TaskName 'Zero Project weekly refresh'"
