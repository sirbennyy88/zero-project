# Local weekly refresh + publish (alternative to the GitHub Actions schedule).
# Usage: pwsh -File run-refresh.ps1        (register with install-scheduler.ps1 to run every Monday)
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
if (-not $env:GITHUB_TOKEN) { try { $env:GITHUB_TOKEN = (gh auth token) } catch { Write-Warning "no GITHUB_TOKEN / gh login: ecosystem counts will come from cache" } }
python data-src\refresh.py 2>&1 | Tee-Object -FilePath data-src\cache\last-local-run.log
git add zeroweek-data.js zeroweek-data.json zeroweek-data.csv feed.xml data-src\cache\*.json
git diff --cached --quiet; if ($LASTEXITCODE -ne 0) { git commit -m "data: local refresh $(Get-Date -Format yyyy-MM-dd)"; git push }
