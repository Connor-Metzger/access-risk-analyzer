# Run the full pipeline end to end with simulated manager responses (Windows).
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
python src\generate_data.py;      if ($LASTEXITCODE) { exit $LASTEXITCODE }
python src\analyzer.py;           if ($LASTEXITCODE) { exit $LASTEXITCODE }
python src\generate_packets.py;   if ($LASTEXITCODE) { exit $LASTEXITCODE }
python src\simulate_decisions.py; if ($LASTEXITCODE) { exit $LASTEXITCODE }   # demo only
python src\process_decisions.py;  if ($LASTEXITCODE) { exit $LASTEXITCODE }
python src\create_tickets.py      # dry run; add --live after configuring .env
Write-Host "`nDashboard: streamlit run src\dashboard.py   (binds to 127.0.0.1 only)"