# update_cti.ps1

# Run fetch + generate scripts with python
python scripts/fetch_cti_feed.py
if ($LASTEXITCODE -ne 0) {
    Write-Error "fetch_cti_feed.py failed. Exiting."
    exit 1
}

python scripts/generate_reports.py
if ($LASTEXITCODE -ne 0) {
    Write-Error "generate_reports.py failed. Exiting."
    exit 1
}

# Stage updated files
git add cti_data.json
git add docs/*.md
git add docs/index.md docs/_config.yml
git add scripts/generate_reports.py update_cti.ps1

# Create a timestamped commit message
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm"
git commit -m "Auto update: CTI feed refresh on $timestamp"

# Push to main branch
git push origin main
