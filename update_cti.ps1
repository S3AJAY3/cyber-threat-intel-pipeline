# update_cti.ps1

# Navigate to project directory (adjust if needed)
cd "C:\Users\alexj\Downloads\Cyber-threat-intel-pipeline"

# Run fetch + generate scripts
scripts/fetch_cti_feed.py
scripts/generate_reports.py


# Commit and push to GitHub
git add cti_data.json
git add scripts/generate_reports.py
git add docs/*.md
git add docs/index.md docs/_config.yml cti_data.json scripts/generate_reports.py update_cti.ps1
git commit -m "Daily CTI feed update"
git push origin main

# Automatically stage all changes
git add .

# Create a timestamped commit message
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm"
git commit -m " Auto update: CTI feed refresh on $timestamp"
