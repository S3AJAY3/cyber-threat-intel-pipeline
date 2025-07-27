# update_cti.ps1

# Navigate to project directory (adjust if needed)
cd "C:\Users\alexj\Downloads\Cyber-threat-intel-pipeline"

# Run fetch + generate scripts
scripts/fetch_cti_feed.py
scripts/generate_reports.py


# Commit and push to GitHub
git add docs/index.md docs/_config.yml cti_data.json scripts/generate_reports.py update_cti.ps1
git commit -m "Daily CTI feed update"
git push origin main
