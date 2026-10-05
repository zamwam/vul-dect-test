# Normal colored terminal report
python security_auditor.py

# JSON for automation / SIEM
python security_auditor.py --json

# Beautiful HTML report
python security_auditor.py --html -o security-report.html

# Quiet mode (only errors + final report)
python security_auditor.py -q

# Debug everything
python security_auditor.py -v
