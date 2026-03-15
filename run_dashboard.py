import subprocess
import sys

subprocess.Popen([
sys.executable,
'-m',
'streamlit',
'run',
'dashboard.py'
])

print("Dashboard Running ✅")
print("Open → http://localhost:8501")