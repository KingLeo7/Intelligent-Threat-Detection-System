content = """ENHANCED THREAT DETECTION SYSTEM
====================================

A GUI-based Python application for real-time file monitoring and ransomware detection using hashing, activity tracking, and visualization.

------------------------------------------------------------
🔐 AUTHENTICATION
------------------------------------------------------------

- Default Admin Login:
  Username: admin
  Password: admin

- Passwords are securely stored using SHA-256 hashing.
- Supports multiple users and roles.

------------------------------------------------------------
⚙️ FEATURES
------------------------------------------------------------

✔ Real-time file monitoring  
✔ Ransomware detection based on file modifications  
✔ SHA-256 file hashing for integrity checks  
✔ Interactive GUI built with Tkinter  
✔ Activity visualization using Matplotlib  
✔ CSV logging of scan history  
✔ JSON-based configuration system  
✔ Security alert system with popups  
✔ Safe scan notifications  
✔ Dark mode support  
✔ Recursive directory scanning  
✔ Export reports functionality  

------------------------------------------------------------
📁 HOW IT WORKS
------------------------------------------------------------

1. Select a directory to monitor
2. Start monitoring
3. The system scans files periodically
4. Tracks:
   - New files
   - Modified files
   - Deleted files
5. If modified files exceed threshold → ALERT triggered

------------------------------------------------------------
🚀 HOW TO RUN
------------------------------------------------------------

Run the application:

    python your_script_name.py

Then:
- Click "Start Monitoring"
- Choose directory if needed
- View logs and graph in real-time

------------------------------------------------------------
📊 OUTPUT FILES
------------------------------------------------------------

1. scan_history.csv
   - Logs all file activity

2. security_alerts.txt
   - Stores detected threat alerts

3. config.json
   - Stores user settings

4. users.json
   - Stores user credentials

------------------------------------------------------------
⚙️ SETTINGS OPTIONS
------------------------------------------------------------

- Scan Interval (seconds)
- Alert Threshold (number of modified files)
- Safe Scan Notification count
- Recursive scanning toggle
- Excluded file extensions

------------------------------------------------------------
📈 VISUALIZATION
------------------------------------------------------------

- Bar chart showing file activity
- Color indicators:
  Green → Safe
  Blue → New files
  Red → Modified files

------------------------------------------------------------
🛠️ TROUBLESHOOTING
------------------------------------------------------------

No files detected:
- Ensure selected directory contains files

No alerts:
- Increase sensitivity by lowering threshold

App not starting:
- Ensure Python and required libraries are installed

------------------------------------------------------------
📦 DEPENDENCIES
------------------------------------------------------------

Install required packages:

    pip install matplotlib

(Standard libraries used: tkinter, hashlib, threading, csv, json)

------------------------------------------------------------
⚠️ SECURITY NOTICE
------------------------------------------------------------

This tool is for:
✔ Learning and testing
✔ Personal system monitoring

Not for:
✘ Unauthorized surveillance
✘ Malicious use

------------------------------------------------------------
✅ END OF README
------------------------------------------------------------
"""

file_path = "/mnt/data/threat_detection_README.txt"
with open(file_path, "w", encoding="utf-8") as f:
    f.write(content)

file_path
