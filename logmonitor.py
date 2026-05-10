import re
import csv
import sys
import json
from collections import defaultdict
from datetime import datetime


# Load configuration
with open("config.json", "r") as config_file:
    config = json.load(config_file)

LOG_FILE = sys.argv[1] if len(sys.argv) > 1 else "auth.log"
OUTPUT_FILE = config["output_file"]
HTML_OUTPUT_FILE = config["html_output_file"]
THRESHOLD = config["threshold"]
BRUTE_FORCE_WINDOW = config["brute_force_window_seconds"]

# CIS Control mappings for audit findings
# CIS Control 4.3 = Controlled Use of Administrative Privileges
# CIS Control 6.2 = Activate Audit Logging
CIS_MAPPING = {
    "CRITICAL": "Violates CIS Control 4.3 - Controlled Use of Admin Privileges; Possible violation of CIS Control 18.3 - Penetration Testing",
    "HIGH": "Violates CIS Control 4.3 - Controlled Use of Admin Privileges",
    "LOW": "Monitor per CIS Control 6.2 - Activate Audit Logging"
}

ip_data = defaultdict(lambda: {
    "count": 0,
    "first_seen": None,
    "last_seen": None,
    "usernames": set(),
    "timestamps": []
})

failed_attempts = defaultdict(int)

with open(LOG_FILE, "r") as f:
    for line in f:
        if "Failed password" in line:
            match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
            if match:
                ip = match.group(1)
                failed_attempts[ip] += 1
                ip_data[ip]["count"] += 1

                # Extract timestamp (e.g., "Apr 11 10:30:45")
                time_match = re.search(r'(\w+ \d+ \d+:\d+:\d+)', line)
                if time_match:
                    timestamp = time_match.group(1)
                    if ip_data[ip]["first_seen"] is None:
                        ip_data[ip]["first_seen"] = timestamp
                    ip_data[ip]["last_seen"] = timestamp
                    ip_data[ip]["timestamps"].append(timestamp)

                # Extract username (e.g., "root", "admin")
                user_match = re.search(r'for (\S+) from', line)
                if user_match:
                    ip_data[ip]["usernames"].add(user_match.group(1))
            

def is_brute_force(timestamps, window=BRUTE_FORCE_WINDOW):
    # Convert timestamp strings to datetime objects
    fmt = "%b %d %H:%M:%S"
    current_year = datetime.now().year
    times = []
    for t in timestamps:
        try:
            times.append(datetime.strptime(f"{current_year} {t}", f"%Y {fmt}"))
        except:
            continue

    # Sort times and check if any two consecutive ones are within the window
    times.sort()
    for i in range(1, len(times)):
        diff = (times[i] - times[i-1]).total_seconds()
        if diff <= window:
            return True
    return False

def generate_html_report(ip_data, summary, log_file, threshold):
    # Build rows for each IP finding
    rows = ""
    for ip, data in ip_data.items():
        count = data["count"]
        usernames = ", ".join(data["usernames"])
        first_seen = data["first_seen"]
        last_seen = data["last_seen"]
        brute_force = is_brute_force(data["timestamps"])

        if count >= threshold and brute_force:
            risk = "CRITICAL"
            action = "Block IP immediately - automated brute force detected"
            cis = CIS_MAPPING["CRITICAL"]
            row_color = "#fff0f0"
            badge_color = "#cc0000"
        elif count >= threshold:
            risk = "HIGH"
            action = "Block IP and Investigate immediately"
            cis = CIS_MAPPING["HIGH"]
            row_color = "#fff8f0"
            badge_color = "#ff6600"
        else:
            risk = "LOW"
            action = "Monitor for further activity"
            cis = CIS_MAPPING["LOW"]
            row_color = "#f0fff0"
            badge_color = "#007700"

        rows += f"""
        <tr style="background-color: {row_color};">
            <td>{ip}</td>
            <td>{usernames}</td>
            <td style="text-align:center;">{count}</td>
            <td>{first_seen}</td>
            <td>{last_seen}</td>
            <td style="text-align:center;">{" YES" if brute_force else "NO"}</td>
            <td style="text-align:center;">
                <span style="background:{badge_color};color:white;padding:3px 10px;border-radius:12px;font-weight:bold;font-size:12px;">
                    {risk}
                </span>
            </td>
            <td style="font-size:12px;">{cis}</td>
            <td>{action}</td>
        </tr>
        """

    # Build full HTML
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Access Log Risk Assessment Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 40px;
            background-color: #f5f5f5;
            color: #333;
        }}
        .header {{
            background-color: #1a1a2e;
            color: white;
            padding: 30px;
            border-radius: 8px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            margin: 0;
            font-size: 22px;
            letter-spacing: 1px;
        }}
        .header p {{
            margin: 5px 0 0 0;
            font-size: 13px;
            color: #aaa;
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 15px;
            margin-bottom: 30px;
        }}
        .summary-card {{
            background: white;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
            box-shadow: 0 2px 6px rgba(0,0,0,0.08);
        }}
        .summary-card .number {{
            font-size: 36px;
            font-weight: bold;
            margin: 5px 0;
        }}
        .summary-card .label {{
            font-size: 12px;
            color: #888;
            text-transform: uppercase;
        }}
        .critical {{ color: #cc0000; }}
        .high {{ color: #ff6600; }}
        .low {{ color: #007700; }}
        .total {{ color: #1a1a2e; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 6px rgba(0,0,0,0.08);
            font-size: 13px;
        }}
        th {{
            background-color: #1a1a2e;
            color: white;
            padding: 12px 10px;
            text-align: left;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        td {{
            padding: 10px;
            border-bottom: 1px solid #eee;
        }}
        .section-title {{
            font-size: 16px;
            font-weight: bold;
            color: #1a1a2e;
            margin: 30px 0 10px 0;
            padding-bottom: 5px;
            border-bottom: 2px solid #1a1a2e;
        }}
        .footer {{
            margin-top: 30px;
            font-size: 11px;
            color: #aaa;
            text-align: center;
        }}
    </style>
</head>
<body>

    <div class="header">
        <h1>ACCESS LOG RISK ASSESSMENT REPORT</h1>
        <p>Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} &nbsp;|&nbsp; Log File: {log_file} &nbsp;|&nbsp; Detection Threshold: {threshold} failed attempts</p>
    </div>

    <div class="summary-grid">
        <div class="summary-card">
            <div class="label">Total IPs Analysed</div>
            <div class="number total">{summary["total"]}</div>
        </div>
        <div class="summary-card">
            <div class="label">Critical Risk</div>
            <div class="number critical">{summary["critical"]}</div>
        </div>
        <div class="summary-card">
            <div class="label">High Risk</div>
            <div class="number high">{summary["high"]}</div>
        </div>
        <div class="summary-card">
            <div class="label">Low Risk</div>
            <div class="number low">{summary["low"]}</div>
        </div>
    </div>

    <div class="section-title">ATTACK DETAILS</div>


    <table>
        <thead>
            <tr>
                <th>IP Address</th>
                <th>Targeted Usernames</th>
                <th>Failed Attempts</th>
                <th>First Seen</th>
                <th>Last Seen</th>
                <th>Brute Force</th>
                <th>Risk Level</th>
                <th>CIS Control Reference</th>
                <th>Action Required</th>
            </tr>
        </thead>
        <tbody>
            {rows}
        </tbody>
    </table>



</body>
</html>"""

    with open(HTML_OUTPUT_FILE, "w") as f:
        f.write(html)

    print(f"HTML Report saved to {HTML_OUTPUT_FILE}")

# Calculate summary statistics
total_ips = len(ip_data)
critical_count = 0
high_count = 0
low_count = 0

for ip, data in ip_data.items():
    count = data["count"]
    brute_force = is_brute_force(data["timestamps"])
    if count >= THRESHOLD and brute_force:
        critical_count += 1
    elif count >= THRESHOLD:
        high_count += 1
    else:
        low_count += 1

with open(OUTPUT_FILE, "w", newline="") as csvfile:
    writer = csv.writer(csvfile)

    # Executive Summary Block
    writer.writerow(["AUDIT REPORT — ACCESS LOG RISK ASSESSMENT"])
    writer.writerow(["Generated", datetime.now().strftime("%Y-%m-%d %H:%M:%S")])
    writer.writerow(["Log File Analysed", LOG_FILE])
    writer.writerow(["Detection Threshold", f"{THRESHOLD} failed attempts"])
    writer.writerow([])
    writer.writerow(["SUMMARY"])
    writer.writerow(["Total IPs Analysed", total_ips])
    writer.writerow(["Critical Risk IPs", critical_count])
    writer.writerow(["High Risk IPs", high_count])
    writer.writerow(["Low Risk IPs", low_count])
    writer.writerow([])
    writer.writerow(["DETAILED FINDINGS"])

    # Column headers
    writer.writerow([
        "IP Address",
        "Targeted Usernames",
        "Failed Attempts",
        "First Seen",
        "Last Seen",
        "Brute Force Detected",
        "Risk Level",
        "CIS Control Reference",
        "Action Required"
    ])

    for ip, data in ip_data.items():
        count = data["count"]
        usernames = ", ".join(data["usernames"])
        first_seen = data["first_seen"]
        last_seen = data["last_seen"]

        brute_force = is_brute_force(data["timestamps"])

        if count >= THRESHOLD and brute_force:
            risk = "CRITICAL"
            action = "Block IP immediately AUTOMATED BRUTE FORCE DETECTED"
        elif count >= THRESHOLD:
            risk = "HIGH"
            action = "Block IP and Investigate immediately"
        else:
            risk = "LOW"
            action = "Monitor for further activity"

        cis_reference = CIS_MAPPING[risk]
        writer.writerow([ip, usernames, count, first_seen, last_seen, "YES" if brute_force else "NO", risk, cis_reference, action])

print(f"Report saved to {OUTPUT_FILE}")

# Generate HTML report
summary = {
    "total": total_ips,
    "critical": critical_count,
    "high": high_count,
    "low": low_count
}
generate_html_report(ip_data, summary, LOG_FILE, THRESHOLD)