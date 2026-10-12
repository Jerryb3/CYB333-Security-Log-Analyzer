from detection import detect_brute_force
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
import re

from report_generator import generate_report

# Configuration
LOG_FILE = Path(__file__).with_name("sample_auth.log")
ALERT_THRESHOLD = 3
TIME_WINDOW_SECONDS = 60

# Store failed login timestamps by IP address
failed_attempts = defaultdict(list)

try:
    with LOG_FILE.open("r", encoding="utf-8") as file:
        for line in file:
            if "Failed password" not in line:
                continue

            match = re.search(
                r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"
                r".*from (\d{1,3}(?:\.\d{1,3}){3})",
                line
            )

            if match:
                timestamp = datetime.strptime(
                    match.group(1),
                    "%Y-%m-%d %H:%M:%S"
                )
                ip = match.group(2)
                failed_attempts[ip].append(timestamp)

    failed_counts = Counter({
        ip: len(times)
        for ip, times in failed_attempts.items()
    })

    print("=== Security Log Analyzer ===")
    print(f"Total failed logins: {sum(failed_counts.values())}")
    print()

    
    # Detect suspicious IPs using the reusable function
    detected_ips = detect_brute_force(
        failed_attempts,
        threshold=ALERT_THRESHOLD,
        window_seconds=TIME_WINDOW_SECONDS
    )

    # Display results for each IP address
    for ip, timestamps in failed_attempts.items():
        print(f"IP Address: {ip}")
        print(f"Failed Attempts: {len(timestamps)}")

        if ip in detected_ips:
            print(
                "ALERT: Possible brute-force activity "
                "within 60 seconds!"
            )

        print("-----------------------------")

    # Generate the security report
    generate_report(failed_counts, detected_ips)

    print(f"Suspicious IP addresses detected: {len(detected_ips)}")

except FileNotFoundError:
    print("Error: The log file could not be found.")

except (OSError, ValueError) as error:
    print(f"Error processing the log file: {error}")
