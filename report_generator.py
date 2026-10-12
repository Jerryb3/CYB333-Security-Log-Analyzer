
from datetime import datetime
from pathlib import Path


def generate_report(failed_counts, detected_ips):
    """Generate a security report from failed login counts."""

    report_path = Path(__file__).with_name(
        "security_report.txt"
    )

    report_lines = [
        "CYB 333 - Security Log Analysis Report",
        "=" * 40,
        f"Generated: {datetime.now():%Y-%m-%d %H:%M:%S}",
        f"Total Failed Logins: {sum(failed_counts.values())}",
        f"Unique Source IPs: {len(failed_counts)}",
        "",
        "Failed Login Activity:",
    ]

    for ip, count in failed_counts.items():
        status = (
            "POSSIBLE BRUTE-FORCE"
            if ip in detected_ips
            else "No time-based alert"
        )

        report_lines.append(
            f"{ip} | Attempts: {count} | {status}"
        )

    report_path.write_text(
        "\n".join(report_lines) + "\n",
        encoding="utf-8"
    )

    print(f"\nSecurity report saved to: {report_path}")
