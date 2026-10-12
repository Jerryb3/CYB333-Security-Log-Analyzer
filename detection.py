
from datetime import timedelta


def detect_brute_force(
    failed_attempts,
    threshold=3,
    window_seconds=60
):
    """Find IPs with repeated failures inside a time window."""

    detected_ips = set()

    for ip, timestamps in failed_attempts.items():
        sorted_times = sorted(timestamps)

        for index, start_time in enumerate(sorted_times):
            window_end = start_time + timedelta(
                seconds=window_seconds
            )

            count = sum(
                1 for timestamp in sorted_times[index:]
                if timestamp <= window_end
            )

            if count >= threshold:
                detected_ips.add(ip)
                break

    return detected_ips
