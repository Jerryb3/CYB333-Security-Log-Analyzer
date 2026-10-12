# CYB 333 Security Log Analyzer

## Project Overview

This project is a Python-based security automation tool designed to analyze authentication logs and identify suspicious failed login activity. It helps detect potential brute-force attacks by monitoring repeated failed login attempts from individual IP addresses.

## Features

- Reads and analyzes authentication log files.
- Identifies failed login attempts and source IP addresses.
- Detects three or more failed attempts within a 60-second window.
- Generates an automated security report.
- Handles missing log files without crashing.
- Includes automated unit tests to verify detection accuracy.

## Technologies Used

- Python 3
- Visual Studio Code
- Python standard libraries
- GitHub for version control

## Project Files

- `log_analyzer.py` — Main program for reading and analyzing logs.
- `detection.py` — Contains the brute-force detection logic.
- `report_generator.py` — Generates the security report.
- `test_detection.py` — Contains automated unit tests.
- `sample_auth.log` — Simulated authentication logs.
- `security_report.txt` — Automatically generated analysis results.

## How to Run

Open the project folder in VS Code and execute:

`python log_analyzer.py`

To run the automated tests:

`python -m unittest test_detection.py -v`

## Security Considerations

The analyzer uses a configurable detection threshold and time window to identify potentially suspicious activity. This helps reduce unnecessary alerts from login failures spread over longer periods.

The project uses simulated authentication data rather than actual user credentials. It is intended as an educational demonstration of security automation, not a replacement for a production security monitoring system.

## Testing

The project includes tests for rapid failed login attempts, failed attempts spread over time, and attempts below the detection threshold. Missing-file handling was also manually tested.

## Conclusion

This project demonstrates how Python can automate security log analysis, identify possible brute-force activity, and generate reports that help security analysts investigate suspicious events.