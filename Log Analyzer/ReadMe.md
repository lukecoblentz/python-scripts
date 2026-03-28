# Python Log Analyzer

## Overview
This project is a Python-based log analysis tool designed to identify suspicious activity within system logs. It scans log files for security-related events such as failed logins, errors, warnings, and access denials, while also extracting and summarizing IP addresses associated with these events.

## Objective
- Analyze log files for suspicious activity  
- Identify and categorize security-related events  
- Extract IP addresses from suspicious entries  
- Summarize findings for quick analysis  

---

## Tools & Technologies
- Python 3  
- Regular Expressions (`re` module)  

---

## Features
- Detects suspicious log entries:
  - Failed login attempts  
  - Errors  
  - Warnings  
  - Access denied events  
- Counts occurrences of each event type  
- Extracts IP addresses from suspicious logs  
- Aggregates and summarizes suspicious IP activity  
- Clean and readable console output  

---

## How It Works
1. Reads a log file line by line  
2. Converts each line to lowercase for consistent matching  
3. Checks for suspicious keywords (`failed`, `error`, `warning`, `denied`)  
4. Flags suspicious entries and prints them  
5. Extracts IP addresses using regex  
6. Counts occurrences of each IP  
7. Displays a summary of findings  

---

## Example Output
=== Suspicious Entries ===
2026-03-20 10:02:01 WARNING Failed login from 203.0.113.7
2026-03-20 10:03:45 ERROR Access denied for admin from 198.51.100.25

=== Summary ===
Failed: 2
Error: 2
Warning: 0
Denied: 0

=== Suspicious IP Addresses ===
203.0.113.7 -> 2
198.51.100.25 -> 1

---

## Project Structure
python-scripts/
├── log_analyzer.py
├── sample.log
└── README.md

---

## Skills Demonstrated
- Python scripting and automation  
- File handling and data processing  
- Pattern matching with regular expressions  
- Basic threat detection and log analysis  
- Data aggregation and reporting  

---

## Future Improvements
- Accept log file as a command-line argument  
- Support additional log formats  
- Export results to a file (CSV/JSON)  
- Improve IP validation accuracy  
- Add timestamp analysis for event timelines  

---

## Conclusion
This project demonstrates how Python can be used to automate log analysis and identify potential security threats. By combining keyword detection with IP extraction and summarization, this tool provides a foundation for more advanced security monitoring and analysis workflows.