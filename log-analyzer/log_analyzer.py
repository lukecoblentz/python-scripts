## Log Analyzer

# Import re
import re

# Open Sample File
with open("sample.log", "r") as file:
    lines = file.readlines()

# Counters
ip_counts = {}
failed_count = 0
error_count = 0
warning_count = 0
denied_count = 0

# Suspicious Entries
print("\n=== Suspicious Entries ===")
for line in lines:
    lower_line = line.lower()
    is_suspicious = False

    if "failed" in lower_line:
        failed_count += 1
        is_suspicious = True

    elif "error" in lower_line:
        error_count += 1
        is_suspicious = True

    elif "warning" in lower_line:
        warning_count += 1
        is_suspicious = True

    elif "denied" in lower_line:
        denied_count += 1
        is_suspicious = True
    
    if is_suspicious:
        print(line.strip())

        ips = re.findall(r"\d+\.\d+\.\d+\.\d+", line)

        for ip in ips:
            ip_counts[ip] = ip_counts.get(ip, 0) + 1

# Summary
print("\n=== Summary ===")
print("Failed:", failed_count)
print("Error:", error_count)
print("Warning:", warning_count)
print("Denied:", denied_count)

# Suspicious IPs
print("\n=== Suspicious IP Addresses ===")
for ip, count in ip_counts.items():
    print(f"{ip} -> {count}")

