import re
import csv
from collections import Counter

# Path to your log file
LOG_FILE_PATH = 'access.log'

# Threshold for suspicious activity (failed login attempts)
FAILED_LOGIN_THRESHOLD = 10

def count_requests_per_ip(log_file):
    ip_pattern = r'(\d+\.\d+\.\d+\.\d+)'  # Regex pattern for IP addresses
    ip_counts = Counter()

    with open(log_file, 'r') as file:
        for line in file:
            ip_match = re.search(ip_pattern, line)
            if ip_match:
                ip = ip_match.group(1)
                ip_counts[ip] += 1
    return ip_counts

def identify_most_accessed_endpoint(log_file):
    endpoint_pattern = r'\"[A-Z]+\s(/[^ ]+)'  # Regex pattern for endpoint (URLs)
    endpoint_counts = Counter()

    with open(log_file, 'r') as file:
        for line in file:
            endpoint_match = re.search(endpoint_pattern, line)
            if endpoint_match:
                endpoint = endpoint_match.group(1)
                endpoint_counts[endpoint] += 1
    if endpoint_counts:
        most_accessed = endpoint_counts.most_common(1)[0]
        return most_accessed
    return None

def detect_suspicious_activity(log_file, threshold=FAILED_LOGIN_THRESHOLD):
    failed_login_pattern = r'POST\s/.*\sHTTP/1.1"\s401\s.*'  # Regex pattern for failed logins (status 401)
    failed_login_counts = Counter()

    with open(log_file, 'r') as file:
        for line in file:
            if re.search(failed_login_pattern, line):
                ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                if ip_match:
                    ip = ip_match.group(1)
                    failed_login_counts[ip] += 1
    
    suspicious_ips = {ip: count for ip, count in failed_login_counts.items() if count >= threshold}
    return suspicious_ips

def save_results_to_csv(ip_counts, most_accessed_endpoint, suspicious_ips, output_file='log_analysis_results.csv'):
    with open(output_file, 'w', newline='') as file:
        writer = csv.writer(file)
        
        # Writing the Requests per IP
        writer.writerow(['IP Address', 'Request Count'])
        for ip, count in ip_counts.items():
            writer.writerow([ip, count])

        # Writing the Most Accessed Endpoint
        writer.writerow(['Endpoint', 'Access Count'])
        if most_accessed_endpoint:
            writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])

        # Writing Suspicious Activity
        writer.writerow(['IP Address', 'Failed Login Count'])
        for ip, count in suspicious_ips.items():
            writer.writerow([ip, count])

def main():
    # Count Requests per IP
    ip_counts = count_requests_per_ip(LOG_FILE_PATH)
    
    # Identify Most Accessed Endpoint
    most_accessed_endpoint = identify_most_accessed_endpoint(LOG_FILE_PATH)
    
    # Detect Suspicious Activity (failed login attempts)
    suspicious_ips = detect_suspicious_activity(LOG_FILE_PATH, FAILED_LOGIN_THRESHOLD)
    
    # Display results
    print("IP Address           Request Count")
    for ip, count in ip_counts.items():
        print(f"{ip:<20} {count}")

    print("\nMost Frequently Accessed Endpoint:")
    if most_accessed_endpoint:
        print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")
    
    print("\nSuspicious Activity Detected:")
    for ip, count in suspicious_ips.items():
        print(f"{ip:<20} {count}")
    
    # Save the results to CSV
    save_results_to_csv(ip_counts, most_accessed_endpoint, suspicious_ips)

if __name__ == '__main__':
    main()
