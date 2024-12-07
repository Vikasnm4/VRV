
import re
import csv
from collections import Counter, defaultdict

# Configurable threshold for suspicious activity
FAILED_LOGIN_THRESHOLD = 10

def parse_log_file(file_path):
    ip_requests = Counter()
    endpoint_requests = Counter()
    failed_login_attempts = defaultdict(int)

    # Regular expressions for parsing
    log_pattern = re.compile(r'(?P<ip>\d+\.\d+\.\d+\.\d+).*\s"GET\s(?P<endpoint>/\S*).*"\s(?P<status>\d{3})')
    failed_login_codes = ['401']

    try:
        with open(file_path, 'r') as log_file:
            for line in log_file:
                match = log_pattern.search(line)
                if match:
                    ip = match.group('ip')
                    endpoint = match.group('endpoint')
                    status = match.group('status')

                    # Count requests by IP
                    ip_requests[ip] += 1

                    # Count requests by endpoint
                    endpoint_requests[endpoint] += 1

                    # Detect failed login attempts
                    if status in failed_login_codes:
                        failed_login_attempts[ip] += 1

    except FileNotFoundError:
        print(f"Error: The file {file_path} was not found.")
        return None, None, None

    return ip_requests, endpoint_requests, failed_login_attempts


def save_results_to_csv(ip_requests, most_accessed_endpoint, suspicious_ips, output_file):
    with open(output_file, 'w', newline='') as csv_file:
        writer = csv.writer(csv_file)
        
        # Write IP requests
        writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_requests.items():
            writer.writerow([ip, count])
        writer.writerow([])

        # Write most accessed endpoint
        writer.writerow(["Most Frequently Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow(most_accessed_endpoint)
        writer.writerow([])

        # Write suspicious activity
        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_ips.items():
            writer.writerow([ip, count])


def main():
    log_file_path = input("Enter the path to the log file: ").strip()
    output_file_path = "log_analysis_results.csv"

    # Parse the log file
    ip_requests, endpoint_requests, failed_login_attempts = parse_log_file(log_file_path)
    if ip_requests is None:
        return

    # Sort and display IP requests
    sorted_ip_requests = dict(ip_requests.most_common())
    print("\nRequests per IP Address:")
    print(f"{'IP Address':<20} {'Request Count':<15}")
    for ip, count in sorted_ip_requests.items():
        print(f"{ip:<20} {count:<15}")

    # Identify the most accessed endpoint
    most_accessed_endpoint = endpoint_requests.most_common(1)[0]
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    # Detect suspicious activity
    suspicious_ips = {ip: count for ip, count in failed_login_attempts.items() if count > FAILED_LOGIN_THRESHOLD}
    print("\nSuspicious Activity Detected:")
    if suspicious_ips:
        print(f"{'IP Address':<20} {'Failed Login Attempts':<20}")
        for ip, count in suspicious_ips.items():
            print(f"{ip:<20} {count:<20}")
    else:
        print("No suspicious activity detected.")

    # Save results to CSV
    save_results_to_csv(sorted_ip_requests, most_accessed_endpoint, suspicious_ips, output_file_path)
    print(f"\nResults saved to {output_file_path}")


if __name__ == "__main__":
    main()
