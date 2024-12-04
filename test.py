import csv
from collections import defaultdict

# Configurable threshold for failed login attempts
FAILED_LOGIN_THRESHOLD = 10

def parse_log_file(file_path):
    """Reads the log file and extracts necessary data."""
    ip_request_counts = defaultdict(int)
    endpoint_counts = defaultdict(int)
    failed_logins = defaultdict(int)
    
    try:
        with open(file_path, 'r') as file:
            for line in file:
                try:
                    parts = line.split()
                    ip = parts[0]
                    request = parts[5] + " " + parts[6]
                    status_code = parts[8]
                    message = " ".join(parts[9:])
                    
                    # Count requests per IP
                    ip_request_counts[ip] += 1
                    
                    # Count endpoint accesses
                    endpoint = parts[6]
                    endpoint_counts[endpoint] += 1
                    
                    # Identify failed login attempts
                    if status_code == "401" or "Invalid credentials" in message:
                        failed_logins[ip] += 1
                except IndexError:
                    print(f"Malformed log line skipped: {line.strip()}")
    except FileNotFoundError:
        print(f"Error: Log file '{file_path}' not found.")
        return None, None, None
    
    return ip_request_counts, endpoint_counts, failed_logins

def write_to_csv(ip_data, endpoint_data, suspicious_data, output_file):
    """Writes the analysis results to a CSV file."""
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        
        # Write IP request counts
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_data:
            writer.writerow([ip, count])
        
        writer.writerow([])
        
        # Write most accessed endpoint
        writer.writerow(["Endpoint", "Access Count"])
        for endpoint, count in endpoint_data:
            writer.writerow([endpoint, count])
        
        writer.writerow([])
        
        # Write suspicious activity
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_data:
            writer.writerow([ip, count])

def main():
    # File paths
    log_file_path = 'sample.log'
    output_csv_file = 'log_analysis_results.csv'
    
    # Parse log file
    ip_request_counts, endpoint_counts, failed_logins = parse_log_file(log_file_path)
    
    if ip_request_counts is None:
        return
    
    # Sort and analyze data
    sorted_ip_requests = sorted(ip_request_counts.items(), key=lambda x: x[1], reverse=True)
    sorted_endpoints = sorted(endpoint_counts.items(), key=lambda x: x[1], reverse=True)
    suspicious_activity = [(ip, count) for ip, count in failed_logins.items() if count > FAILED_LOGIN_THRESHOLD]
    
    # Display results
    print("IP Address Request Counts:")
    print(f"{'IP Address':<20} {'Request Count':<15}")
    for ip, count in sorted_ip_requests:
        print(f"{ip:<20} {count:<15}")
    print()
    
    if sorted_endpoints:
        most_accessed_endpoint, access_count = sorted_endpoints[0]
        print("Most Frequently Accessed Endpoint:")
        print(f"{most_accessed_endpoint} (Accessed {access_count} times)")
    print()
    
    print("Suspicious Activity Detected:")
    print(f"{'IP Address':<20} {'Failed Login Attempts':<15}")
    for ip, count in suspicious_activity:
        print(f"{ip:<20} {count:<15}")
    print()
    
    # Save results to CSV
    write_to_csv(sorted_ip_requests, sorted_endpoints, suspicious_activity, output_csv_file)
    print(f"Results saved to {output_csv_file}")

if __name__ == "__main__":
    main()
