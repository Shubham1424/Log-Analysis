import csv
from collections import defaultdict

def parse_log_file(file_path):
    """Parse the log file and return the relevant data."""
    ip_counts = defaultdict(int)
    endpoint_counts = defaultdict(int)
    failed_login_attempts = defaultdict(int)
    
    with open(file_path, 'r') as log_file:
        for line in log_file:
            parts = line.split()
            
            # Extract IP Address
            ip_address = parts[0]
            ip_counts[ip_address] += 1
            
            # Extract the endpoint (resource path)
            try:
                # Assuming log format has "GET /path HTTP/1.1" part
                endpoint = parts[6]  # URL after GET/POST
                endpoint_counts[endpoint] += 1
            except IndexError:
                continue
            
            # Check for failed login attempts (HTTP status code 401 or specific failure messages)
            status_code = parts[8] if len(parts) > 8 else ""
            if status_code == "401":  # Failed login attempt
                failed_login_attempts[ip_address] += 1
            elif "Invalid credentials" in line:
                failed_login_attempts[ip_address] += 1
    
    return ip_counts, endpoint_counts, failed_login_attempts

def generate_report(ip_counts, endpoint_counts, failed_login_attempts, failed_threshold=10):
    """Generate a report for requests per IP, most accessed endpoint, and suspicious activity."""
    # Sort IP counts in descending order
    sorted_ip_counts = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)
    
    # Find most frequently accessed endpoint
    most_accessed_endpoint = max(endpoint_counts.items(), key=lambda x: x[1], default=None)
    
    # Find suspicious IPs
    suspicious_ips = {ip: count for ip, count in failed_login_attempts.items() if count > failed_threshold}
    
    # Display the results
    print("IP Address           Request Count")
    for ip, count in sorted_ip_counts:
        print(f"{ip:<20} {count}")
    
    if most_accessed_endpoint:
        print(f"\nMost Frequently Accessed Endpoint:\n{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    if suspicious_ips:
        print("\nSuspicious Activity Detected:")
        print("IP Address           Failed Login Attempts")
        for ip, count in suspicious_ips.items():
            print(f"{ip:<20} {count}")

def save_to_csv(ip_counts, endpoint_counts, failed_login_attempts, filename="log_analysis_results.csv"):
    """Save the analysis results to a CSV file."""
    with open(filename, 'w', newline='') as csvfile:
        fieldnames = ['Type', 'Identifier', 'Count']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        
        # Write IP Request Count data
        for ip, count in ip_counts.items():
            writer.writerow({'Type': 'IP Address', 'Identifier': ip, 'Count': count})
        
        # Write Endpoint Access Count data
        for endpoint, count in endpoint_counts.items():
            writer.writerow({'Type': 'Endpoint', 'Identifier': endpoint, 'Count': count})
        
        # Write Suspicious Activity data
        for ip, count in failed_login_attempts.items():
            if count > 10:
                writer.writerow({'Type': 'Suspicious Activity', 'Identifier': ip, 'Count': count})

def main(log_file_path, failed_threshold=10):
    # Parse the log file
    ip_counts, endpoint_counts, failed_login_attempts = parse_log_file(log_file_path)
    
    # Generate and display the report
    generate_report(ip_counts, endpoint_counts, failed_login_attempts, failed_threshold)
    
    # Save results to CSV
    save_to_csv(ip_counts, endpoint_counts, failed_login_attempts)

if __name__ == "__main__":
    log_file_path = "sample.log"  # Path to the log file
    main(log_file_path)
