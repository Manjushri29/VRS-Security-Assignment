import re
import csv
from collections import Counter, defaultdict

LOG_FILE = 'server_log.txt'
OUTPUT_FILE = 'log_analysis_results.csv'
FAILED_LOGIN_THRESHOLD = 10


def parse_log_file(log_file):
    ip_requests = Counter()
    endpoint_requests = Counter()
    failed_logins = defaultdict(int)

    with open(log_file, 'r') as file:
        for line in file:
            
            ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', line)
            ip_address = ip_match.group(0) if ip_match else None

           
            endpoint_match = re.search(r'"[A-Z]+\s(/[^\s]*)', line)
            endpoint = endpoint_match.group(1) if endpoint_match else None

            
            status_code_match = re.search(r'\s(\d{3})\s', line)
            status_code = int(status_code_match.group(1)) if status_code_match else None

            if ip_address:
                ip_requests[ip_address] += 1
            
            if endpoint:
                endpoint_requests[endpoint] += 1
            
            if status_code == 401 and ip_address:
                failed_logins[ip_address] += 1

    return ip_requests, endpoint_requests, failed_logins


def write_results_to_csv(ip_requests, most_accessed_endpoint, failed_logins, output_file):
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        
        writer.writerow(['IP Address', 'Request Count'])
        for ip, count in ip_requests.most_common():
            writer.writerow([ip, count])

        writer.writerow([]) 

      
        writer.writerow(['Endpoint', 'Access Count'])
        writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])

        writer.writerow([])  

        
        writer.writerow(['IP Address', 'Failed Login Count'])
        for ip, count in failed_logins.items():
            if count > FAILED_LOGIN_THRESHOLD:
                writer.writerow([ip, count])


def main():
    print("Processing log file...")


    ip_requests, endpoint_requests, failed_logins = parse_log_file(LOG_FILE)

   
    most_accessed_endpoint = endpoint_requests.most_common(1)[0] if endpoint_requests else ("None", 0)

    
    print("\nRequests per IP:")
    for ip, count in ip_requests.most_common():
        print(f"{ip:<20} {count}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    print("\nSuspicious Activity Detected:")
    for ip, count in failed_logins.items():
        if count > FAILED_LOGIN_THRESHOLD:
            print(f"{ip:<20} {count}")

   
    write_results_to_csv(ip_requests, most_accessed_endpoint, failed_logins, OUTPUT_FILE)
    print(f"\nResults saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
