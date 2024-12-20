import pandas as pd
import logging

# Setup logging configuration for better error tracking
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def log_to_csv(log_file_path, output_csv_path):
    """
    Converts the log file to a CSV file using pandas and split method.
    
    Args:
        log_file_path (str): Path to the log file.
        output_csv_path (str): Path to the output CSV file.
    """
    log_data = []
    
    try:
        with open(log_file_path, 'r') as log_file:
            for line in log_file:
                parts = line.split(' ')
                
                if len(parts) < 10:  # Skip malformed lines
                    continue

                ip = parts[0]
                timestamp = parts[3][1:] + " " + parts[4][:-1]
                method = parts[5][1:]
                endpoint = parts[6]
                http_version = parts[7][:-1]
                status_code = parts[8]
                size = parts[9]
                message = " ".join(parts[10:]).strip() if len(parts) > 10 else ""

                log_data.append({
                    "ip": ip,
                    "timestamp": timestamp,
                    "method": method,
                    "endpoint": endpoint,
                    "http_version": http_version,
                    "status_code": status_code,
                    "size": size,
                    "message": message
                })

        # Convert to DataFrame and save to CSV
        df = pd.DataFrame(log_data)
        df.to_csv(output_csv_path, index=False)
        logging.info(f"Log data successfully converted to {output_csv_path}")
    
    except Exception as e:
        logging.error(f"Error while processing the log file: {e}")
        raise

def count_requests(csv_file_path):
    """
    Count the number of requests made by each IP address using a CSV file.
    
    Args:
        csv_file_path (str): Path to the CSV file.
    
    Returns:
        pd.DataFrame: DataFrame with IP addresses and their request counts, sorted in descending order.
    """
    try:
        df = pd.read_csv(csv_file_path)
        ip_counts = df['ip'].value_counts().reset_index()
        ip_counts.columns = ['IP Address', 'Request Count']
        return ip_counts
    except Exception as e:
        logging.error(f"Error reading CSV file: {e}")
        raise

def most_frequent_endpoint(csv_file_path):
    """
    Identify the most frequently accessed endpoint using a CSV file.
    
    Args:
        csv_file_path (str): Path to the CSV file.
    
    Returns:
        str, int: The most frequently accessed endpoint and its access count.
    """
    try:
        df = pd.read_csv(csv_file_path)
        endpoint_counts = df['endpoint'].value_counts()
        most_accessed_endpoint = endpoint_counts.idxmax()
        access_count = endpoint_counts.max()
        return most_accessed_endpoint, access_count
    except Exception as e:
        logging.error(f"Error processing CSV file: {e}")
        raise

def suspicious_activity(csv_file_path, threshold=10):
    """
    Detect suspicious activity (potential brute force login attempts) using a CSV file.
    
    Args:
        csv_file_path (str): Path to the CSV file.
        threshold (int): Number of failed attempts to consider an IP suspicious.
    
    Returns:
        pd.DataFrame: DataFrame with suspicious IPs and their failed login counts.
    """
    try:
        df = pd.read_csv(csv_file_path)
        failed_logins = df[
            (df['status_code'] == '401') | (df['message'].str.contains("Invalid credentials", na=False))
        ]
        
        suspicious_ips = failed_logins['ip'].value_counts().reset_index()
        suspicious_ips.columns = ['IP Address', 'Failed Login Attempts']
        suspicious_ips = suspicious_ips[suspicious_ips['Failed Login Attempts'] >= threshold]
        return suspicious_ips
    except Exception as e:
        logging.error(f"Error processing suspicious activity: {e}")
        raise

def save_results_to_csv(output_file, ip_counts, most_accessed_endpoint, suspicious_ips):
    """
    Save the analysis results to a single CSV file with structured sections using pandas.
    
    Args:
        output_file (str): Path to the output CSV file.
        ip_counts (pd.DataFrame): DataFrame of requests per IP.
        most_accessed_endpoint (tuple): Tuple of the most accessed endpoint and its count.
        suspicious_ips (pd.DataFrame): DataFrame of suspicious IPs.
    """
    try:
        # Display results in terminal
        print("Requests per IP Address:")
        print(ip_counts)
        print("\nMost Frequently Accessed Endpoint:")
        print(f"Endpoint: {most_accessed_endpoint[0]}, Access Count: {most_accessed_endpoint[1]}")
        print("\nSuspicious Activity Detected:")
        if not suspicious_ips.empty:
            print(suspicious_ips)
        else:
            print("No suspicious activity detected.")

        # Prepare CSV output
        requests_header = pd.DataFrame([['Requests per IP Address']], columns=["Section"])
        endpoint_header = pd.DataFrame([['Most Frequently Accessed Endpoint']], columns=["Section"])
        suspicious_header = pd.DataFrame([['Suspicious Activity Detected']], columns=["Section"])

        most_accessed_endpoint_df = pd.DataFrame([[most_accessed_endpoint[0], most_accessed_endpoint[1]]], 
                                                  columns=["Endpoint", "Access Count"])

        # If no suspicious IPs, show a message instead
        if suspicious_ips.empty:
            suspicious_ips = pd.DataFrame([['No suspicious activity detected']], columns=["Message"])

        # Concatenate all results
        all_data = pd.concat([requests_header, ip_counts, 
                              endpoint_header, most_accessed_endpoint_df, 
                              suspicious_header, suspicious_ips], ignore_index=True)

        # Save to CSV
        all_data.to_csv(output_file, index=False, header=False)
        logging.info(f"Analysis results saved to {output_file}")
    
    except Exception as e:
        logging.error(f"Error saving results to CSV: {e}")
        raise

if __name__ == "__main__":
    log_file_path = "sample.log"  # Change this to your log file path
    output_csv_path = "sample_log.csv"  # Intermediate CSV file path

    try:
        # Step 1: Convert logs to CSV
        log_to_csv(log_file_path, output_csv_path)

        # Step 2: Analyze IP request counts
        ip_counts = count_requests(output_csv_path)

        # Step 3: Identify the most accessed endpoint
        most_accessed_endpoint = most_frequent_endpoint(output_csv_path)

        # Step 4: Detect suspicious activity
        suspicious_ips = suspicious_activity(output_csv_path, threshold=4)

        # Step 5: Save results to a CSV
        output_file = "log_analysis_results.csv"
        save_results_to_csv(output_file, ip_counts, most_accessed_endpoint, suspicious_ips)

    except Exception as e:
        logging.error(f"An error occurred during the log analysis process: {e}")
