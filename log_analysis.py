import pandas as pd

def count_requests(csv_file_path):
    """
    Count the number of requests made by each IP address using a CSV file.

    Args:
        csv_file_path (str): Path to the CSV file.

    Returns:
        pd.DataFrame: DataFrame with IP addresses and their request counts, sorted in descending order.
    """
    df = pd.read_csv(csv_file_path)
    ip_counts = df['ip'].value_counts().reset_index()
    ip_counts.columns = ['IP Address', 'Request Count']
    return ip_counts

def most_frequent_endpoint(csv_file_path):
    """
    Identify the most frequently accessed endpoint using a CSV file.

    Args:
        csv_file_path (str): Path to the CSV file.

    Returns:
        str, int: The most frequently accessed endpoint and its access count.
    """
    df = pd.read_csv(csv_file_path)
    endpoint_counts = df['endpoint'].value_counts()
    most_accessed_endpoint = endpoint_counts.idxmax()
    access_count = endpoint_counts.max()
    return most_accessed_endpoint, access_count

def suspicious_activity(csv_file_path, threshold=10):
    """
    Detect suspicious activity (potential brute force login attempts) using a CSV file.

    Args:
        csv_file_path (str): Path to the CSV file.
        threshold (int): Number of failed attempts to consider an IP suspicious.

    Returns:
        pd.DataFrame: DataFrame with suspicious IPs and their failed login counts.
    """
    df = pd.read_csv(csv_file_path)

    failed_logins = df[
        (df['status_code'] == 401) | (df['message'].str.contains("Invalid credentials", na=False))
    ]

    suspicious_ips = failed_logins['ip'].value_counts().reset_index()
    suspicious_ips.columns = ['IP Address', 'Failed Login Attempts']

    suspicious_ips = suspicious_ips[suspicious_ips['Failed Login Attempts'] >= threshold]
    return suspicious_ips

def save_results_to_csv(output_file, ip_counts, most_accessed_endpoint, suspicious_ips):
    """
    Save the analysis results to a single CSV file with structured sections using pandas.

    Args:
        output_file (str): Path to the output CSV file.
        ip_counts (pd.DataFrame): DataFrame of requests per IP.
        most_accessed_endpoint (tuple): Tuple of the most accessed endpoint and its count.
        suspicious_ips (pd.DataFrame): DataFrame of suspicious IPs.
    """
    requests_header = pd.DataFrame([['Requests per IP Address']], columns=["Section"])
    endpoint_header = pd.DataFrame([['Most Frequently Accessed Endpoint']], columns=["Section"])
    suspicious_header = pd.DataFrame([['Suspicious Activity Detected']], columns=["Section"])

    most_accessed_endpoint_df = pd.DataFrame([[most_accessed_endpoint[0], most_accessed_endpoint[1]]],
                                              columns=["Endpoint", "Access Count"])

    if suspicious_ips.empty:
        suspicious_ips = pd.DataFrame([['No suspicious activity detected']], columns=["Message"])

    all_data = pd.concat([
        requests_header, ip_counts,
        endpoint_header, most_accessed_endpoint_df,
        suspicious_header, suspicious_ips
    ], ignore_index=True)

    all_data.to_csv(output_file, index=False, header=False)

if __name__ == "__main__":
    csv_file_path = "sample_log.csv"  
    output_file = "log_analysis_results.csv" 

    ip_counts = count_requests(csv_file_path)
    most_accessed_endpoint = most_frequent_endpoint(csv_file_path)
    suspicious_ips = suspicious_activity(csv_file_path, 4)

    print("Requests per IP Address:")
    print(ip_counts)
    print("\nMost Frequently Accessed Endpoint:")
    print(most_accessed_endpoint)
    print("\nSuspicious Activity Detected:")
    print(suspicious_ips if not suspicious_ips.empty else "No suspicious activity detected.")

    save_results_to_csv(output_file, ip_counts, most_accessed_endpoint, suspicious_ips)
    print(f"\nResults saved to {output_file}")