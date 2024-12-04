import pandas as pd 

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
    
    # Filter rows with failed login attempts (status code 401 or failure message)
    failed_logins = df[
        (df['status_code'] == 401) | (df['message'].str.contains("Invalid credentials", na=False))
    ]
    
    # Count failed attempts per IP
    suspicious_ips = failed_logins['ip'].value_counts().reset_index()
    suspicious_ips.columns = ['IP Address', 'Failed Login Attempts']

    # Filter IPs exceeding the threshold
    suspicious_ips = suspicious_ips[suspicious_ips['Failed Login Attempts'] >= threshold]
    return suspicious_ips

if __name__ == "__main__":
    print(suspicious_activity(r"sample_log.csv",5))