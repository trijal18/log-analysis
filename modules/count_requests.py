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

if __name__ == "__main__":
    print(count_requests(r"sample_log.csv"))