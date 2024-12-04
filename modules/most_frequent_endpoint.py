import pandas as pd 

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

if __name__ == "__main__":
    print(most_frequent_endpoint(r"sample_log.csv"))