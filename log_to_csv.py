import pandas as pd

def log_to_csv(log_file_path, output_csv_path):
    """
    Converts the log file to a CSV file using pandas and split method.
    
    Args:
        log_file_path (str): Path to the log file.
        output_csv_path (str): Path to the output CSV file.
    """
    log_data = []

    with open(log_file_path, 'r') as log_file:
        for line in log_file:
            parts = line.split(' ')
            
            # Extract relevant parts
            ip = parts[0]
            timestamp = parts[3][1:] + " " + parts[4][:-1] 
            method = parts[5][1:]                          
            endpoint = parts[6]
            http_version = parts[7][:-1]                   
            status_code = parts[8]
            size = parts[9]
            
            # Extract message if available
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

    df = pd.DataFrame(log_data)

    df.to_csv(output_csv_path, index=False)

    print(f"Log data successfully converted to {output_csv_path}")

if __name__ == "__main__":
    log_file_path = "sample.log"  
    output_csv_path = "sample_log.csv" 
    log_to_csv(log_file_path, output_csv_path)
