
# Log Analysis Script

## Overview
This script processes server log files to provide insights into the following areas:

- **Requests per IP Address**: Identifies the number of requests made by each IP address.
- **Most Accessed Endpoint**: Determines the most frequently accessed endpoint in the server logs.
- **Suspicious Activity Detection**: Detects potential suspicious activities, such as brute-force login attempts, based on failed login counts.

The results are displayed in a clear format in the terminal and saved to a CSV file for further analysis.

## Features
- **IP Request Count**: Displays the total number of requests made by each IP address.
- **Most Accessed Endpoint**: Identifies and displays the most frequently accessed endpoint.
- **Suspicious Activity Detection**: Flags IP addresses with failed login attempts that exceed a predefined threshold (default is 10).

## Requirements
- **Python 3.6+**: The script uses Python 3 features and libraries.
- **Pandas**: For processing and analyzing CSV data.
- **Logging**: For better error tracking and debugging.

You can install required dependencies using:

```bash
pip install pandas
```

## File Structure
- **log_analysis.py**: Main Python script that performs the log analysis.
- **sample.log**: Sample log file (you can replace this with your own server log file).
- **sample_log.csv**: Intermediate CSV file (automatically generated).
- **log_analysis_results.csv**: Final CSV output containing the analysis results.

## Usage

### Step 1: Prepare Your Log File
Make sure your server log file is in the correct format (common log format is expected). Each line should look something like:

```sql
203.0.113.5 - - [10/Dec/2024:14:23:01 +0000] "GET /login HTTP/1.1" 200 532 "-" "Mozilla/5.0"
```

### Step 2: Running the Script
To run the script, execute the following command:

```bash
python log_analysis.py
```

The script will:
1. Parse the log file.
2. Count the requests made by each IP address.
3. Identify the most frequently accessed endpoint.
4. Detect suspicious activity based on failed login attempts (default threshold of 4).

### Step 3: View the Results
The results will be displayed in the terminal and saved to a CSV file (`log_analysis_results.csv`), which includes:

- Requests per IP Address
- Most Accessed Endpoint
- Suspicious Activity Detected

## Example Output

### Terminal Output:
```yaml
Requests per IP Address:
         IP Address  Request Count
0      203.0.113.5             8
1  198.51.100.23             8
2     192.168.1.1             7
3     10.0.0.2              6
4  192.168.1.100             5

Most Frequently Accessed Endpoint:
Endpoint: /login, Access Count: 13

Suspicious Activity Detected:
         IP Address  Failed Login Attempts
0      203.0.113.5                    8
1  192.168.1.100                    5
```

### CSV File (log_analysis_results.csv):
```css
Section,Requests per IP Address
,203.0.113.5,8.0
,198.51.100.23,8.0
,192.168.1.1,7.0
,10.0.0.2,6.0
,192.168.1.100,5.0

Section,Most Frequently Accessed Endpoint
,/login,13.0

Section,Suspicious Activity Detected
,203.0.113.5,8.0
,192.168.1.100,5.0
```

## CSV Output Format
The output CSV file will have the following structure:

- **Requests per IP Address**: Columns: IP Address, Request Count
- **Most Accessed Endpoint**: Columns: Endpoint, Access Count
- **Suspicious Activity**: Columns: IP Address, Failed Login Attempts
