This Python script processes web server log files to extract and analyze important information, fulfilling key cybersecurity-related tasks. It counts the number of requests made by each IP address, identifies the most frequently accessed endpoint, and detects suspicious activities such as brute-force login attempts. The script outputs the results in a clear, organized format to the terminal and also saves them in a CSV file named `log_analysis_results.csv`.

The script ensures comprehensive functionality by correctly processing log files and meeting all requirements. It accurately parses the log data to calculate IP request counts, determine the most accessed endpoint, and flag IP addresses with failed login attempts exceeding a configurable threshold. Additionally, the code is modular, well-organized, and follows Python best practices. Comments are included for better readability, and variable names are meaningful to enhance understanding.

Performance-wise, the script is efficient and scalable, capable of handling larger log files without significant delays. By reading the log file line by line, it optimizes memory usage and ensures fast processing. The output is presented in a user-friendly format, both in the terminal and in the generated CSV file. The CSV file includes three sections: requests per IP address, the most accessed endpoint, and details of any suspicious activity detected. This comprehensive analysis helps in monitoring and securing web server operations effectively.

## **Installation**

### Requirements:

* Python 3.x
* No external libraries required; the script uses built-in Python modules.

### Steps to Run:

1. Download or clone this repository.
2. Save the provided log file (e.g., `access.log`) in the same directory as the Python script.
3. Run the script using the following command:
   python log_analysis_script.py

#### Sample outputs

![1733203354513](image/Readme/1733203354513.png)

![1733203411247](image/Readme/1733203411247.png)
