# Mass IP Info Extractor

<p align="center">
  <img src="img/thumbnail.png" alt="Mass IP Info Extractor" width="350" height="350">
</p>


**Mass IP Info Extractor** is a command-line Python tool that takes in a list of IPs (from one or multiple CSV files) and retrieves detailed geographical and network information for each IP address. The results are outputted in JSON format, with an optional export to Excel. This tool is designed for penetration testers, data analysts, and IT professionals who need efficient, large-scale IP data retrieval.

## Features
- Supports both single and bulk CSV files, including nested folders.
- Retrieves IP address information using primary and fallback APIs.
- Outputs IP data in JSON format with optional Excel export.
- Multi-threaded processing for faster handling of large IP lists.
- Logs events and errors for easy troubleshooting.

## Prerequisites
- Python 3.x
- Required Python libraries:
  ```bash
  pip install pandas requests pyfiglet coloredlogs
  ```
## Installation
  ```bash
    git clone https://github.com/Spirit-Maker/Mass-IP-Info-Extractor.git
    cd mass-ip-info-extractor
    pip install -r requirements.txt
  ```

## Usage
### Single CSV formaat
  ```bash
    python3 main.py -f path/to/file.csv -c ip_address -o output.json -x output.xlsx -t 5 -d INFO
  ```
    
### Bulk CSV format
  ```bash
    python3 main.py -p path/to/folder -c ip_address,alt_ip_column -o output.json -t 15 -d DEBUG
  ```
    
#### Expected Output
JSON file: IP address details in JSON format.
Optional Excel file: If -x is specified, an Excel file with normalized IP data.

## API Integration
- Primary API: ipgeolocation.io (Requires an API key).
- Fallback API: ip-api.com (No API key required but limited by request rate).
To use the ipgeolocation.io service, create an account and replace the API_KEY in the ipgeoloc function with your own key.

## Handling Existing Records
The script checks for existing IP records in the output file to avoid duplicate entries, appending only new data.
