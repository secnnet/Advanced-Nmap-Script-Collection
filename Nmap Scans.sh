# The script provided is a simple bash script that automates a series of Nmap scans using some of the Nmap scripts mentioned earlier. It performs several tasks, including:
# 1. Retrieving the HTTP title of the target's web page
# 2. Enumerating SSL/TLS ciphers supported by the target
# 3. Checking for known vulnerabilities using the Vulners API
# 4. Scanning for SMB vulnerabilities
# 5. Grabbing banners of open services on the target

# The script takes a single argument, the target IP address or domain, and saves the output of the scans into a combined report file.

# To run the script, follow these steps:
# 1. Save the script as nmap_scan.sh using a text editor.
# 2. Open a terminal (Linux or macOS) or use a bash-compatible environment like Git Bash or Windows Subsystem for Linux (WSL) on Windows.
# 3. Navigate to the directory where you saved the script. You can use the cd command for this, e.g., cd /path/to/your/script.
# 4. Make the script executable using the command chmod +x nmap_scan.sh.
# 5. Run the script by entering ./nmap_scan.sh <target>, where <target> is the IP address or domain you want to scan. For example: ./nmap_scan.sh example.com.

# The script will perform the Nmap scans and save the results in a report file named nmap_report_<target>.txt in the same directory.

# Please note that you should only use this script on systems you have permission to access, as unauthorized scanning or exploitation can be illegal and unethical.

#!/bin/bash

if [ "$#" -ne 1 ]; then
  echo "Usage: $0 <target>"
  exit 1
fi

TARGET=$1
REPORT="nmap_report_$TARGET.txt"

echo "Scanning target: $TARGET"

# Get HTTP title
nmap --script http-title $TARGET -oN http_title_$TARGET.txt
echo "HTTP title scan completed."

# Enumerate SSL/TLS ciphers
nmap --script ssl-enum-ciphers -p 443 $TARGET -oN ssl_enum_ciphers_$TARGET.txt
echo "SSL/TLS ciphers enumeration completed."

# Check for known vulnerabilities
nmap --script vulners $TARGET -oN vulners_$TARGET.txt
echo "Vulnerability scan completed."

# SMB vulnerabilities check
nmap --script smb-vuln-* -p 445 $TARGET -oN smb_vuln_$TARGET.txt
echo "SMB vulnerabilities scan completed."

# Grab banners
nmap --script banner $TARGET -oN banner_$TARGET.txt
echo "Banner grabbing completed."

# Combine reports
echo "Combining reports..."
cat http_title_$TARGET.txt ssl_enum_ciphers_$TARGET.txt vulners_$TARGET.txt smb_vuln_$TARGET.txt banner_$TARGET.txt > $REPORT
echo "Report saved as $REPORT"

# Remove individual report files
rm http_title_$TARGET.txt ssl_enum_ciphers_$TARGET.txt vulners_$TARGET.txt smb_vuln_$TARGET.txt banner_$TARGET.txt

echo "Scan completed."
