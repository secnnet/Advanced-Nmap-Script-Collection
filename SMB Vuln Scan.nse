-- To run this script, you need to have Nmap installed on your system. If you haven't already, download and install Nmap from the official website: https://nmap.org/download.html.

-- After installing Nmap, save the script to a file with a meaningful name, such as "smb_vuln_scan.nse". Make sure to save the file in the appropriate directory where Nmap looks for scripts.

-- On Linux or macOS systems, you can save it in the "/usr/local/share/nmap/scripts/" directory. On Windows, you can save it in the "C:\Program Files (x86)\Nmap\scripts" directory.

-- Once you have saved the script, open a command prompt or terminal window and navigate to the directory where you saved the script.

-- To run the script against a target system, use the following command:

-- nmap -p 445 -sV -sC <target> --script=smb_vuln_scan.nse

-- Replace <target> with the IP address or hostname of the system you want to scan.

-- This command tells Nmap to run the script smb_vuln_scan.nse against the target system on port 445, which is the default port for SMB. The -sV option tells Nmap to perform version detection, and -sC tells it to run the default script set.

-- If any SMB vulnerabilities are detected, the script will output them to the console. If no vulnerabilities are found, the script will output a message indicating so.

-- Please note that running vulnerability scans without permission is illegal and unethical. Make sure to obtain proper authorization and permission before running any vulnerability scans or tests.

-- Define the script's purpose and behavior
description = [[
Runs several SMB (Server Message Block) vulnerability scripts against the target system.
]]

-- Define the author and license of the script
author = "Bilel Graine"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

-- Define the script's categories
categories = {"vuln", "safe"}

-- Define the port rule for the script
portrule = port.number(445, "tcp")

-- Define the list of SMB vulnerability scripts to run
local vuln_scripts = {
  "smb-vuln-cve2009-3103.nse",
  "smb-vuln-ms06-025.nse",
  "smb-vuln-ms07-029.nse",
  "smb-vuln-ms08-067.nse",
  "smb-vuln-ms10-054.nse",
  "smb-vuln-ms10-061.nse",
  "smb-vuln-ms17-010.nse"
}

-- Define the action function to execute when the script runs
action = function(host, port)
  local result_table = {}

  -- Loop through each SMB vulnerability script and execute it against the target
  for _, script in ipairs(vuln_scripts) do
    local script_result = stdnse.execute_script(host, port, script)
    
    -- If the script execution is complete and it found vulnerabilities, add the output to the results table
    if script_result["state"] == "finished" then
      if script_result["output"] ~= "" then
        table.insert(result_table, script_result["output"])
      end
    end
  end

  -- If no vulnerabilities were found, return a false status and a message indicating so
  if #result_table == 0 then
    return stdnse.format_output(false, "No SMB vulnerabilities found.")
  else
    -- Otherwise, return a true status and the list of vulnerabilities concatenated together
    return stdnse.format_output(true, table.concat(result_table, "\n"))
  end
end
