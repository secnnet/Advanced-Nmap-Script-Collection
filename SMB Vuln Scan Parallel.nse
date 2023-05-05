-- This script runs several SMB (Server Message Block) vulnerability scripts against the target system.
-- It can be run using the command "nmap -p 445 -sV -sC <target>".

-- To run the script, you need to save it with a meaningful name such as "smb_vuln_scan.nse" in the Nmap script directory.

-- On Linux or macOS systems, you can save it in the "/usr/local/share/nmap/scripts/" directory. On Windows, you can save it in the "C:\Program Files (x86)\Nmap\scripts" directory.

-- Once you have saved the script, you can run it using the following command:

-- nmap -p 445 -sV -sC <target>

-- The command scans for the SMB vulnerability scripts on TCP port 445, which is the default port for SMB. The -sV and -sC options instruct Nmap to perform version detection and run default scripts, respectively. The <target> parameter specifies the target system to scan.

-- When you run the command, Nmap will execute each SMB vulnerability script in the list defined in the script. The results of each script will be combined into a single output table, which will be displayed at the end of the scan.

-- Note that running vulnerability scans and tests can potentially cause network disruption or downtime. Always ensure that you have appropriate permission and authorization before running any vulnerability scans or tests.

description = [[
Runs several SMB (Server Message Block) vulnerability scripts against the target system.
]]

author = "Bilel Graine"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

-- This script runs on TCP port 445, which is the default port for SMB.
portrule = port.number(445, "tcp")

-- The list of SMB vulnerability scripts to run.
local vuln_scripts = {
  "smb-vuln-cve2009-3103.nse",
  "smb-vuln-ms06-025.nse",
  "smb-vuln-ms07-029.nse",
  "smb-vuln-ms08-067.nse",
  "smb-vuln-ms10-054.nse",
  "smb-vuln-ms10-061.nse",
  "smb-vuln-ms17-010.nse"
}

-- This function runs an individual SMB vulnerability script.
local function run_script(script)
  local script_result = stdnse.execute_script(host, port, script)
  -- Only add the script's output to the result table if the script ran successfully and generated output.
  if script_result["state"] == "finished" then
    if script_result["output"] ~= "" then
      table.insert(result_table, script_result["output"])
    end
  end
end

-- The main action function for the script.
-- This function runs all of the SMB vulnerability scripts concurrently and aggregates the results.
action = function(host, port)
  local result_table = {}
  local output_table = {}
  
  -- Run each SMB vulnerability script in parallel using nmap.exec_par.
  nmap.new_task("SMB Vulnerability Scan")
  nmap.exec_par(run_script, vuln_scripts)

  -- Combine the output of each script into a single output table.
  if #result_table == 0 then
    return stdnse.format_output(false, "No SMB vulnerabilities found.")
  else
    for _, output in ipairs(result_table) do
      table.insert(output_table, output)
    end
    return stdnse.format_output(true, table.concat(output_table, "\n"))
  end
end
