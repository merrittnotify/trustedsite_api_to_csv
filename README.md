# trustedsite_api_to_csv

This is a dependency-free Javascript script that can be used to query the TrustedSite API for target, scan, and vulnerability details to output to a CSV file.

## Getting Started / Installation

This script is portable-- no build or installation required. Just clone the script and run as per "Usage"

### Usage

Simply run the script in a Javascript runtime environment (NodeJS suggested) with your API key as the only argument:

```
$ node trustedsite_api_to_csv.js YOUR-API-KEY-HERE
```

## Output

This script outputs results from the most recent scan for each target on your account in a comma-separated values file with one vulnerability finding per line. The output file will be placed in the directory the script is run from, and be named "output.csv". Targets with no scans will have one line in the CSV with target details. The fields provided for each line are:


    target_id
    target_hostname
    target_name
    target_tags
    target_created
    target_last_scan
    target_next_scan
    target_scan_frequency
    target_scan_hour
    target_network_scan
    target_website_scan
    target_pci_scan
    vuln_id
    vuln_name
    vuln_first_found
    vuln_protocol
    vuln_port
    vuln_pci
    vuln_num_scans
    vuln_severity
    vuln_consequence
    vuln_solution
    vuln_description
    vuln_type
    vuln_cves
    vuln_cvss_base_score
    vuln_result
    vuln_param
    vuln_uri
    vuln_payload
    vuln_resolved
