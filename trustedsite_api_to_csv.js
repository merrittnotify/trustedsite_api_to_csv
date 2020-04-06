const API_VERSION = "1";
const API_KEY = process.argv.slice(2)[0];

const scan_frequency_to_text = code => {
  if (code == 0) {
    return "OnDemand";
  } else if (code == 1) {
    return "Day";
  } else if (code == 2) {
    return "Week";
  } else if (code == 3) {
    return "Month";
  } else if (code == 4) {
    return "Quarter";
  }
};

const scan_hour_to_text = code => {
  if (code == -1) {
    return "Random";
  } else {
    return code;
  }
};

const vuln_type_to_text = code => {
  if (code == 1) {
    return "Vulnerability";
  } else {
    return "Disclosure";
  }
};

const vuln_pci_to_text = code => {
  if (code == 1) {
    return "Yes";
  } else {
    return "No";
  }
};

const target_scan_type_to_text = code => {
  if (code == 1) {
    return "Yes";
  } else {
    return "No";
  }
};

const csv_data_protect = data => {
  if (data) {
    return data.toString().replace(/"/g, "'");
  }
};

const encoded_to_text = data => {
  if (data) {
    let buff = new Buffer(data, "base64");
    return buff.toString("ascii");
  }
};

const https_request = options => {
  return new Promise((resolve, reject) => {
    const lib = require("https");
    const request = lib.get(options, response => {
      if (response.statusCode < 200 || response.statusCode > 299) {
        reject(new Error("FALURE: " + response.statusCode));
      }
      const body = [];
      response.on("data", chunk => body.push(chunk));
      response.on("end", () => resolve(body.join("")));
    });
    request.on("error", err => reject(err));
  });
};

const json_to_csv = json => {
  let fields = Object.keys(json[0]);
  let replacer = function(key, value) {
    return value === null ? "" : value;
  };
  let csv = json.map(function(row) {
    return fields
      .map(function(fieldName) {
        return JSON.stringify(row[fieldName], replacer);
      })
      .join(",");
  });
  csv.unshift(fields.join(","));
  return csv.join("\r\n");
};

const api_request = async endpoint => {
  let options = {
    hostname: "api.trustedsite.com",
    port: 443,
    path: `/api/v${API_VERSION}/${endpoint}`,
    method: "GET",
    headers: {
      "x-apikey": `${API_KEY}`
    }
  };
  console.log(`==> ${options.path}`);
  let res = await https_request(options);
  return JSON.parse(res);
};

const api = async () => {
  let lines = [];
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // GET: TARGETS
  //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  let vuln_cache = {};
  let targets = await api_request("scan-targets.json");
  if (targets.code == 1) {
    for (let target of targets.targets) {
      let scan_date_list = [];
      //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      // GET: RECENT SCAN DATES
      //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      if (target.lastScan === undefined) {
        lines.push({
          target_id: csv_data_protect(target.targetId),
          target_hostname: csv_data_protect(target.hostname),
          target_name: csv_data_protect(target.name),
          target_tags: csv_data_protect(target.tags),
          target_created: csv_data_protect(target.dateCreated),
          target_last_scan: "",
          target_next_scan: csv_data_protect(target.next_scan_date),
          target_scan_frequency: scan_frequency_to_text(target.scan_frequency),
          target_scan_hour: scan_hour_to_text(target.scan_hour),
          target_network_scan: target_scan_type_to_text(target.scan_network),
          target_website_scan: target_scan_type_to_text(target.scan_website),
          target_pci_scan: target_scan_type_to_text(target.scan_pci),
          vuln_id: "",
          vuln_name: "",
          vuln_first_found: "",
          vuln_protocol: "",
          vuln_port: "",
          vuln_pci: "",
          vuln_num_scans: "",
          vuln_severity: "",
          vuln_consequence: "",
          vuln_solution: "",
          vuln_description: "",
          vuln_type: "",
          vuln_cves: "",
          vuln_cvss_base_score: "",
          vuln_result: "",
          vuln_uri: "",
          vuln_param: "",
          vuln_payload: "",
          vuln_resolved_date: ""
        });
        continue;
      }
      for (let i = 0; i < target.recentScanIds.length; i++) {
        let recent_scan = await api_request(
          `scan-result.json?targetId=${target.targetId}&scanId=${target.recentScanIds[i]}&includeInstanceOutput=1`
        );
        scan_date_list.push(recent_scan.scan.dateTime);
      }
      //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      // GET: LAST SCAN RESULT
      //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      let results = await api_request(
        `scan-result.json?targetId=${target.targetId}&scanId=${target.lastScan.scanId}&includeInstanceOutput=1`
      );
      //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      // GET: VULN INFO
      //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      for (let result of results.scan.vulns) {
        let vuln = "";
        if (result.vulnId in vuln_cache) {
          vuln = vuln_cache[result.vulnId];
        } else {
          vuln = await api_request(`scan-vuln.json?vulnId=${result.vulnId}`);
          vuln_cache[result.vulnId] = vuln;
        }
        //---
        let vuln_num_scans = 1;
        if (target.lastScan.dateTime != result.first_found_date) {
          for (let date of scan_date_list) {
            if (result.first_found_date === date) {
              break;
            }
            vuln_num_scans++;
          }
        }
        let uri = param = payload = resolved = "";
        if (result.hasOwnProperty("uri")) {
          uri = result.uri;
        };
        if (result.hasOwnProperty("param")) {
          param = result.param;
        };
        if (result.hasOwnProperty("payload")) {
          payload = result.payload;
        };
        if (result.hasOwnProperty("resolved")) {
          resolved = result.resolved.date
        }
        //---
        lines.push({
          target_id: csv_data_protect(target.targetId),
          target_hostname: csv_data_protect(target.hostname),
          target_name: csv_data_protect(target.name),
          target_tags: csv_data_protect(target.tags),
          target_created: csv_data_protect(target.dateCreated),
          target_last_scan: csv_data_protect(target.lastScan.dateTime),
          target_next_scan: csv_data_protect(target.next_scan_date),
          target_scan_frequency: scan_frequency_to_text(target.scan_frequency),
          target_scan_hour: scan_hour_to_text(target.scan_hour),
          target_network_scan: target_scan_type_to_text(target.scan_network),
          target_website_scan: target_scan_type_to_text(target.scan_website),
          target_pci_scan: target_scan_type_to_text(target.scan_pci),
          vuln_id: csv_data_protect(result.vulnId),
          vuln_name: csv_data_protect(vuln.vuln.name),
          vuln_first_found: csv_data_protect(result.first_found_date),
          vuln_protocol: csv_data_protect(result.protocol),
          vuln_port: csv_data_protect(result.port),
          vuln_pci: vuln_pci_to_text(vuln.vuln.pci),
          vuln_num_scans: csv_data_protect(vuln_num_scans),
          vuln_severity: csv_data_protect(vuln.vuln.severity),
          vuln_consequence: csv_data_protect(vuln.vuln.consequence),
          vuln_solution: csv_data_protect(vuln.vuln.solution),
          vuln_description: csv_data_protect(vuln.vuln.description),
          vuln_type: vuln_type_to_text(vuln.vuln.type),
          vuln_cves: csv_data_protect(vuln.vuln.cve_ids),
          vuln_cvss_base_score: csv_data_protect(vuln.vuln.cvss_base_score),
          vuln_result: csv_data_protect(encoded_to_text(result.result)),
          vuln_uri: csv_data_protect(encoded_to_text(uri)),
          vuln_param: csv_data_protect(encoded_to_text(param)),
          vuln_payload: csv_data_protect(encoded_to_text(payload)),
          vuln_resolved: resolved
        });
      }
    }
    const fs = require("fs");
    fs.writeFile("output.csv", await json_to_csv(lines), function(err) {
      if (err) {
        return console.log(err);
      }
      console.log("==> output.csv");
    });
  } else {
    console.log(targets);
  }
};
api();
