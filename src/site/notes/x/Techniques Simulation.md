---
{"dg-publish":true,"permalink":"/x/techniques-simulation/","tags":["mitre"]}
---

[[MITREATTCKAnalysis/Threat Analysis with ATT&CK\|Threat Analysis with ATT&CK]]
### Summary
---
### Initials
---
- **Atomic Red Team ID**: T1059.003 - User Execution
- **Description**: 
- **Challenges Encountered & Solution*:
	- It requires installing some dependencies.
	- Requires Windows 8 to work.
## Analysis
---
- Screenshots or code snippets
- Wazuh alerts generated with default configurations.
- False positive/negative analysis

### WAZUH. rule creation
---
- **Rule ID and description**: 
- **Rule logic (conditions, actions)**
- **Effectiveness of detection**
- Make sure to put appropriate severity level for the next optional step.

### Example Wazuh Rule Documentation

```
Rule ID: suspicious_process_creation
Description: Detects process creation with suspicious command-line arguments
Logic: Checks for process creation with specific keywords in command-line (e.g., powerhell, cmd, wscript)
Expected Detections: Malicious script execution, command-line tools abuse
```


## IOCs and IOAs
---
### Incident Overview
---
- **Incident Overview Date and Time**: 
- **Source IP Address**:
- **Destination IP address**:
- **Malware URL**: de[.]fanged[.]com//malware.exe
- **Reported To**: OUROBOROS.org
#### Summary
---
In August 15th, 2024, at 15:35 UTC, the Kali Linux VM (IP: 192.168.1.2) attempted to
download the EICAR test file from eicar.org (IP: 89.238.73.97).
##### Indicators of Compromise (IOCs)
---
**IP addresses**:
- **Source IP**: 192.168.1.2
- **Description:** IP address of the Kali Linux VM initiating the download attempt.

- **Destination IP**: 89.238.73.97
- **Description: IP** address of the server hosting the EICAR test file.
##### Indicators of Attacks (IOAs)
---
- **Malware Test File Download Attempt:**
	- Behavior: Attempt to download the EICAR test file.
	- Intent: Test or bypass network defenses.

## Incident Response
---
- **Incident identification criteria**
- **Investigation steps** 
- **Containment actions**
- **Eradication procedures**
- **Recovery steps**

