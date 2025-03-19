---
{"dg-publish":true,"permalink":"/activities/endpoint-analysis/btl/log-analysis-sysmon/","tags":["mitre"]}
---

[[MITREATTCKAnalysis/Threat Analysis\|Threat Analysis]]
### Case Description
---
You are provided with Sysmon logs from a compromised endpoint. Analyse the logs to find out the steps and techniques used by the attacker.

source: https://blueteamlabs.online/home/challenge/log-analysis-sysmon-fabcb83517
## Tools
---
- jq - a command line JSON prettyfier.

# Analysis

Here is a screenshot of the format:

![Pasted image 20241014154417.png](/img/user/x/images/Pasted%20image%2020241014154417.png)
So to properly view the EventData in `jq`:

```bash
jq '.Event.EventData'
```

![Pasted image 20241014154456.png](/img/user/x/images/Pasted%20image%2020241014154456.png)
To filter out for specific Event IDs such as network connections:

```bash
jq '. | select(.Event.System.EventID == 3) | .Event.EventData' sysmon-events.json
```

For specific protocols:

```bash
jq '.Event | select(.System.EventID == "3" and .EventData.DestinationPort == "80") | .EventData' sysmon-events.json
```

However no output, trying for process creation with `EventID == "1"`:

![Pasted image 20241014155914.png](/img/user/x/images/Pasted%20image%2020241014155914.png)
Decoding it and resulting into creation of a zip file:
![Pasted image 20241014161422.png](/img/user/x/images/Pasted%20image%2020241014161422.png)
At process creation (Event ID 1) we see this:

![Pasted image 20241014162442.png](/img/user/x/images/Pasted%20image%2020241014162442.png)
But before the event above the `.hta` downloaded using `chrome.exe` is most likely responsible for giving access to the attacker:

- `.hta` stands for html applications that consist of html,css and scripts
- `mshta.exe` is designed to execute `.hta` files.

![Pasted image 20241014162822.png](/img/user/x/images/Pasted%20image%2020241014162822.png)
Then using the same filter the attacker set a environment variable:

![Pasted image 20241014164918.png](/img/user/x/images/Pasted%20image%2020241014164918.png)
Then the attacker open up `ftp` then somehow executes `supply.exe`:

![Pasted image 20241014165930.png](/img/user/x/images/Pasted%20image%2020241014165930.png)
Then using the `supply.exe`:

![Pasted image 20241014170734.png](/img/user/x/images/Pasted%20image%2020241014170734.png)
Then using Event ID 11 for file creation, we can see that the malware's programming language is written in python:

![Pasted image 20241014171743.png](/img/user/x/images/Pasted%20image%2020241014171743.png)
Then the malware downloads a new binary from github:

![Pasted image 20241014171855.png](/img/user/x/images/Pasted%20image%2020241014171855.png)
Then attempts to get a reverse shell using the downloaded malware from the previous one:

![Pasted image 20241014171922.png](/img/user/x/images/Pasted%20image%2020241014171922.png)




