---
{"dg-publish":true,"permalink":"/lima-charlie-detection-and-rules/","tags":["edr"]}
---

[[]]
### Introduction
---
Let's answer first what is even an **Endpoint Detection Response (EDR)** system and what is the difference between this and Antivirus?

- Antivirus protects only against known malware using signature-based detection such as a file hash or name.
	- Automatic, little to no human interferance.
- EDR focuses on suspicious patterns and anomaly such as URL found in the malware for C2 connections and anomalies such as communication through non-standard ports.
	- It can perform real-time containment and respond in a specific way such as block, alert (`report` in case of LimaCharlie), and more.

### Pre-requisite
---
- Ubuntu VM with msfconsole (or Kali Linux)
- Windows VM

## Rules & Detection
---
The main feature of an EDR is it's ability to focus on suspicious patterns and anomalies but by default we still need to define this to our EDR with rules and detection as **EDR does not magically 'know' what is suspicious**.
### Rule Writing
---
LimaCharlie offers a way to monitor core 'activities' such as new process, network connection, registry modification, and more, we can tell LC agents to consume sysmon events as well.

Writing a basic rule to detect powershell process creation:

```C
# Detection
event: NEW_PROCESS
op: is
path: event/FILE_PATH
value: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

# Response
- action: report
  name: Powershell started
```

- `event` the event type in this case monitor for new process. (view other events [here](https://docs.limacharlie.io/docs/sysmon-comparison))
- `is` exact match of the condition specified.
- `path` events in LC uses JSON formatting - in this case, we want to access/check the value of  `FILE_PATH` right under the `event` key.
- `action` what to do with it? in this case report only.
- `name`: what should we name the event?

Additionally LimaCharlie can ingest sysmon logs [here](https://docs.limacharlie.io/v2/docs/ingesting-sysmon-event-logs).
#### Adding our own Detections & Response Rules
---
**Sidebar:** Automation -> D&R Rules -> click the **Add Rule** button:

![Pasted image 20250314143704.png](/img/user/x/images/Pasted%20image%2020250314143704.png)
Click the create button and don't forget to enable the rule by checking and hitting the **enable** button, and after that simulate opening a powershell then navigate to detections:

![Pasted image 20250314144458.png](/img/user/x/images/Pasted%20image%2020250314144458.png)
- The name we provided.
- The image hash.
- The PPID and PID.
- The user responsible for the execution: `USER_NAME`

However we need to note that some events are not supported by other OSes, see [here](https://docs.limacharlie.io/docs/reference-edr-events).

```
event: mem_find_string
op: contains
path: STRINGSA/1
value: privilege::debug
```

```
- action: isolate network
  name: mimikatz.exe detected
```

Next: [[LimaCharlie - Staging the attack\|LimaCharlie - Staging the attack]].
#### Resources
---
https://www.paloaltonetworks.com/cyberpedia/what-is-edr-vs-antivirus
https://docs.limacharlie.io/v2/docs/detection-and-response-examples