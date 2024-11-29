---
{"dg-publish":true,"permalink":"/mitreattck-analysis/tryhackme/siem/boogeyman-3/"}
---

[[tryhackme\|tryhackme]]
### Case Description
---
A phishing email against the CEO of the company that compromised his workstation around August 29 and August 30.
## Tools
---
- Sysmon
- ELK
# Analysis

Screenshot of the attachment:

![Pasted image 20240923151417.png](/img/user/x/images/Pasted%20image%2020240923151417.png)
And `.iso` file:

![Pasted image 20240923154422.png](/img/user/x/images/Pasted%20image%2020240923154422.png)
Using the filenames as filter and turning off the Kibana Query Language:

![Pasted image 20240923154827.png](/img/user/x/images/Pasted%20image%2020240923154827.png)
- **mshta.exe** it is designed to execute `.hta` files
- Viewing the 'message' field shows PID: 6392

Filtering for processes with parent process id '6392' shows `process.parent.pid : "6392" or process.pid : "6392"` using KQL:

```
C:\Windows\System32\xcopy.exe" /s /i /e /h D:\review.dat C:\Users\EVAN~1.HUT\AppData\Local\Temp\review.dat
```

- `xcopy` is a utility tool that copies files and directories.
- The command basically says copy directories and subdirectories where the `review.dat` file is located to the Temp directory.
- `.dat` file contains information about the program used to create it.
- Process ID: 3832

Command output:
![Pasted image 20240923173611.png](/img/user/x/images/Pasted%20image%2020240923173611.png)
Using the process ID of **mshta.exe** and the name of the `.dat` file:

```bash
process.parent.pid : "6392" and review.dat
```

Command output:

![Pasted image 20240923174803.png](/img/user/x/images/Pasted%20image%2020240923174803.png)
- **rundll32.exe** enables applications to use `.dll`.
- `.dat` files cannot be executed by the said binary not unless it is maliciously renamed to a `.dat` file instead of a `.dll`
- `DllRegisterServer` registers the `.dll` files, so it can be used or called later.

Then the log entry above shows:

```PowerShell
"powershell.exe" 
$A = New-ScheduledTaskAction -Execute 'rundll32.exe' -Argument 'C:\Users\EVAN~1.HUT\AppData\Local\Temp\review.dat,DllRegisterServer';
$T = New-ScheduledTaskTrigger -Daily -At 06:00; $S = New-ScheduledTaskSettingsSet; 
$P = New-ScheduledTaskPrincipal $env:username; $D = New-ScheduledTask -Action $A -Trigger $T -Principal $P -Settings $S; 
Register-ScheduledTask Review -InputObject $D -Force;
```

Modified version:

![Pasted image 20240923181859.png](/img/user/x/images/Pasted%20image%2020240923181859.png)
1. Open's up powershell.
2. Create new scheduled task with the previous discussed code.
3. Set it to trigger daily at 6:00
4. Run the tasks under the current user.
5. Creates a scheduled task named '**Review**'
6. `-force` the flag to be registered.

- 10.10.155.59
- Looking at the sample scheduled execution using "Review" as filter we can see the process ID.

Filtering for `destination.ip` and checking who has the most log entry revealed:

![Pasted image 20240923190503.png](/img/user/x/images/Pasted%20image%2020240923190503.png)
And a sample log entry:

![Pasted image 20240923190549.png](/img/user/x/images/Pasted%20image%2020240923190549.png)
- It was executed by `rundll32.exe`.
- The sourceIP is our IP address indicating we connected to the destIP.
- port 80 and http common ways to send and retrieve commands.
- It was run under our compromised user.

Using `process.parent.pid == 4672` process ID of a network connection:

![Pasted image 20240923192430.png](/img/user/x/images/Pasted%20image%2020240923192430.png)
The attacker performed a [UAC bypass](https://book.hacktricks.xyz/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control):
- It requires the current user in the local group administrator.
- Programs that are autoelevated automatically and signed by Microsoft:
	- fortunately for the attacker: [fodhelper.exe](https://www.oreilly.com/library/view/mastering-kali-linux/9781789340563/1124000a-2945-4408-99f3-e5f6c420f7e3.xhtml) is one of them. PID 5180

Looking at the DNS logs the threat actor queried for github using the Powershell:

![Pasted image 20240923193254.png](/img/user/x/images/Pasted%20image%2020240923193254.png)
**NOTES dissappeard however images are saved starting from here**

![Pasted image 20240924174632.png](/img/user/x/images/Pasted%20image%2020240924174632.png)
![Pasted image 20240924175215.png](/img/user/x/images/Pasted%20image%2020240924175215.png)
![Pasted image 20240924175630.png](/img/user/x/images/Pasted%20image%2020240924175630.png)

![Pasted image 20240924185445.png](/img/user/x/images/Pasted%20image%2020240924185445.png)


![Pasted image 20240924185535.png](/img/user/x/images/Pasted%20image%2020240924185535.png)

![Pasted image 20240924194127.png](/img/user/x/images/Pasted%20image%2020240924194127.png)
**NOTES dissappeard however images are saved ending from here**

Filtering for hostname 'WKSTN-1327' and 'event.code: 1' shows an interesting process name which is used for powershell remote session:

![Pasted image 20240925094122.png](/img/user/x/images/Pasted%20image%2020240925094122.png)
Then the attacker dumped the hashes again using the same tool:

![Pasted image 20240925094257.png](/img/user/x/images/Pasted%20image%2020240925094257.png)
After gaining access to the Domain Controller the attacker yet again dumped another credentials by performing DCsync attack:

![Pasted image 20240925094512.png](/img/user/x/images/Pasted%20image%2020240925094512.png)
Then after performing the following the attacker downloaded a ransomware binary using filter 'WKSTN-1327' and 'Powershell':

![Pasted image 20240925094736.png](/img/user/x/images/Pasted%20image%2020240925094736.png)

