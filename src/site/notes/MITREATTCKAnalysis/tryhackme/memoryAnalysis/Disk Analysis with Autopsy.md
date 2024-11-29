---
{"dg-publish":true,"permalink":"/mitreattck-analysis/tryhackme/memory-analysis/disk-analysis-with-autopsy/"}
---

[[tryhackme\|tryhackme]]

**What is the MD5 hash of the E01 image?**

**What is the computer account name?**

The image name -> Summary -> Container

Extracted Content > Operating System Information -> System.

**List all the user accounts. (alphabetical order)**

![Pasted image 20241114165055.png](/img/user/x/images/Pasted%20image%2020241114165055.png)
**Who was the last user to log into the computer?**

Operating System User Account > Date Accessed

**What was the IP address of the computer?**

In the Operating System Information -> System -> Application (down from the panel) and then ControlSet01 -> Services -> TCPIP -> Parameters -> Interfaces shows no IP address:

![Pasted image 20241116205033.png](/img/user/x/images/Pasted%20image%2020241116205033.png)
But there is a strange installed program that has a networking related concept in it's name:

![Pasted image 20241117125603.png](/img/user/x/images/Pasted%20image%2020241117125603.png)
A google search:

![Pasted image 20241117125702.png](/img/user/x/images/Pasted%20image%2020241117125702.png)
Then at the content viewer -> Applications -> WOW6432Node -> Look@LAN then still nothing to be found.

`C:\Progam Files` to see if it drops any log files however it is empty, only a `.ini` file but at the `Progam Files (x86)` wee see the folder of the program and viewing the `.ini` file we see:

![Pasted image 20241117131728.png](/img/user/x/images/Pasted%20image%2020241117131728.png)
**What was the MAC address of the computer? (XX-XX-XX-XX-XX-XX)**

08-00-27-2c-c4-b9

**What is the name of the network card on this computer?**

At Operating System Information -> System -> Applications:

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}

![Pasted image 20241117133226.png](/img/user/x/images/Pasted%20image%2020241117133226.png)

**What is the name of the network monitoring tool?**
Look@LAN

**A user has his full name printed on his desktop wallpaper. What is the user's full name?**

The windows desktop wallpaper can be found on each NTUSER.dat -> Control Panel -> Desktop -> Wallpaper.

Viewing one by one mostly on the download's directory we see this:

![Pasted image 20241117140652.png](/img/user/x/images/Pasted%20image%2020241117140652.png)

**The same user found an exploit to escalate privileges on the computer. What was the message to the device owner?**

Invesitaging the user one by one, I found shreya's `exploit.ps1` in vol3 below data sources -> HASAN2.EO1 then Shreya's desktop:

![Pasted image 20241117133756.png](/img/user/x/images/Pasted%20image%2020241117133756.png)
**A user had a file on her desktop. It had a flag but she changed the flag using PowerShell. What was the first flag?**

We can view powershell history right here:

APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

or 

simply search keyword with `flag{`

![Pasted image 20241117135810.png](/img/user/x/images/Pasted%20image%2020241117135810.png)

**A user bookmarked a Google Maps location. What are the coordinates of the location?**

12°52'23.0"N 80°13'25.0"E


**2 hack tools focused on passwords were found in the system. What are the names of these tools? (alphabetical order)**

One from run programs with a name of `lazagne.exe` and at recent documents we can see `mimikatz.exe`:

![Pasted image 20241116213541.png](/img/user/x/images/Pasted%20image%2020241116213541.png)

And

![Pasted image 20241116213309.png](/img/user/x/images/Pasted%20image%2020241116213309.png)

**One of the users wanted to exploit a domain controller with an MS-NRPC based exploit. What is the filename of the archive that you found? (include the spaces in your answer)**

At Recent Document's tab:

![Pasted image 20241116213123.png](/img/user/x/images/Pasted%20image%2020241116213123.png)
**There is a YARA file on the computer. Inspect the file. What is the name of the author?**

At recent documents:

![Pasted image 20241117141254.png](/img/user/x/images/Pasted%20image%2020241117141254.png)
To search exactly the location:

Tools -> File Search by attributes then input .yar:

![Pasted image 20241117141553.png](/img/user/x/images/Pasted%20image%2020241117141553.png)