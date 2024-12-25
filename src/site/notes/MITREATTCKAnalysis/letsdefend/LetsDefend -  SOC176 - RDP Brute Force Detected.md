---
{"dg-publish":true,"permalink":"/mitreattck-analysis/letsdefend/lets-defend-soc-176-rdp-brute-force-detected/"}
---


[[]]

![Pasted image 20241225142651.png](/img/user/x/images/Pasted%20image%2020241225142651.png)
Based on the alert, it is safe to say this is a brute-force attempt, why? Because one is the source IP address is public, second is the reason **Login failure from a single source with different non existing accounts**, if you are a legitimate employee of course you should know at least the correct username credentials.

- Source IP is flagged with a 13/94 on VirusTotal.
- Threat Intel also flagged this as Malicious.

![Pasted image 20241225143150.png](/img/user/x/images/Pasted%20image%2020241225143150.png)
## Investigating host Matthew
---
- **Processes**: There** is no suspicious process apart from a lot of processes open including `wininit`, `services`, `sysmon`, `amazon-ssm-agent`, and more.
- **Network Connections**: We can see the network connection attempt even though the log in attempts are not succesful and we can confirm the brute-force from the timestamp:

![Pasted image 20241225144352.png](/img/user/x/images/Pasted%20image%2020241225144352.png)
However the terminal history tells a different story:

![Pasted image 20241225144617.png](/img/user/x/images/Pasted%20image%2020241225144617.png)
- 1st: opens up `cmd`.
- 2nd: find out what is the name of the account currently logged in.
- 3rd: find out full details about **letsdefend** including full name, description, and other personal details.
- 4th: list all members of local administrators group.

Looking at the time of brute force and the terminal commands, this suggest that either the threat actor already have a initial foothold trying to gain graphical user interface foothold or the brute force is succesful and the SIEM did not record the attempt.

Either way the terminal history alone is suspicious enough therefore the host should be contained:

![Pasted image 20241225145133.png](/img/user/x/images/Pasted%20image%2020241225145133.png)
#### Confirming if there is a RDP request and a login succesful
---
There is a login attempt:

![Pasted image 20241225145733.png](/img/user/x/images/Pasted%20image%2020241225145733.png)
And a succesful login:

![Pasted image 20241225145956.png](/img/user/x/images/Pasted%20image%2020241225145956.png)
##### Confirming If 'Matthew' interacted with other devices
---
Replacing `source_address` in the filter with **172.16.17.148**:

![Pasted image 20241225150356.png](/img/user/x/images/Pasted%20image%2020241225150356.png)
Logs show the compromised machine did not make any interaction with other devices on the network.








