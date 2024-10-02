---
{"dg-publish":true,"permalink":"/simulating-command-and-control-attack-and-defend/"}
---

[[Homelab Topology\|Homelab Topology]]
### Introduction
---
Command and Control also known as C2 is one of the critical component of a cyber attacker's operation, this is where the attacker sends instructions to compromised systems, instructions could be anything from data exfiltration to using the compromised system to attack other systems.
## Prerequisites
---
- Velociraptor installed both server and client. [Install Velociraptor Server in Ubuntu](https://www.atlantic.net/dedicated-server-hosting/how-to-install-and-configure-velociraptor-on-ubuntu/)
- Windows VM.
- Kali Linux.
- Windows Server with Active Directory installed.
- Forensic Workstation: FlareVM and Remnux.
- Wazuh Installed
# Modules

- Take a look at the MITRE emulation plugin.
- [[C2 Initial Access\|C2 Initial Access]]


# Analysis

At Wazuh:

![Pasted image 20240929163343.png](/img/user/x/images/Pasted%20image%2020240929163343.png)
However the problem is registry modifications and network connection was not logged, investigating further with Velociraptor:

![Pasted image 20240929165529.png](/img/user/x/images/Pasted%20image%2020240929165529.png)
In Velociraptor sidebar: "Hunt Manager > New Hunt > Fill Details" then choose and skip to launch:

![Pasted image 20240929165901.png](/img/user/x/images/Pasted%20image%2020240929165901.png)
Then run it and should see something like this after it is finishing hunting:

![Pasted image 20240929170049.png](/img/user/x/images/Pasted%20image%2020240929170049.png)
Then find the culprit:

![Pasted image 20240929170618.png](/img/user/x/images/Pasted%20image%2020240929170618.png)
- Suspicious arguments
- Use of base64
- Task name: Updater.

Now collecting and analysing forensic artificats with Velociraptor's built in plugin KAPE:

![Pasted image 20240929171007.png](/img/user/x/images/Pasted%20image%2020240929171007.png)
Then at the configure parameter select:

![Pasted image 20240929171120.png](/img/user/x/images/Pasted%20image%2020240929171120.png)
Then back at the same Window run the hunt and at the bottom there should be a download button:

![Pasted image 20240929171455.png](/img/user/x/images/Pasted%20image%2020240929171455.png)
Then I am going to open up FlareVM and analyse it with RegistryExplorer by Eric Zimmerman:

The registry hive we want is the compromised user's NTUSER.dat:

![Pasted image 20240929175654.png](/img/user/x/images/Pasted%20image%2020240929175654.png)
Then we can find it via `SOFTWARE/Microsoft/Windows/CurrentVersion`:

![Pasted image 20240929180729.png](/img/user/x/images/Pasted%20image%2020240929180729.png)
**Why here?**
- This place usually is for system configuration.
- Not the usual place blue teamers will look for such as in Registry: Run, RunOnce and more.

The decoded base64 is:

![Pasted image 20240929180936.png](/img/user/x/images/Pasted%20image%2020240929180936.png)
And the encoded base64 from the decoded is:

![Pasted image 20240929181006.png](/img/user/x/images/Pasted%20image%2020240929181006.png)

Knowing the file location we can simply delete it now.
























