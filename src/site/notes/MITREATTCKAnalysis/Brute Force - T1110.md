---
{"dg-publish":true,"permalink":"/mitreattck-analysis/brute-force-t1110/","tags":["mitre"]}
---

[[MITREATTCKAnalysis/Threat Analysis with ATT&CK\|Threat Analysis with ATT&CK]]
### Summary
---
Simulating an attacker figuring out the username pattern for their company then brute-forcing ssh and discovering hashed password on the user's home directory then cracking the password offline then succesfully logging into root.

### Initials
---
- **Atomic Red Team ID**: T1110 - Brute Force
- **Description**: It is a type of attack that guesses the correct credentials repetitively using systems.
	- T1110.001 or Password guessing is using multiple passwords against a single username or account name.
	- T1110.002 or Password Cracking is recovering usable credentials that are hashed guessing the correct password.
- **Challenges Encountered & Solution**:
	- Any online brute forcing tool such as Hydra
	- Any offline brute forcing tool such as John
	- OpenSSH
## Analysis
---
Assuming the following the attacker gained the username pattern for their employees through employees with the format of 'firstName-lastName':

Performing an employee forgetting his password:

```
ssh john-mcallstar@10.200.2003
```

Command output in Wazuh:

![Pasted image 20241007164944.png](/img/user/x/images/Pasted%20image%2020241007164944.png)
Performing a brute-force attack:

```bash
hydra -l john-mcallstar -P lots_of_pass.txt ssh://10.200.200.3
```

Command output in Wazuh:

![Pasted image 20241007165330.png](/img/user/x/images/Pasted%20image%2020241007165330.png)

Source IP address of the attacker:

![Pasted image 20241007180024.png](/img/user/x/images/Pasted%20image%2020241007180024.png)


Command output in Kali Linux:

![Pasted image 20241007170036.png](/img/user/x/images/Pasted%20image%2020241007170036.png)
**Cracking password offline**:

![Pasted image 20241007171356.png](/img/user/x/images/Pasted%20image%2020241007171356.png)
Unshadowing the /etc/shadow file with /etc/passwd by copying the /etc/passwd back to our kali linux machine with filename of `local_pw` and the **secret_password.txt** with the filename of `hashed_pw.txt`:

![Pasted image 20241007173932.png](/img/user/x/images/Pasted%20image%2020241007173932.png)
Then getting the hash and the username formatting similarly in /etc/shadow file:

![Pasted image 20241007174209.png](/img/user/x/images/Pasted%20image%2020241007174209.png)
```
unshadow local_pw hashed_pw.txt > shadowed.txt
```

Then using john the ripper to crack the password:

![Pasted image 20241007174712.png](/img/user/x/images/Pasted%20image%2020241007174712.png)
Logging into the machine with the `client` username:

![Pasted image 20241007174742.png](/img/user/x/images/Pasted%20image%2020241007174742.png)
Since in default setting the created user at Ubuntu setup uses the same password therefore after the offline password cracking the attacker immediately switched user as **root**.

![Pasted image 20241007174921.png](/img/user/x/images/Pasted%20image%2020241007174921.png)
Source IP address:
![Pasted image 20241007180117.png](/img/user/x/images/Pasted%20image%2020241007180117.png)

Viewing the output from both command at a glance, we can think of the first legitimate attempt as brute force attempt with the rule triggering "**syslog: User missed password more than one time**" however for the first command we can safely say it is not an attack and can be considered as false positive due to the attempt per second:

![Pasted image 20241007165652.png](/img/user/x/images/Pasted%20image%2020241007165652.png)
The user login attempt has an average of 7 seconds using a [avg-calculator](https://www.calculator.net/average-calculator.html?numberinputs=5%2C6%2C10&x=Calculate):

![Pasted image 20241007165919.png|450](/img/user/x/images/Pasted%20image%2020241007165919.png)
While the second one are miliseconds closed to each other:

![Pasted image 20241007170005.png](/img/user/x/images/Pasted%20image%2020241007170005.png)
Output from another ssh connection with different user and switching to root immediately:

![Pasted image 20241007175306.png](/img/user/x/images/Pasted%20image%2020241007175306.png)
The difference in both is the 'noise' it created the second ssh connection is much more quiet since the password cracking was done offline.
### WAZUH. rule creation
---
- **Rule ID and description**:  2502
- **Rule logic (conditions, actions)**: Requires user to miss the correct password more than one time.
- **Effectiveness of detection**: Requires further investigation such as checking the timestamp in between the login attempts and checking if it's a normal production hour or not.
## IOCs and IOAs
---
### Incident Overview
---
- **Incident Overview Date and Time**: Oct 7, 2024 @ 4:52:32.079 UTC
- **Source IP Address**: 10.200.200.7
- **Destination IP address**: 10.200.200.3
- **Reported To**: OUROBOROS.org
#### Summary
---
In Oct 7, 2024 @ 4:52:32.079 UTC, the Kali Linux VM (IP: 10.200.200.7) brute forced and succesfully logged in as john-macallstar (IP: 10.200.200.3) and then found a password hash on the desktop and cracked the password offline and succesfully escalated privilege to root.
##### Indicators of Compromise (IOCs)
---
**IP addresses**:
- **Source IP**: 10.200.200.7
- **Description:** IP address of the Kali Linux VM making multiple ssh login attempts in miliseconds.

- **Destination IP**: 10.200.200.3
- **Description: IP**: SSH open and listening but has no login attempt limits.
##### Indicators of Attacks (IOAs)
---
- **Multiple Login attempts:**
	- Behavior: Multiple login attempts using the same username in miliseconds
## Incident Response
---
- **Incident identification criteria** 
	- Multiple ssh login attempts in miliseconds using the same username and using unknown IP address.
- **Investigation steps** 
	- Check Wazuh Security Event & Information Management (SIEM) security events
- **Containment actions**
	- Remove the machine from the network.
- **Eradication procedures**
- **Recovery steps**
	- Configure Open-SSH to limit allowed login attempts.
	- Remove or create a password policy that even password hash should not be displayed on the user home directory.


