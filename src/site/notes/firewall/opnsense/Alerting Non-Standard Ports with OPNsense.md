---
{"dg-publish":true,"permalink":"/firewall/opnsense/alerting-non-standard-ports-with-op-nsense/","tags":["opnsense"]}
---

[[]]
### Introduction
---
Blocking non-standard ports depends on the organization normal traffic, for example: a typical day traffic only consist of users accessing port 80 (http), port 443 (https), and port 445 (SMB server) however it would be strange a user connecting to port 4444 which is the default port for metasploit.
## Pre-requisite
---
- Opnsense
- Kali Linux
- Windows or Linux VM
# Analysis

I set up a `netcat` server using Kali Linux with the command:

```bash
nc -nvlp 8000
```

I had my linux machine [10.200.200.4] connect to the `netcat` server using `netcat`:

```bash
nc 10.200.200.7 8000
```

Command Output:

![Pasted image 20241002173703.png](/img/user/x/images/Pasted%20image%2020241002173703.png)
However at the Firewall live view no port 8000 was logged:

![Pasted image 20241002173918.png](/img/user/x/images/Pasted%20image%2020241002173918.png)
Creating a suricata rule to detect non-standard ports at `/usr/local/etc/suricata/rules/custom.rules`, this assumes that port 80, 443, and 445 is the normal traffic in our made up organization:

```YAML
alert tcp $HOME_NET any -> 10.200.200.7 ![80,443,445] (msg:"Malicious traffic detected on non-standard ports"; 
    sid:1000002; 
    rev:1;  
    priority:2; )
```

- Note: 10.200.200.7[Kali Linux] should be replaced with `$EXTERNAL_NET` but I am running on Virtual Machine for demonstration purposes.

Command output:

![Pasted image 20241002185615.png](/img/user/x/images/Pasted%20image%2020241002185615.png)
Since we are using the wazuh-agent plugin there is no need for custom rules and decoders, we can already see the alert:

![Pasted image 20241002185829.png](/img/user/x/images/Pasted%20image%2020241002185829.png)
Command output:

![Pasted image 20241002185906.png](/img/user/x/images/Pasted%20image%2020241002185906.png)







