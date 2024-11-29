---
{"dg-publish":true,"permalink":"/pcap-analysis/eight-days-of-server-scans-and-probes/","tags":["pcap"]}
---

[[pcapAnalysis/Network Analysis\|Network Analysis]]
### Case Description
---
source: https[://]malware-traffic-analysis[.]net/2024/07/23/index[.]html

The `.zip` only came in with a `.pcap` file and nothing else, I am going to based my goal on the title of the source `.pcap` file:

- Analyze the `.pcap` file to identify the IP address responsible for conducting server scans and probing activities over the eight-day period.

#### Summary
---
It seems like IP address **203.161.44.208** is the server that is being scanned by multiple IP address. 
## Tools
---
- Wireshark
# Analysis

Starting with statistics and looking at the conversation, there is one public IP addresses that stood out the most:

- 203.161.44.208

![Pasted image 20241129142251.png|200](/img/user/x/images/Pasted%20image%2020241129142251.png)
Then moving at the **TCP** tab, we can see multiple IP addresses connecting to port 23 (telnet) to IP 203.1611.44.208:

![Pasted image 20241129142638.png](/img/user/x/images/Pasted%20image%2020241129142638.png)
So 203.161.44.208 must be a server? but the problem is it host multiple services at 1433 is default for SQL server, 23 is for telnet, 9999 is unknown, 445 is for SMB.

This is not suspicious by itself however the ideal way is one server = one service, plus telnet is insecure, and considering it is a public IP address it means that services such as telnet and smb are exposed to the Internet.
### Analyzing 203.161.44.208
---
Since this IP address shows in a lot of rows and seems to be hosting a lot of services, I am going to analyze this first:

```
ip.src == 203.161.44.208
```

Scrolling down with the result:

![Pasted image 20241129143753.png](/img/user/x/images/Pasted%20image%2020241129143753.png)
The 'server' ping has error, it says destination unreachable then scrolling down shows a lot of packet rows in red and this:

![Pasted image 20241129144226.png](/img/user/x/images/Pasted%20image%2020241129144226.png)
Following the HTTP shows this:

![Pasted image 20241129144544.png](/img/user/x/images/Pasted%20image%2020241129144544.png)
This shows that 172.168.41.29 uses `zgrab`, a banner grabber tool programmed in GO and 203.161.44.208 shows that it is `www.wiresharkworkshop.online`.

Based on the evidence (different port numbers being accessed), 203.161.44.208 is most likely the server being scanned by multiple IP addresses.

```
ip.dst == 203.161.44.208
```

![Pasted image 20241129150333.png](/img/user/x/images/Pasted%20image%2020241129150333.png)
We can also see a HOST enabling `XDEBUG_SESSION_START=phpstorm`, it is a PHP extension that allows code debugging, set breakpoints and inspect variables, which is obviously dangerous, it could reveal server configuration and more.

[exploit db link](https://www.exploit-db.com/ghdb/6763)

We can also see 128.90.170.18 accessing `/wp-admin` on the same server IP address:

![Pasted image 20241129150613.png](/img/user/x/images/Pasted%20image%2020241129150613.png)
#### Analyzing 172.168.41.29
---
Remember this is the IP address that used `zgrab` to grab banner from the server:

```
ip.src == 172.168.41.29
```

Shows only the `zgrab` request:

![Pasted image 20241129150933.png](/img/user/x/images/Pasted%20image%2020241129150933.png)
Going to statistics protocol hierarchy and shows UDP remote desktop protocol as part of the hierarchy:

```bash
udp.port == 3389 and ip.dst == 203.161.44.208
```

![Pasted image 20241129151847.png](/img/user/x/images/Pasted%20image%2020241129151847.png)
This shows that 64.62.197.142 is attempting to **connect to IP address 203.161** using **RDP over UDP**.