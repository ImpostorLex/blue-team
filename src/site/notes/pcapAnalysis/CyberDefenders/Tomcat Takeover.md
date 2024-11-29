---
{"dg-publish":true,"permalink":"/pcap-analysis/cyber-defenders/tomcat-takeover/","tags":["pcap"]}
---

[[]]
### Case Description
---
A suspicious activity is detected on one of the company's web servers tomcat.
## Tools
---
- Wireshark
- NetworkMiner
- TShark
# Analysis

In network analysis, I always start with viewing the protocol hierarchy as this tell what are the possible attack vectors the attacker may perform or already performed:

![Pasted image 20241010184908.png](/img/user/x/images/Pasted%20image%2020241010184908.png)
Then the top 'talkers' in the packet capture such as:
- Is there any public IP address that talks too much?
- What private IP address that talks too much?

![Pasted image 20241010184826.png](/img/user/x/images/Pasted%20image%2020241010184826.png)
Based on the result we have two public IP address which is **224.0.0.251** and **14.0.0.120**.

In network miner we can get some nice information based on packet capture:

![Pasted image 20241010185902.png](/img/user/x/images/Pasted%20image%2020241010185902.png)
The IP address **14.0.0.120** seems to be checking open ports or in other words performing network mapping and originated from guangzho,china using IP reputation:

```bash
tshark -nlr "web server.pcap" -Y "tcp.flags.syn==1 && tcp.flags.ack==0" -T fields -e ip.src -e ip.dst -e tcp.dstport | sort | uniq | grep "10.0.0.112"
```

Adding `wc -l` to line count for the IP address `14.0.0.120`:

![Pasted image 20241010190610.png](/img/user/x/images/Pasted%20image%2020241010190610.png)
Comparing it to a Linux Machine, thanks to the feature that networkminer determining the OS:

![Pasted image 20241010190651.png](/img/user/x/images/Pasted%20image%2020241010190651.png)
Then back in Wireshark we can set the filter for the suspicious IP address with http since in the case description relating to one of web servers:

```bash
ip.addr == 14.0.0.120 and http
```

As previously shown the IP 10.0.0.112 is the tomcat server and the default configuration is the admin panel at port 8080, this most likely shows that the attacker manages to succesfully logged in to the admin panel:

![Pasted image 20241010191524.png](/img/user/x/images/Pasted%20image%2020241010191524.png)
After looking around the GET request of the attacker it made me look into the User-agent since the packet capture shows the attacker requesting multiple pages at once shows that the attacker uses a directory enumeration tool:

![Pasted image 20241010191956.png](/img/user/x/images/Pasted%20image%2020241010191956.png)
Then it manages to uncover the `/manager` page associated with the admin panel:

![Pasted image 20241010192121.png](/img/user/x/images/Pasted%20image%2020241010192121.png)
We can view this on networkminer's credentials tab but in a typical 'data submission' on the web it uses the POST request method:

![Pasted image 20241010192444.png](/img/user/x/images/Pasted%20image%2020241010192444.png)
We can also see the attacker uploaded a file **JXQOZY.war** and then make a request to that directory most likely a reverse shell.

```
ip.addr = 14.0.0.120 and tcp
```

We can also see the command that the attacker sent on the compromised machine since no encryption applied we can see the commands:

![Pasted image 20241010194833.png](/img/user/x/images/Pasted%20image%2020241010194833.png)

