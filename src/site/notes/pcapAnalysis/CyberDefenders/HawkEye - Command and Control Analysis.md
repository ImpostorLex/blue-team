---
{"dg-publish":true,"permalink":"/pcap-analysis/cyber-defenders/hawk-eye-command-and-control-analysis/","tags":["pcap"]}
---

[[]]
### Case Description
---
An accountant at your organization received an email regarding an invoice with a download link. Suspicious network traffic was observed shortly after opening the email. As a SOC analyst, investigate the network trace and analyze exfiltration attempts.
## Tools
---
- VirusTotal
- Wireshark
- Brim
- MaxMind Geo IP.
# Analysis

There is a total of 4003 packets and based on the statistics the compromised machine is [10.4.10.32] due to communications found from multiple IP address and now will be referred to as the victim:

![Pasted image 20241003151420.png](/img/user/x/images/Pasted%20image%2020241003151420.png)
- Additionaly [00:08:02:1c:47:ae] is manufactured by a company name Hewlett Packard (HP) located at palo alto.
- Using `ip.addr == 10.4.10.32and http` Wireshark filter we can see the operating system is Windows NT 6.1
- There are three company devices captured as well (/24).

Based on the first few packets we are dealing with an Active Directory environment:

![Pasted image 20241003152241.png](/img/user/x/images/Pasted%20image%2020241003152241.png)
- Not shown in the image but [10.4.10.4] is most likely the Domain Controller as [10.4.10.32] authenticated itself to Active Directory.

Further inspection on the AS-REQ shows the name of the active computer is 'BEIJING-5CD1-PC' authenticating itself with Active Directory:

![Pasted image 20241003153812.png](/img/user/x/images/Pasted%20image%2020241003153812.png)
The victim makes a DNS request to **proforma-invoices.com**:

![Pasted image 20241003154353.png](/img/user/x/images/Pasted%20image%2020241003154353.png)
And following the DNS response shows the IP address [217.182.138.150] and looking up the address it belongs to france.

![Pasted image 20241003154521.png](/img/user/x/images/Pasted%20image%2020241003154521.png)
Using the wireshark filter below, we found out the victim downloaded a `.exe`:

```bash
ip.addr == 10.4.10.32and http
```

Command Output:

![Pasted image 20241003155931.png](/img/user/x/images/Pasted%20image%2020241003155931.png)
- The victim downloaded `tkraw_Protected99.exe` and categorizes by VirusTotal as trojan.

The webserver that the threat actor uses is `litespeed` which is an apache alternative for PHP web applications:

```bash
ip.src == 217.182.138.150 and http
```

Command output:

![Pasted image 20241003160453.png](/img/user/x/images/Pasted%20image%2020241003160453.png)
It seems like after the execution of the `.exe` the threat actor use 'whatismyipaddress' to find out it's public IP address [173.66.146.112] :

```bash
ip.addr == 10.4.10.132 and http
```

![Pasted image 20241003160952.png](/img/user/x/images/Pasted%20image%2020241003160952.png)
The victim authenticated to an email server **secureserver.net** from Microsoft using mail transfer agent Exim 4.91 :

```
smtp
```

Command output:

![Pasted image 20241003163944.png](/img/user/x/images/Pasted%20image%2020241003163944.png)
- We can also see the victim authenticating and the email contents sent to the domain **macwinlogistics.in**.

In the packet capture the credentials use to send the email is encoded in base64 string and decoding shows:

![Pasted image 20241003164435.png](/img/user/x/images/Pasted%20image%2020241003164435.png)
Decoded base64:

![Pasted image 20241003164426.png](/img/user/x/images/Pasted%20image%2020241003164426.png)
Viewing one of the contents of the email shows credentials and the malware real world name:

![Pasted image 20241003165004.png](/img/user/x/images/Pasted%20image%2020241003165004.png)
Comparing two 'from' packet capture to determine the interval of malware sending logged data:

![Pasted image 20241003165223.png](/img/user/x/images/Pasted%20image%2020241003165223.png)
Second one:

![Pasted image 20241003165158.png](/img/user/x/images/Pasted%20image%2020241003165158.png)
Resulting into 10 mins.





