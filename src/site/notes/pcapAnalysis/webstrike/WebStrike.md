---
{"dg-publish":true,"permalink":"/pcap-analysis/webstrike/web-strike/","tags":["pcap"]}
---

[[pcapAnalysis/Network Analysis\|Network Analysis]]
#### Scenario
---
An anomaly was discovered within our company's intranet as our Development team found an unusual file on one of our web servers. Suspecting potential malicious activity, the network team has prepared a pcap file with critical network traffic for analysis for the security team, and you have been tasked with analyzing the pcap.

## Questions
---
Viewing the statistics from Wireshark we see two IP address one is 24.49.63.79 most likely the server and the adversary IP: 117.11.88.124.

> Q1: Understanding the geographical origin of the attack aids in geo-blocking measures and threat intelligence analysis. What city did the attack originate from?

![Pasted image 20240824161719.png](/img/user/x/images/Pasted%20image%2020240824161719.png)
> Q2: Knowing the attacker's user-agent assists in creating robust filtering rules. What's the attacker's user agent?

Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0 by viewing one of the HTTP request made by the adversary.

> Q3: We need to identify if there were potential vulnerabilities exploited. What's the name of the malicious web shell uploaded?

image.jpg.php by http.request.method == 'POST' since exploit usually happens adversary sending data or uploading data to the server.

> Q4: Knowing the directory where files uploaded are stored is important for reinforcing defenses against unauthorized access. Which directory is used by the website to store the uploaded files?

/reviews/uploads/ 

> Q5: Identifying the port utilized by the web shell helps improve firewall configurations for blocking unauthorized outbound traffic. What port was used by the malicious web shell?
 
port 8080 by finding GET request http packet to the reviews/uploads/image.jpg.php then viewing TCP connection right after:

![Pasted image 20240824164356.png](/img/user/x/images/Pasted%20image%2020240824164356.png)
> Q6: Understanding the value of compromised data assists in prioritizing incident response actions. What file was the attacker trying to exfiltrate?

/etc/passwd right after a TCP connection or the reverse shell there should be following POST request.

source: cyberdefenders.com