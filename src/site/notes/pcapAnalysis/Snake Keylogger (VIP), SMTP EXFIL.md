---
{"dg-publish":true,"permalink":"/pcap-analysis/snake-keylogger-vip-smtp-exfil/","tags":["pcap"]}
---

[[pcapAnalysis/Network Analysis\|Network Analysis]]
### Incident Summary
---
A spearphishing email that request for the company's offering or services attached with a zip file after extracting the zip file, a keylogger was extracted, it contacted first `api[.]telegram[.]org` unfortunately content or purpse is unknown due to encryption.

After succesful malware execution, the malware or Snake Keylogger malware started sending emails to smtp[.]inhousepick[.]com containing all the keylogged credentials, it includes the website, and the username and password as part of the email content.
# Analysis

Email screenshot:

![Pasted image 20241008174106.png](/img/user/x/images/Pasted%20image%2020241008174106.png)
- The sender's name is **Westfield Sofia** with the email of hang_chhaily@leadingstar[.]tw
- The receiver's name is removed.
- There is a zip attachment with the name **NEW PO-09162024**.

Here are the top noise maker on the captured file:

```bash
tshark -r mal.pcap --color -z ip_hosts,tree -q
```

Command Output:

![Pasted image 20241008175143.png](/img/user/x/images/Pasted%20image%2020241008175143.png)
Based on the given information I am going to make an assumption is that the top IP address is the compromised machine while the second one is the Command and Control since it is a key logger it will generate a lot of noise.
### Analyzing 10.9.16.101
---
The '10.9.16.101' made a query to **checkip.dyndns** and **reallyfreegeoip.org** most likely information for the command and control:

![Pasted image 20241008175841.png](/img/user/x/images/Pasted%20image%2020241008175841.png)
- Using VirusTotal confirmed that these are legitimate websites (checkip[.]dyndns[.]com and reallyfreegeoip[.]org).

Then the 10[.]9[.]16[.]101 connects or use telegram's API and made a DNS request to **smtp.inhousepick.com**, the 10[.]9[.]16[.]1 is most likely the default gateway acting as DNS forwarder or cached:

![Pasted image 20241008180504.png](/img/user/x/images/Pasted%20image%2020241008180504.png)
- Communication between telegram's API cannot be viewed due to encryption.
- smtp[.]inhousepick.com is flagged as malicious in VirusTotal.

The second noisy endpoint is **smtp[.]inhousepick[.]com** captured:

```
tshark -r mal.pcap --color -Y 'dns' -T fields -e dns.qry.name -e dns.a
```

Command output:

![Pasted image 20241008185122.png](/img/user/x/images/Pasted%20image%2020241008185122.png)
#### Analyzing smtp.inhousepick.com
---

```bash
tshark -r mal.pcap --color -Y 'smtp' 
```

Command output:

![Pasted image 20241008185340.png](/img/user/x/images/Pasted%20image%2020241008185340.png)
- Decoding the base64 credentials resulting into sender@inhousepick[.]com:#(P%eO^#J0.

Scrolling below using the same query we can see a packet capture that the compromised machine sent an email alongside with an interesting subject:

![Pasted image 20241008185830.png](/img/user/x/images/Pasted%20image%2020241008185830.png)
Then viewing the email contents we can see the information extracted from the keylogger alongside what website or credential is used for:

![Pasted image 20241008190038.png](/img/user/x/images/Pasted%20image%2020241008190038.png)
- In the same packet the receiving email is **inlogs@inhousepick[.]com**

#### Indicators of Compromise
---
- inlogs@inhousepick[.]com
- hang_chhaily@leadingstar[.]tw

### Recommendations
---
- User awareness training: Always verify with the security team, if there is an attached document from an unknown sender.
- At the email gateway block: `.zip` files, `.exe`, `.ps1`, `.sh` or any attachment that does not make sense.
- At the email gateway append or prepend a warning if the sender is outside of the organization.
- Block the email address of: inlogs@inhousepick[.]com and hang_chhaily@leadingstar[.]tw at the email gateway.
- Monitor for the snake keylogger malware using it's hash.

