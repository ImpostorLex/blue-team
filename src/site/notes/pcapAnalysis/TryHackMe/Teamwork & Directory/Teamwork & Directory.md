---
{"dg-publish":true,"permalink":"/pcap-analysis/try-hack-me/teamwork-and-directory/teamwork-and-directory/","tags":["pcap"]}
---

[[pcapAnalysis/Network Analysis\|Network Analysis]]

source: TryHackMe

## Tools
---
- Tshark
# Analysis
Statistics of packets shows HTTP contains a large amount of traffic:

![Pasted image 20240906184809.png](/img/user/x/images/Pasted%20image%2020240906184809.png)
Here are resolved domains:

![Pasted image 20240906185140.png](/img/user/x/images/Pasted%20image%2020240906185140.png)
VirusTotal flagged the last domain as malicious with a score of 1/64 impersonating as paypal.

Using the tshark query below to find the email used:

```bash
tshark -r teamwork.pcap -T fields -Y 'http' -e http.file_data -e urlencoded-form.key -e urlencoded-form.value | grep -E '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
```

![Pasted image 20240906192611.png](/img/user/x/images/Pasted%20image%2020240906192611.png)
### Directory Challenge
---
Querying for domains and checking them in VirusTotal:

![Pasted image 20240908150034.png](/img/user/x/images/Pasted%20image%2020240908150034.png)
- **jx2-bavuong.com** has a VirusTotal score of 6/94.
- There are 14 http request to the malicious domain using the command below:

```bash
tshark -r directory-curiosity.pcap  -Y 'http.host == "jx2-bavuong.com" and http.request.method == "GET"'
```

Output:

![Pasted image 20240908151148.png](/img/user/x/images/Pasted%20image%2020240908151148.png)
- Malicious IP: 141[.]164[.]41[.]174
- It's server information is "Apache/2.2.11 (Win32) DAV/2 mod_ssl/2.2.11 OpenSSL/0.9.8i PHP/5.2.9":

```bash
tshark -r directory-curiosity.pcap -Y "http" -T fields -e http.host -e http.server
```

![Pasted image 20240908152228.png](/img/user/x/images/Pasted%20image%2020240908152228.png)
- Suspicious scripts and executables:

```bash
tshark -r directory-curiosity.pcap -z follow,tcp,ascii,0
```

Output:

![Pasted image 20240908154105.png](/img/user/x/images/Pasted%20image%2020240908154105.png)
The sha256sum value of **.exe** file is and uploading to VirusTotal:

```
b4851333efaf399889456f78eac0fd532e9d8791b23a86a19402c1164aed20de
```

- It is made using `.NET framework`.
- It is a trojan.