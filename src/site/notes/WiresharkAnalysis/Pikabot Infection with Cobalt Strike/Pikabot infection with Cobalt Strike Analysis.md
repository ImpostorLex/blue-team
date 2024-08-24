---
{"dg-publish":true,"permalink":"/wireshark-analysis/pikabot-infection-with-cobalt-strike/pikabot-infection-with-cobalt-strike-analysis/","tags":["pcap"]}
---

[[WiresharkAnalysis/Network Analysis\|Network Analysis]]
## Summary
---
The initial exploitation based on the packet capture alone is not shown but it communicates with `tsdandassociates.co.sz` to download `.zip` file to pass a parameter to the same domain, most likely a 'go' signal to download the pikabot from the shakyastatuetrade.com 143.95.249.177 then victim communicates with the C2 using multiple IP address then the cobalt strike traffic at port 443.

---
- The capture starts with a DNS query from 10.0.0.101 to `tsdandassociates[.]co[.]sz` with IP address of 41.185.8.61.
	- The queried domain is flagged by VirusTotal with a score of 9/93
- GET request to tsdandassociates
- The requested resource is a gzip

![Pasted image 20240813093431.png](/img/user/images/Pasted%20image%2020240813093431.png)

- Another GET request with a parameter to `tsdandassociates[.]co[.]sz/w0ks//?YO=1702920835` - based on the packet capture the user was redirected after a delay of 3 seconds probably to download the malware.

```bash
<div id="url" data-url="/w0ks//?YO=1702920835">Loading...</div><script>function red(){ window.location.href = document.getElementById("url").getAttribute("data-url") }setTimeout(red,3000);</script>
```

- Server then responded with a `TD.zip` file:

![Pasted image 20240813095431.png](/img/user/images/Pasted%20image%2020240813095431.png)
![Pasted image 20240813095546.png](/img/user/images/Pasted%20image%2020240813095546.png)

- The 10.0.0.101 -> 10.0.0.10 SMB connection Path: `\\WIN-BQHVFR3MVSA\IPC$`
	- LANMAN protocol is found after the connection most likely for discovering files and printers
	- BROWSER protocol for network device enumeration for shared resources and available computers
	- The domain name is sneaktree.farm by looking at the `export objects -> smb`
- The .zip file contains a file name `Nuj.js` with most notably at the bottom contains a signature block that is encoded in base64 - nothing interesting found after decoded
	- It is accompanied by a `y` file
- A TLS handshake iniated by 10.0.0.101 to 13.91.231.123 then termination with FIN 
- 10.0.0.101 DNS request to shakyastatuestrade[.]com (143.95.249.177) followed by a TLS handshake after that a massive exchange of data, most likely downloading the Pikabot.dll

![Pasted image 20240813192514.png](/img/user/images/Pasted%20image%2020240813192514.png)

Followed by massive exchanges most likely victim communicating with Pika C2:
- 149.28.100.66 port 4243 -> 55087 10.0.0.101 
- 154.221.30.136  port 13724
- 45.33.15.215 port 2967

After a list of IP address above looking at the `statistics -> conversation` filter we found this:

![Pasted image 20240813201416.png](/img/user/images/Pasted%20image%2020240813201416.png)

207.246.99.159 has the most open ports for communication with 10.0.0.101


