---
{"dg-publish":true,"permalink":"/mitreattck-analysis/tryhackme/siem/boss-of-the-soc/"}
---

[[tryhackme\|tryhackme]]
### Case Description
---
Security researchers from Splunk set up a lab environment that is connected to the Internet, the environment consist of Windows endpoint, and best practices for logging and endpoint monitoring.
## Tools
---
- Splunk
# Analysis

The endpoint with the most traffic generated is from the user **amber** with IP address of 10.0.2.101 and amber works for a beer company name Grace Hoppy.

Filtering for http connections:

![Pasted image 20241111123045.png](/img/user/x/images/Pasted%20image%2020241111123045.png)
From the result we can see:

![Pasted image 20241111123512.png](/img/user/x/images/Pasted%20image%2020241111123512.png)
Using the following filter:

```bash
index="botsv2" 10.0.2.101 sourcetype="stream:HTTP" site="www.berkbeer.com"
```

Amber discovers the CEO contact information:
![Pasted image 20241111123841.png](/img/user/x/images/Pasted%20image%2020241111123841.png)Since amber is looking up competitor's contact information, we can try filtering out email:

- berkbeer ip is 69.90.41.74 by including the `dest_ip` using the keyword table.

Adding only `berk` as a string in the search reveals one event:

![Pasted image 20241111163629.png](/img/user/x/images/Pasted%20image%2020241111163629.png)
Then using the sender's email address as filter, we can see amber's email:

![Pasted image 20241111163802.png](/img/user/x/images/Pasted%20image%2020241111163802.png)
Doing the same thing for the email of amber as filter:

- Martin Berk is the CEO by viewing the data as raw

![Pasted image 20241111171416.png](/img/user/x/images/Pasted%20image%2020241111171416.png)

The second employee that amber contacted is:

![Pasted image 20241111164025.png](/img/user/x/images/Pasted%20image%2020241111164025.png)

Then amber attached a `.docx` while sending to heinz:

![Pasted image 20241111171730.png](/img/user/x/images/Pasted%20image%2020241111171730.png)
In the raw data we can see there is base64 encoding:

![Pasted image 20241111172959.png](/img/user/x/images/Pasted%20image%2020241111172959.png)

Decoding some of it reveals:

![Pasted image 20241111173005.png](/img/user/x/images/Pasted%20image%2020241111173005.png)Amber downloaded Tor to obsfucate her communication (`amber tor.exe`):

![Pasted image 20241111193245.png](/img/user/x/images/Pasted%20image%2020241111193245.png)
Then the public IP address of `brewertalk.com`:

![Pasted image 20241111194019.png](/img/user/x/images/Pasted%20image%2020241111194019.png)
Searching for `brewertalk` and filtering for the `src_ip` we see a lot of request from this IP address:

![Pasted image 20241112141532.png](/img/user/x/images/Pasted%20image%2020241112141532.png)
Adding the IP address as filter, we can see at `/member.php` there are multiple request being sent into this domain including SQL Injection:

From the **question_id** paramaeter, we can see the SQL function `updatexml` is being abused.

![Pasted image 20241112141727.png](/img/user/x/images/Pasted%20image%2020241112141727.png)
The second person in question is kevin: kevin.lagerfield and his IP addres is most likely 10.0.2.109 since using his name as filter and checking the `src_ip` with the most hits and it is a private IP address.

Looking at Kevin's http activities, we can see an interesting user agent:

NaenaraBrowser is the official browser of North Korea.

![Pasted image 20241112143342.png](/img/user/x/images/Pasted%20image%2020241112143342.png)
Interesting scripts here using filter with kevin's name and `<script>` shows and it is very uncommon that the entire HTML content is being logged so this is definetly suspicious:

![Pasted image 20241112144426.png](/img/user/x/images/Pasted%20image%2020241112144426.png)
We can also see the username **Kiagerfield** at many `form_data` request and then at the sidebar we can see the cookies set and sent:

![Pasted image 20241112152141.png](/img/user/x/images/Pasted%20image%2020241112152141.png)
Mallory Kraeusen case of ransomware:

- mkraeusen@froth[.]ly

Using `USER=mallorykraeusen` as filter shows this:

![Pasted image 20241113143149.png](/img/user/x/images/Pasted%20image%2020241113143149.png)
```bash
index="botsv2" USER=mallorykraeuse (got OR game OR thrones) (crypt)
```

A got series:

![Pasted image 20241113144059.png](/img/user/x/images/Pasted%20image%2020241113144059.png)
Then we can see a usb devices inserted to `kulekitten` machine by adding the filter, NOTE: OSQuery is installed:

```
kutekitten (usb_devices)
```

![Pasted image 20241113151810.png](/img/user/x/images/Pasted%20image%2020241113151810.png)
Then a quick search result:
![Pasted image 20241113151830.png](/img/user/x/images/Pasted%20image%2020241113151830.png)
Then we found a different user `mkraeusen`, using the below filter:

```bash
kutekitten "\\/Users\\/"
```

![Pasted image 20241113155457.png](/img/user/x/images/Pasted%20image%2020241113155457.png)
Then we found a file hash scrolling down by using the filter below :

```
mkraeusen (file)
```

![Pasted image 20241113155853.png](/img/user/x/images/Pasted%20image%2020241113155853.png)
Then at VirusTotal it is flagged as malicious alongside the programming language, first seen, dns contact, and second dns contact.

Taedonggang actor sends an `zip` file to froth.ly then scrolling down:

```
sourcetype="stream:smtp)
```

![Pasted image 20241113160835.png](/img/user/x/images/Pasted%20image%2020241113160835.png)
Then viewing the raw:

![Pasted image 20241113161044.png](/img/user/x/images/Pasted%20image%2020241113161044.png)
Remembering the NaenaraBrowser, we can find this again with and add it as filter:

```
index="botsv2" 10.0.2.109 sourcetype="stream:http" brewertalk.com 
| dedup http_user_agent
| table http_user_agent
```

Analyzing the IP address 10.0.2.109 as this the IP address that scans brewertalk.com:

![Pasted image 20241113164413.png](/img/user/x/images/Pasted%20image%2020241113164413.png)
Searching for `winsys32.dll` as filter and scrolling down, we can see a base64 encoded string and part of the result is `ftp.exe` is used:

![Pasted image 20241113165417.png](/img/user/x/images/Pasted%20image%2020241113165417.png)
Decoded into:

![Pasted image 20241113165522.png](/img/user/x/images/Pasted%20image%2020241113165522.png)
However this did not prove anything yet, so using filter:
```
sourcetype="stream:ftp"
```

Filtering for table and removing duplicates we can see:

![Pasted image 20241113171049.png](/img/user/x/images/Pasted%20image%2020241113171049.png)
Then using the filter below there is a strange text:

```
index="botsv2" sourcetype="stream:ftp" method=RETR
```

![Pasted image 20241113171608.png](/img/user/x/images/Pasted%20image%2020241113171608.png)
It looks like user `rkovar` is included in the metadata as most likely he/she is the first victim

![Pasted image 20241113172558.png](/img/user/x/images/Pasted%20image%2020241113172558.png)
Then scrolling down we can find **rkovar's** full name and then to find the C2:

```
schtasks.exe
```

Then at the sidebar's commandline:

![Pasted image 20241113174813.png](/img/user/x/images/Pasted%20image%2020241113174813.png)
Then filtering for the registry I removed the `debug` part in the registry path, then it should show up a base64 encoded string:

![Pasted image 20241113175635.png](/img/user/x/images/Pasted%20image%2020241113175635.png)

