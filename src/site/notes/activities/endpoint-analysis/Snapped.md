---
{"dg-publish":true,"permalink":"/activities/endpoint-analysis/snapped/"}
---

[[tryhackme\|tryhackme]]
### Case Description
---
Multiple users cannot login after receiving a phishing email from sender 'Group Marketing Online Accounts payable' some contains `.pdf` and `.html` all targets are swiftspend employees.
## Tools
---
- Thunderbird
- grep
- FireFox

# Analysis

- A screenshot of sample email from the threat actor:

![Pasted image 20240916163545.png](/img/user/x/images/Pasted%20image%2020240916163545.png)
- The image also shows an employee receiving a `.pdf`.
- The threat actor's email is 'Accounts.Payable@groupmarketingonline[.]icu'
- In some employees they receive a `.html` attachment that leads to a fake 'microsoft' landing page:

![Pasted image 20240916164214.png](/img/user/x/images/Pasted%20image%2020240916164214.png)
- A defanged sample URL provided:

```bash
hxxp[://]kennaroads[.]buzz/data/Update365/office365/40e7baa2f826a57fcf04e5202526f8bd/?email=zoe[.]duncan@swiftspend[.]finance&error
```

- Enumerating the URL paths found a `.zip` file, it is found at 'kennaroads[.]buzz/data/':

![Pasted image 20240916171006.png](/img/user/x/images/Pasted%20image%2020240916171006.png)
```SHA256SUM
ba3c15267393419eb08c7b2652b8b6b39b406ef300ae8a18fee4d16b19ac9686
```

- VirusTotal score 27/66 tagged as trojan.
- First submitted at 2020-04-08 21:55:50 UTC.
- The `.zip` contains `.php` files and most interesting part is the email used to receive victim information: 'jamestanner2299@gmail[.]com'.
- Using a SSL certificate lookup tool such as `crt.sh` found that the first time SSL/TLS certificate issued to this domain is at 2020-06-25.
- At `/data/Update365/log.txt` shows all user who submitted their password:

![Pasted image 20240916175038.png](/img/user/x/images/Pasted%20image%2020240916175038.png)
- After viewing the source code, it shows that the threat actor used another email to receive the above information: 'm3npat@yandex[.]com'
- THM{pL4y_w1th_tH3_URL}

