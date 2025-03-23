---
{"dg-publish":true,"permalink":"/google-ads-leads-to-matanbuchus-infection-with-danabot/","tags":["malware"]}
---

[[MalwareAnalysis/Malware Analysis\|Malware Analysis]]

March 2025 | Alexander Macenas| v1
### Executive Summary
---
A malvertising that attracts victim that leads to the malicious website, after filling up the form, a zip file is downloaded, once extracted it downloads a non-malicious pdf as decoy and dowloads the Matanbuchus malware in the background once installed the Matanbuchus malware installs the Danabot malware, both Matanbuchus and Danabot malware continues their command and control operation.

### High Level Summary
---
Based on the malware source provider, the infection chain goes like this malicious google ad --> fake money claim site treasurybanks[.]org --> fill up form and get a download --> download zip archive --> victim double clicks .js file in zip archive --> wscript[.]exe runs .js file --> .downloads & runs .msi file --> downloads and runs Matanbuchus --> downloads and runs Danabot --> Both malware continues their C2 operation.

#### Malware Composition

![Pasted image 20250323163036.png](/img/user/x/images/Pasted%20image%2020250323163036.png)
- `q-report-60033.js` - 43aa76bec0e160c4e4a587e452b3303fa7ac72f08521bcbdcae2c370d669e451
- `bLhLdebqq.msi` -  8b8e9a0de005d5ec4539a7db288d1553eacb2e7b64067cb88882d7047511a13c
- `Dad.dll` = `dad86.dll` - 7832c515d7e0198d97733266c34b3ea207c4938fe8877301952ef2ec7efcb1ec
- `uyegwfgewfg.exe` - 5f24b7934a1981d24700049056dca1be14a19db32779a97ca19766f218e47c0f
- `Hqeyair.dll` - f4b783cd81ae0eba7234e0a4d14d47c813b0e8c18b1d8eb00eda6d326b8c6fbe

## Static Analysis
---
#### Javascript analysis

![Pasted image 20250323143305.png](/img/user/x/images/Pasted%20image%2020250323143305.png)
1. Open an object to write or read text streams.
2. Opens `Wscript.Shell` to enable scripting with `.vbs` or `.js`
3. Gets and store the username.
4. Determine if the **.exe** file already exist in the specified folder.
5. If the **.exe** does not exist already, perform the command specified using `wscript.Run`.
##### Wscript.Run Analysis
---
Guest to Host copy paste is disabled for security purposes:

1. It changes to the directory AppData/Local/Temp of the current user.
2. It copies the `curl.exe` to this directory and named it as **TNheBOJElq.exe** (will still be referred as curl).

![Pasted image 20250323144549.png](/img/user/x/images/Pasted%20image%2020250323144549.png)
3. Uses curl to download a `.pdf` file from bologna[.]sunproject[.]dev/download/pdf and then once downloaded the `.pdf` file is executed.
![Pasted image 20250323145041.png](/img/user/x/images/Pasted%20image%2020250323145041.png)
4. It uses curl again to download a `.msi` file from rome[.]sunproject[.]dev/download/agent and uses `msiexec.exe` to install the download file which is **bLhLIdebqq.msi** with a flag `/qn` which means quite don't show interface.
5. as for `0` run the command in background no window needed and `false` do not wait for the commands to be finished.

#### Investigating the `.msi` file
---
The `.cab` or cabinet files sometimes will contain the actual application to be installed:

Open the `.msi` file with `7-Zip` and extract the following:

![Pasted image 20250323150302.png](/img/user/x/images/Pasted%20image%2020250323150302.png)
Then once extracted do the same, open it up again with zip application:
![Pasted image 20250323150332.png](/img/user/x/images/Pasted%20image%2020250323150332.png)
Since it's a compiled binary, we can't actually view the actual source code, only strings we can use `strings` or the `floss` command:

```
floss dad86.dll
```

We can see interesting Windows API calls:

- GetCommandLineA(W)
- IsDebuggerPresent
- CreateFileW
- WriteConsoleW
- KERNEL32.dll for communication with hardware and software.
- USER32.dll for interacting anything you see in a screen windows, buttons or menus.
## Dynamic Analysis
---
#### Installing `.msi` file and viewing it's traffic
---
```bash
msiexec /i bLhLIdebqq.msi
```

In our fake internet simulator, it made a DNS query to two domains:

![Pasted image 20250323152249.png](/img/user/x/images/Pasted%20image%2020250323152249.png)
- sweetapp[.]page
- gammaproject[.]dev

For some reason, the `.msi` or the installation could not make any http(s) request only dns. I don't know if it's because I am using only Internet simulator or it has to do something with the malware, based on any.run submitting the hash of `.msi` it also does not include the HTTP request but navigating to the DNS request we can see both mentioned domains

![Pasted image 20250323171437.png](/img/user/x/images/Pasted%20image%2020250323171437.png)

Based on the report: 
1. it's supposed to retrieve `.dll` by making a GET request from hxxps[://]sweetapp[.].page/userinfo/useraccount[.]aspx 
2. And then retrieve a base64 text on hxxps:[://]gammaproject[.]dev/index/index[.]aspx that will be used to install the Matanbuchus DLL 
3. And then Matanbuchus will download the Danabot from hxxps[://]torontoclub[.]vip/uyegwfgefwg[.]exe

#### Executing uyegwfgefwg.exe
---
**Note:** uyegwfgefwg[.]exe is retrieved by Matanbuchus malware and then uyegwfgefwg[.]exe will install the danabot.exe:

In process monitor, I am going to filter out for uyegwfgefwg[.]exe only and opening TCPview to view it's connection:

![Pasted image 20250323160947.png](/img/user/x/images/Pasted%20image%2020250323160947.png)
After execution it makes a lot of SYN flags to **34[.]77[.]22[.]163** probably trying to make a TCP connection attempt.
![Pasted image 20250323161135.png](/img/user/x/images/Pasted%20image%2020250323161135.png)
At any.run:

![Pasted image 20250323170955.png](/img/user/x/images/Pasted%20image%2020250323170955.png)
#### Running Hqeyair.dll
---
The danabot command and control:
```C
rundll32.exe Hqeyair.dll, start
```

At wireshark, we can view the C2 traffic:

![Pasted image 20250323162606.png](/img/user/x/images/Pasted%20image%2020250323162606.png)
Interestingly, using any.run against the .dll we can see that it drops another `.dll` file:

![Pasted image 20250323170730.png](/img/user/x/images/Pasted%20image%2020250323170730.png)

#### Indicators of Compromise
**Network Indicators**

- treasurybanks.org - the start of the initial infection, the fake ad
- bologna.sunproject.dev - the domain hosting the fake PDF
- rome.sunproject.dev - the domain hosting malicious MSI
- sweetapp.page - the domain hosting Matanbuchus DLL 
- gammaproject.dev - after installed this domain is contacted by the Matanbuchus malware or the Command and Control.
- torontoclub.vip - the domain hosting Danabot malware - installed by the Matanbuchus malware
- 34.168.202.91:443 - The IP address for Danabot C2 communication.

**Host-based Indicators**

- q-report-53394.zip
- q-report-60033.js
- bLhLldebqq.msi
- Dad.dll
- uyegwfgefwg.exe
- Hqeyair.dll

### Rules and Signatures

**A. Yara Rules**

```C
rule MAL_EXE_DLL_MATANBUCHUS_AND_DANABOT
{
    meta:
        author = "Alexander Macenas"
        description = "Detect specific malicious files based on filenames"
        date = "2025-03-23"
        version = "1.0"

    strings:
        $filename1 = "q-report-60033.js"
        $filename2 = "bLhLdebqq.msi"
        $filename3 = "dad86.dll"
        $filename4 = "uyegwfgewfg.exe"
        $filename5 = "Hqeyair.dll"

    condition:
        any of ($filename*)
}
```

Additionally, we can add the file hashes of our **host-based indicators** as part of our conditions:

```C
hash.sha256("43aa76bec0e160c4e4a587e452b3303fa7ac72f08521bcbdcae2c370d669e451") or
        hash.sha256("8b8e9a0de005d5ec4539a7db288d1553eacb2e7b64067cb88882d7047511a13c") or
        hash.sha256("7832c515d7e0198d97733266c34b3ea207c4938fe8877301952ef2ec7efcb1ec") or
        hash.sha256("5f24b7934a1981d24700049056dca1be14a19db32779a97ca19766f218e47c0f") or
        hash.sha256("f4b783cd81ae0eba7234e0a4d14d47c813b0e8c18b1d8eb00eda6d326b8c6fbe") 
```

**B. Callback URLS**

