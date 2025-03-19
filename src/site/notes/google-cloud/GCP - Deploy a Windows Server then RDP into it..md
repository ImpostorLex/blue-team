---
{"dg-publish":true,"permalink":"/google-cloud/gcp-deploy-a-windows-server-then-rdp-into-it/","tags":["gcloud"]}
---

[[]]

- Reference: [[google-cloud/GCP - Creating a Virtual Machine\|GCP - Creating a Virtual Machine]]

![Pasted image 20250310152747.png](/img/user/x/images/Pasted%20image%2020250310152747.png)
Click **OS and storage**:
- **Operating system**: `Windows Server`
- **Version**: `Windows Server 2022 Datacenter`

Once completed, we need to ensure that the server instance is ready and all of it's components are initialized:

At the **cloud shell**, replace `[instance]` with the VM instance name, we can also use `grep` to search for the line:
```bash
gcloud compute instances get-serial-port-output [instance] --zone=us-west3-a |  grep "Instance setup finished" 
```

Repeat the command until you this in the output:
```C
------------------------------------------------------------
Instance setup finished. instance is ready to use.
------------------------------------------------------------
```
#### Reset RDP Password
---
Replace `[instance]` with VM instance name and `[username]` with 'admin':
```
gcloud compute reset-windows-password [instance] --zone us-west3-a --user [username]
```

Enter Y, if prompted for resetting the password:

![Pasted image 20250310153719.png](/img/user/x/images/Pasted%20image%2020250310153719.png)
```
8|BVb(JJKdhR1#p
```

Connect to the VM with the following:

- `xrdp` for linux.
- built-in rdp for Windows.
- In Google Chrome add the extension sparkview.

Second option:
![Pasted image 20250310154146.png](/img/user/x/images/Pasted%20image%2020250310154146.png)
Then the next prompt will ask for username and password.