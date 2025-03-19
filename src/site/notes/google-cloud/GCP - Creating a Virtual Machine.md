---
{"dg-publish":true,"permalink":"/google-cloud/gcp-creating-a-virtual-machine/","tags":["gcloud"]}
---

[[README\|README]]

- **Compute Engine** lets you create and run virtual machines on Google infrastructure.
- **Cloud shell** is a virtual machine that is loaded with development tools and can be used to interact with Google cloud resources.
- **Regions** it is a specific geographical location where you can run your resources.
	- Each region has one or more **zones**
- **Zonal Resources** are resources that lives in a zone.
	- In order to attach a persistent disk into a VM both the VM and the disk must be in the same zone, the same as attaching an IP address they must both live on the same zone.

#### Set the region and zone
---

**Display active accounts:**
```bash
gcloud auth list
```

output:
![Pasted image 20250308183949.png](/img/user/x/images/Pasted%20image%2020250308183949.png)
More on [gcloud CLI.](Compute Engine lets you create and run virtual machines on Google infrastructure.)

![Pasted image 20250308185526.png|450](/img/user/x/images/Pasted%20image%2020250308185526.png)

Set the **project region**:
```bash
gcloud config set compute/region us-east1
```

- `us-east1` will be the region where our resources will be deployed.

Create a variable for region:
```bash
export REGION=us-east1
```

Create a variable for the zone:
```bash
export ZONE=us-east1-d
```

- This sets a shell variable `$ZONE` with the value `us-east1-d`. A zone is a sub-location within a region (e.g., `us-east1-d` is a zone within `us-east1`).

### Creating VM
---
![Pasted image 20250308184128.png|450](/img/user/x/images/Pasted%20image%2020250308184128.png)
Then click **create instance** and prefill the information:

![Pasted image 20250308185830.png|450](/img/user/x/images/Pasted%20image%2020250308185830.png)
- **Series:** E2
	- defines the overall performance that we want for a price
- **Machine-Type:** e2-medium
	- specifies the actual configuration such as the amount of Virtual CPUs, and RAM.

Then at the sidebar, click **OS and Storage:**

- **Operating system**: Debian
- **Version**: Debian GNU/Linux 11 (bullseye)
- **Boot disk type**: Balanced persistent disk
- **Size**: 10 GB

![Pasted image 20250308190031.png|450](/img/user/x/images/Pasted%20image%2020250308190031.png)
Sidebar again: **Networking**

- Allow HTTP traffic

![Pasted image 20250308190137.png](/img/user/x/images/Pasted%20image%2020250308190137.png)
Then click **create** to create the instance and then we can click the **ssh** to connect to the VM:

![Pasted image 20250308190555.png|450](/img/user/x/images/Pasted%20image%2020250308190555.png)

```C
sudo apt-get update
```

Install NGINX:
```bash
sudo apt-get install -y nginx
```

Confirm NGINX running:
```
ps auwx | grep nginx
```

Click the external IP in the **VM Instance** section to navigate to the nginx Server:

![Pasted image 20250308190739.png](/img/user/x/images/Pasted%20image%2020250308190739.png)
#### Creating VM from the CommandLine
---
In Cloud Shell, run the following `gcloud` command to create a new VM instance from the command line:
```bash
gcloud compute instances create gcelab2 --machine-type e2-medium --zone=$ZONE
```

![Pasted image 20250308191019.png](/img/user/x/images/Pasted%20image%2020250308191019.png)
When working in your own project, you can specify a [custom machine type](https://cloud.google.com/compute/docs/instances/creating-instance-with-custom-machine-type).



